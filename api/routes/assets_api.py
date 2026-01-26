"""
RUTAS FLASK PARA ASSET INVENTORY Y WHITELIST

Este módulo define los endpoints de la API Flask que usan las clases
del módulo asset_inventory.py

Integración en app.py:
    from api.routes.assets_api import bp_assets
    app.register_blueprint(bp_assets)
"""

import logging
from flask import Blueprint, jsonify, request, current_app
from bson import ObjectId

from api.assets.inventory import (
    AssetInventoryManager,
    WhitelistEngine,
    initialize_default_assets,
    initialize_default_whitelist,
    initialize_open5gs_assets
)

logger = logging.getLogger(__name__)

# Blueprint para todas las rutas de assets
bp_assets = Blueprint('assets', __name__, url_prefix='/api/v1/assets')


# ============================================================================
# ASSET MANAGEMENT ENDPOINTS
# ============================================================================

@bp_assets.route('/register', methods=['POST'])
def register_asset():
    """
    POST /api/v1/assets/register
    
    Registra un nuevo asset en el inventario
    
    Body:
    {
        "ip": "172.22.0.52",
        "hostname": "api-server",
        "role": "API Backend",
        "owner": "backend-team",
        "services": [
            {"name": "Flask", "port": 5000}
        ],
        "expected_connections": [
            {"dest_ip": "172.22.0.50", "dest_port": 27017, "service": "mongodb"}
        ]
    }
    
    Returns:
        201: Asset registrado exitosamente
        400: Validación fallida
        500: Error del servidor
    """
    try:
        data = request.get_json()
        
        # Validar
        if not data.get('ip') or not data.get('hostname'):
            return jsonify({
                'error': 'ip y hostname son requeridos'
            }), 400
        
        mgr = AssetInventoryManager(current_app.mongo.db)
        mgr.create_asset(data)
        
        return jsonify({
            'status': 'ok',
            'message': f"Asset {data['ip']} registrado",
            'asset': data
        }), 201
    
    except Exception as e:
        logger.error(f"Error registrando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/list', methods=['GET'])
def list_assets():
    """
    GET /api/v1/assets/list
    
    Lista todos los assets registrados
    
    Query params:
        - role: filtrar por role
        - owner: filtrar por owner
        - criticality: HIGH, MEDIUM, LOW
        - tag: filtrar por etiqueta
    
    Returns:
        200: Lista de assets
        500: Error del servidor
    """
    try:
        query = {}
        
        # Construir filtro
        if request.args.get('role'):
            query['role'] = request.args.get('role')
        if request.args.get('owner'):
            query['owner'] = request.args.get('owner')
        if request.args.get('criticality'):
            query['criticality'] = request.args.get('criticality')
        if request.args.get('tag'):
            query['tags'] = {'$in': [request.args.get('tag')]}
        
        mgr = AssetInventoryManager(current_app.mongo.db)
        assets = mgr.list_assets(query)
        
        # Convertir ObjectId a string
        for asset in assets:
            asset['_id'] = str(asset['_id'])
        
        return jsonify({
            'total': len(assets),
            'assets': assets
        }), 200
    
    except Exception as e:
        logger.error(f"Error listando assets: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/<ip>', methods=['GET'])
def get_asset(ip):
    """
    GET /api/v1/assets/{ip}
    
    Obtiene detalles de un asset específico
    
    Args:
        ip: Dirección IP del asset
    
    Returns:
        200: Detalles del asset
        404: Asset no encontrado
        500: Error del servidor
    """
    try:
        mgr = AssetInventoryManager(current_app.mongo.db)
        asset = mgr.get_asset(ip)
        
        if not asset:
            return jsonify({
                'error': f'Asset {ip} no encontrado'
            }), 404
        
        asset['_id'] = str(asset['_id'])
        return jsonify(asset), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/<ip>', methods=['PUT', 'PATCH'])
def update_asset(ip):
    """
    PUT /api/v1/assets/{ip}
    
    Actualiza un asset existente
    
    Args:
        ip: Dirección IP del asset
    
    Body: Campos a actualizar
    
    Returns:
        200: Asset actualizado
        404: Asset no encontrado
        500: Error del servidor
    """
    try:
        data = request.get_json()
        
        mgr = AssetInventoryManager(current_app.mongo.db)
        
        # Verificar que existe
        if not mgr.is_known_asset(ip):
            return jsonify({
                'error': f'Asset {ip} no encontrado'
            }), 404
        
        # Actualizar
        mgr.create_asset({**mgr.get_asset(ip), **data, 'ip': ip})
        
        return jsonify({
            'status': 'ok',
            'message': f"Asset {ip} actualizado"
        }), 200
    
    except Exception as e:
        logger.error(f"Error actualizando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/<ip>', methods=['DELETE'])
def delete_asset(ip):
    try:
        db = current_app.mongo.db
        
        # Cambiar 'assets' por 'network_assets'
        result = db['network_assets'].find_one_and_delete({'ip': ip})
        
        if not result:
            return jsonify({
                'error': f'Asset {ip} no encontrado'
            }), 404
        
        db['expected_connections'].delete_many({
            '$or': [
                {'src_ip': ip},
                {'dest_ip': ip}
            ]
        })
        
        return jsonify({
            'status': 'ok',
            'message': f'Asset {ip} eliminado'
        }), 200
    
    except Exception as e:
        logger.error(f"Error eliminando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# ============================================================================
# EXPECTED CONNECTIONS ENDPOINTS
# ============================================================================

@bp_assets.route('/expected-connections/add', methods=['POST'])
def add_expected_connection():
    """
    POST /api/v1/assets/expected-connections/add
    
    Registra una comunicación como "esperada"
    
    Body:
    {
        "src_ip": "172.22.0.52",
        "dest_ip": "172.22.0.50",
        "dest_port": 27017,
        "service": "mongodb"
    }
    
    Returns:
        201: Conexión registrada
        400: Validación fallida
        500: Error del servidor
    """
    try:
        data = request.get_json()
        
        required = ['src_ip', 'dest_ip', 'dest_port', 'service']
        if not all(data.get(field) for field in required):
            return jsonify({
                'error': f'Campos requeridos: {", ".join(required)}'
            }), 400
        
        mgr = AssetInventoryManager(current_app.mongo.db)
        mgr.register_expected_connection(
            data['src_ip'],
            data['dest_ip'],
            data['dest_port'],
            data['service']
        )
        
        return jsonify({
            'status': 'ok',
            'message': f"Conexión esperada: {data['src_ip']}→{data['dest_ip']}:{data['dest_port']}"
        }), 201
    
    except Exception as e:
        logger.error(f"Error añadiendo conexión: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/expected-connections/list', methods=['GET'])
def list_expected_connections():
    """
    GET /api/v1/assets/expected-connections/list
    
    Lista todas las conexiones esperadas registradas
    
    Returns:
        200: Lista de conexiones
        500: Error del servidor
    """
    try:
        mgr = AssetInventoryManager(current_app.mongo.db)
        connections = mgr.get_expected_connections()
        
        for conn in connections:
            conn['_id'] = str(conn['_id'])
        
        return jsonify({
            'total': len(connections),
            'connections': connections
        }), 200
    
    except Exception as e:
        logger.error(f"Error listando conexiones esperadas: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# WHITELIST ENDPOINTS
# ============================================================================

@bp_assets.route('/whitelist/add', methods=['POST'])
def add_whitelist_rule():
    """
    POST /api/v1/assets/whitelist/add
    
    Añade regla de whitelist
    
    Body ejemplos:
    
    IP:
    {
        "type": "IP",
        "value": "192.168.1.5",
        "description": "Trusted monitoring system"
    }
    
    CIDR:
    {
        "type": "CIDR",
        "value": "10.0.0.0/8",
        "description": "Corporate network"
    }
    
    COMUNICACIÓN:
    {
        "type": "COMMUNICATION",
        "src_ip": "172.22.0.52",
        "dest_ip": "172.22.0.50",
        "dest_port": 27017,
        "description": "API→MongoDB"
    }
    
    PATRÓN FIRMA:
    {
        "type": "SIGNATURE_PATTERN",
        "pattern": "HTTP.*GET /health",
        "description": "Health checks"
    }
    
    SEVERIDAD:
    {
        "type": "SEVERITY_MAX",
        "max_severity": 3,
        "description": "Ignore low-severity alerts"
    }
    
    Returns:
        201: Regla creada
        400: Validación fallida
        500: Error del servidor
    """
    try:
        data = request.get_json()
        
        if not data.get('type') or not data.get('description'):
            return jsonify({
                'error': 'type y description son requeridos'
            }), 400
        
        engine = WhitelistEngine(current_app.mongo.db)
        engine.add_whitelist_rule(data)
        
        return jsonify({
            'status': 'ok',
            'message': 'Whitelist rule added',
            'rule': data
        }), 201
    
    except Exception as e:
        logger.error(f"Error añadiendo whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/whitelist/list', methods=['GET'])
def list_whitelist_rules():
    """
    GET /api/v1/assets/whitelist/list
    
    Lista todas las reglas de whitelist
    
    Query params:
        - approved: "true" o "false" para filtrar por aprobación
    
    Returns:
        200: Lista de reglas
        500: Error del servidor
    """
    try:
        query = {}
        
        # Filtrar por estado de aprobación si se proporciona
        approved_param = request.args.get('approved')
        if approved_param:
            query['approved'] = approved_param.lower() == 'true'
        
        engine = WhitelistEngine(current_app.mongo.db)
        rules = list(current_app.mongo.db['whitelist_rules'].find(query))
        
        for rule in rules:
            rule['_id'] = str(rule['_id'])
        
        return jsonify({
            'total': len(rules),
            'rules': rules
        }), 200
    
    except Exception as e:
        logger.error(f"Error listando whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/whitelist/<rule_id>/approve', methods=['POST'])
def approve_whitelist_rule(rule_id):
    """
    POST /api/v1/assets/whitelist/{rule_id}/approve
    
    Aprueba una regla de whitelist
    
    Args:
        rule_id: ID de MongoDB de la regla
    
    Returns:
        200: Regla aprobada
        400: ID inválido
        404: Regla no encontrada
        500: Error del servidor
    """
    try:
        # Validar ObjectId
        try:
            oid = ObjectId(rule_id)
        except:
            return jsonify({'error': 'Invalid rule ID'}), 400
        
        engine = WhitelistEngine(current_app.mongo.db)
        
        # Verificar que existe
        rule = current_app.mongo.db['whitelist_rules'].find_one({'_id': oid})
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Aprobar
        engine.approve_rule(rule_id)
        
        return jsonify({
            'status': 'ok',
            'message': 'Whitelist rule approved'
        }), 200
    
    except Exception as e:
        logger.error(f"Error aprobando whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/whitelist/<rule_id>', methods=['DELETE'])
def delete_whitelist_rule(rule_id):
    """
    DELETE /api/v1/assets/whitelist/{rule_id}
    
    Elimina una regla de whitelist
    
    Args:
        rule_id: ID de MongoDB de la regla
    
    Returns:
        200: Regla eliminada
        400: ID inválido
        404: Regla no encontrada
        500: Error del servidor
    """
    try:
        # Validar ObjectId
        try:
            oid = ObjectId(rule_id)
        except:
            return jsonify({'error': 'Invalid rule ID'}), 400
        
        db = current_app.mongo.db
        
        # Verificar que existe
        result = db['whitelist_rules'].find_one_and_delete({'_id': oid})
        if not result:
            return jsonify({'error': 'Rule not found'}), 404
        
        return jsonify({
            'status': 'ok',
            'message': 'Whitelist rule deleted'
        }), 200
    
    except Exception as e:
        logger.error(f"Error eliminando whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# INITIALIZATION ENDPOINT
# ============================================================================

@bp_assets.route('/init', methods=['POST'])
def initialize_assets_and_whitelist():
    """
    POST /api/v1/assets/init
    
    ⚠️ SOLO DESARROLLO: Inicializa assets y whitelist por defecto
    
    NO USAR en producción sin supervisión
    
    Returns:
        200: Inicialización completada
        500: Error del servidor
    """
    try:
        # En producción, agregar verificación de token/permiso
        db = current_app.mongo.db
        
        initialize_default_assets(db)
        initialize_open5gs_assets(db)
        initialize_default_whitelist(db)
        
        return jsonify({
            'status': 'ok',
            'message': 'Assets and whitelist initialized'
        }), 200
    
    except Exception as e:
        logger.error(f"Error inicializando: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500