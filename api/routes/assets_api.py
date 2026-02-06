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
from datetime import datetime

from api.assets.inventory import (
    AssetInventoryManager,
    WhitelistEngine,
    initialize_default_assets,
    initialize_default_whitelist,
    initialize_open5gs_assets
)

from api.assets.version_detector import detect_version_simple

from api.assets.inference import (
    infer_service_name,
    infer_role_from_ports,
    infer_role_from_name,
    infer_services_from_name,
    infer_category_from_role,
    calculate_confidence,
    infer_role,
    infer_services,
    infer_category,
    infer_component_5g
)

from api.assets.port_scanner import scan_common_5g_ports

from config.network_config import (
    get_local_networks, 
    is_target_in_local_networks,
    get_discovery_config
)

from api.assets.cve_matcher import CVEMatcher, match_asset_cves_simple

logger = logging.getLogger(__name__)

# Blueprint para todas las rutas de assets
bp_assets = Blueprint('assets', __name__, url_prefix='/api/v1/assets')

LOCAL_NETWORKS = get_local_networks()
logger.debug(f"🌐 Redes locales detectadas: {LOCAL_NETWORKS}")

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
# DISCOVERY ENDPOINTS
# ============================================================================

@bp_assets.route('/discovery/pending', methods=['GET'])
def list_pending_assets():
    """
    Lista assets descubiertos pero NO registrados aún
    CON DETECCIÓN DINÁMICA DE CAMBIOS
    
    Returns:
        200: Lista de assets pendientes de aprobación con cambios detectados
    """
    try:
        db = current_app.mongo.db
        
        # Assets descubiertos (colección temporal)
        pending = list(db['discovered_assets'].find({
            'status': 'pending'
        }))
        
        # Para cada asset, asegurar que tenga registered_data y changes si está registrado
        for asset in pending:
            asset['_id'] = str(asset['_id'])
            
            if asset.get('already_registered'):
                # Buscar asset registrado
                registered = db['network_assets'].find_one({'ip': asset['ip']})
                
                if registered:
                    # Asegurar que tiene registered_data
                    if not asset.get('registered_data'):
                        asset['registered_data'] = {
                            'hostname': registered.get('hostname'),
                            'role': registered.get('role'),
                            'services': registered.get('services', []),
                            'tags': registered.get('tags', []),
                            'software': registered.get('software'),
                            'version': registered.get('version'),
                            'criticality': registered.get('criticality'),
                            'owner': registered.get('owner')
                        }
                    
                    # SIEMPRE recalcular cambios (para estar seguro)
                    changes = {}
                    
                    # Hostname
                    if (registered.get('hostname') and asset.get('hostname') and 
                        asset['hostname'] != registered['hostname']):
                        changes['hostname'] = {
                            'old': registered['hostname'],
                            'new': asset['hostname']
                        }
                    
                    # Role
                    if (registered.get('role') and asset.get('role') and 
                        asset['role'] != registered['role']):
                        changes['role'] = {
                            'old': registered['role'],
                            'new': asset['role']
                        }
                    
                    # Software
                    if (registered.get('software') and asset.get('software') and 
                        asset['software'] != registered['software']):
                        changes['software'] = {
                            'old': registered['software'],
                            'new': asset['software']
                        }
                    
                    # Version
                    if (registered.get('version') and asset.get('version') and 
                        asset['version'] != 'unknown' and
                        asset['version'] != registered['version']):
                        changes['version'] = {
                            'old': registered['version'],
                            'new': asset['version']
                        }
                    
                    # Services - detectar añadidos/removidos
                    if registered.get('services') and asset.get('services'):
                        reg_ports = {f"{s['name']}:{s.get('port')}" for s in registered['services']}
                        new_ports = {f"{s['name']}:{s.get('port')}" for s in asset['services']}
                        
                        added = [s for s in asset['services'] 
                                if f"{s['name']}:{s.get('port')}" not in reg_ports]
                        removed = [s for s in registered['services'] 
                                  if f"{s['name']}:{s.get('port')}" not in new_ports]
                        
                        if added:
                            changes['services_added'] = added
                        if removed:
                            changes['services_removed'] = removed
                    
                    # Tags - detectar añadidos/removidos
                    if registered.get('tags') and asset.get('tags'):
                        # ✅ Filtrar tags automáticos en AMBOS lados
                        exclude = {'auto-discovered', 'docker', 'network-scan'}
                        
                        reg_tags = set(registered['tags']) - exclude
                        new_tags = set(asset['tags']) - exclude
                        
                        added = list(new_tags - reg_tags)
                        removed = list(reg_tags - new_tags)
                        
                        if added:
                            changes['tags_added'] = added
                        if removed:
                            changes['tags_removed'] = removed
                    
                    asset['changes'] = changes if changes else None
                    
                    logger.debug(f"Asset {asset['ip']}: {len(changes) if changes else 0} cambios detectados")
        
        return jsonify({
            'total': len(pending),
            'assets': pending
        }), 200
    
    except Exception as e:
        logger.error(f"Error listando pending assets: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/discovery/<ip>/approve', methods=['POST'])
def approve_discovered_asset(ip):
    """
    Aprueba un asset descubierto y lo registra oficialmente
    
    Body (opcional):
    {
        "role": "override role",
        "criticality": "HIGH",
        "owner": "team-name"
    }
    
    Returns:
        200: Asset aprobado y registrado
    """
    try:
        db = current_app.mongo.db
        overrides = request.get_json() or {}
        
        # Obtener asset de cola
        discovered = db['discovered_assets'].find_one({'ip': ip, 'status': 'pending'})
        
        if not discovered:
            return jsonify({'error': 'Asset no encontrado en pending queue'}), 404
        
        # Merge con overrides del usuario
        asset_data = {
            'ip': discovered['ip'],
            'hostname': overrides.get('hostname', discovered.get('hostname')),
            'role': overrides.get('role', discovered.get('role')),
            'owner': overrides.get('owner', 'unknown'),
            'services': discovered.get('services', []),
            'criticality': overrides.get('criticality', 'MEDIUM'),
            'tags': discovered.get('tags', []) + ['approved'],
        }
        
        # Registrar en inventory oficial
        mgr = AssetInventoryManager(db)
        mgr.create_asset(asset_data)
        
        # Marcar como aprobado en discovered_assets
        db['discovered_assets'].update_one(
            {'ip': ip},
            {'$set': {'status': 'approved', 'approved_at': datetime.utcnow()}}
        )
        
        return jsonify({
            'status': 'ok',
            'message': f'Asset {ip} aprobado y registrado'
        }), 200
    
    except Exception as e:
        logger.error(f"Error aprobando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/discovery/<ip>/reject', methods=['POST'])
def reject_discovered_asset(ip):
    """
    Rechaza un asset descubierto (no se registra)
    """
    try:
        db = current_app.mongo.db
        
        result = db['discovered_assets'].update_one(
            {'ip': ip, 'status': 'pending'},
            {'$set': {'status': 'rejected', 'rejected_at': datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Asset no encontrado'}), 404
        
        return jsonify({
            'status': 'ok',
            'message': f'Asset {ip} rechazado'
        }), 200
    
    except Exception as e:
        logger.error(f"Error rechazando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/discovery/<ip>/update', methods=['PATCH'])
def update_discovered_asset(ip):
    """
    Actualiza un asset registrado con cambios detectados en discovery
    
    Body:
    {
        "apply_changes": true,  // Si false, solo marca como revisado sin actualizar
        "changes": {            // Cambios específicos a aplicar (opcional, aplica todos si no se especifica)
            "hostname": {"old": "...", "new": "..."},
            "version": {"old": "...", "new": "..."},
            ...
        }
    }
    
    Returns:
        200: Asset actualizado
        404: Asset no encontrado
        400: No hay cambios detectados
    """
    try:
        db = current_app.mongo.db
        data = request.get_json() or {}
        
        # Obtener asset descubierto
        discovered = db['discovered_assets'].find_one({'ip': ip, 'status': 'pending'})
        
        if not discovered:
            return jsonify({'error': 'Asset no encontrado en pending queue'}), 404
        
        if not discovered.get('already_registered'):
            return jsonify({
                'error': 'Este asset no está registrado. Use /approve en su lugar.'
            }), 400
        
        # Si apply_changes es False, solo marcar como revisado
        if not data.get('apply_changes', True):
            db['discovered_assets'].update_one(
                {'ip': ip},
                {'$set': {'status': 'rejected', 'rejected_at': datetime.utcnow()}}
            )
            return jsonify({
                'status': 'ok',
                'message': 'Cambios ignorados, asset marcado como revisado'
            }), 200
        
        # Obtener asset registrado actual
        registered_asset = db['network_assets'].find_one({'ip': ip})
        
        if not registered_asset:
            return jsonify({'error': 'Asset registrado no encontrado'}), 404
        
        # ============================================================
        # MERGE INTELIGENTE: Aplicar solo cambios detectados
        # ============================================================
        update_fields = {}
        
        # Campos que se actualizan si cambiaron
        simple_fields = ['hostname', 'role', 'software', 'version', 'version_confidence', 'version_method']
        
        for field in simple_fields:
            if discovered.get(field) and discovered[field] != registered_asset.get(field):
                update_fields[field] = discovered[field]
                logger.info(f"📝 Actualizando {field}: {registered_asset.get(field)} → {discovered[field]}")
        
        # Services: MERGE (agregar nuevos, mantener existentes)
        if discovered.get('services'):
            existing_services = registered_asset.get('services', [])
            new_services = discovered['services']
            
            # Crear set de servicios existentes para comparación rápida
            existing_svc_keys = {f"{s['name']}:{s.get('port')}" for s in existing_services}
            
            # Agregar solo servicios nuevos
            merged_services = existing_services.copy()
            for svc in new_services:
                svc_key = f"{svc['name']}:{svc.get('port')}"
                if svc_key not in existing_svc_keys:
                    merged_services.append(svc)
                    logger.info(f"➕ Nuevo servicio detectado: {svc['name']}:{svc.get('port')}")
            
            if len(merged_services) > len(existing_services):
                update_fields['services'] = merged_services
        
        # Tags: MERGE (agregar nuevos, mantener existentes)
        if discovered.get('tags'):
            existing_tags = set(registered_asset.get('tags', []))
            new_tags = set(discovered['tags'])
            
            # Filtrar tags automáticos que no queremos propagar
            exclude_tags = {'auto-discovered', 'docker', 'network-scan'}
            new_tags = new_tags - exclude_tags
            
            merged_tags = list(existing_tags | new_tags)
            
            if len(merged_tags) > len(existing_tags):
                update_fields['tags'] = merged_tags
                logger.info(f"🏷️ Tags actualizados: {existing_tags} → {merged_tags}")
        
        # Actualizar timestamp
        update_fields['last_scanned'] = datetime.utcnow()
        
        # ============================================================
        # HISTORIAL DE VERSIONES
        # ============================================================
        if 'version' in update_fields and update_fields['version'] != 'unknown':
            version_history = registered_asset.get('version_history', [])
            
            # Agregar nueva entrada al historial
            version_history.append({
                'version': update_fields['version'],
                'detected_at': datetime.utcnow(),
                'confidence': discovered.get('version_confidence', 'MEDIUM'),
                'method': discovered.get('version_method', 'unknown')
            })
            
            # Mantener solo últimas 10 versiones
            update_fields['version_history'] = version_history[-10:]
        
        # ============================================================
        # APLICAR CAMBIOS
        # ============================================================
        if not update_fields:
            return jsonify({
                'status': 'ok',
                'message': 'No hay cambios que aplicar',
                'changes_applied': []
            }), 200
        
        # Actualizar en MongoDB
        db['network_assets'].update_one(
            {'ip': ip},
            {'$set': update_fields}
        )
        
        # Marcar como procesado en discovered_assets
        db['discovered_assets'].update_one(
            {'ip': ip},
            {'$set': {
                'status': 'approved',
                'approved_at': datetime.utcnow(),
                'changes_applied': list(update_fields.keys())
            }}
        )
        
        logger.info(f"✅ Asset {ip} actualizado con {len(update_fields)} cambios")
        
        return jsonify({
            'status': 'ok',
            'message': f'Asset {ip} actualizado correctamente',
            'changes_applied': list(update_fields.keys()),
            'updated_fields': update_fields
        }), 200
    
    except Exception as e:
        logger.error(f"Error actualizando asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/discovery/config', methods=['GET'])
def get_discovery_configuration():
    """
    Retorna configuración de discovery con redes permitidas auto-detectadas.
    
    Returns:
        200: Configuración con redes locales y targets sugeridos
    """
    try:
        config = get_discovery_config()
        
        return jsonify({
            'status': 'ok',
            'config': config
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo config: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_assets.route('/discovery/run', methods=['POST'])
def run_discovery_to_queue():
    """
    Ejecuta discovery con fallback automático y validación de redes locales:
    1. Valida que targets estén en redes locales
    2. Intenta Docker inspect (rápido, solo desarrollo)
    3. Si falla, usa network scan (producción)
    
    Body:
    {
        "targets": {
            "core": ["172.22.0.0/24"],
            "ran_oam": [],
            "transport": []
        },
        "profile": "fast" | "standard" | "exhaustive"
    }
    
    Returns:
        202: Discovery iniciado
        403: Targets no permitidos (redes externas)
        400: Escaneo demasiado grande o targets faltantes
    """
    try:
        from config.network_config import get_local_networks, is_target_in_local_networks
        import ipaddress
        
        data = request.get_json()
        targets = data.get('targets', {})
        profile = data.get('profile', 'fast')
        
        db = current_app.mongo.db
        discovered_count = 0
        method_used = None
        
        # =================================================================
        # VALIDACIÓN 1: REDES LOCALES
        # =================================================================
        local_networks = get_local_networks()
        logger.info(f"🌐 Redes locales detectadas: {local_networks}")
        
        forbidden_targets = []
        
        for category, target_list in targets.items():
            for target in target_list:
                if target and not is_target_in_local_networks(target, local_networks):
                    forbidden_targets.append(target)
        
        if forbidden_targets:
            # Registrar intento de escaneo no autorizado
            db['audit_log'].insert_one({
                'timestamp': datetime.utcnow(),
                'action': 'discovery_scan_blocked',
                'user_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'forbidden_targets': forbidden_targets,
                'allowed_networks': sorted(local_networks),
                'reason': 'targets_not_in_local_networks'
            })
            
            logger.warning(f"⛔ Discovery bloqueado desde {request.remote_addr}: targets no autorizados {forbidden_targets}")
            
            return jsonify({
                'error': 'forbidden_networks',
                'detail': f'Los siguientes targets no están en redes locales: {", ".join(forbidden_targets)}',
                'allowed_networks': sorted(local_networks),
                'hint': 'Solo puedes escanear redes accesibles desde este servidor.'
            }), 403
        
        # =================================================================
        # VALIDACIÓN 2: TAMAÑO MÁXIMO
        # =================================================================
        total_ips = 0
        for category, target_list in targets.items():
            for target in target_list:
                if target:
                    if "/" in target:
                        try:
                            network = ipaddress.ip_network(target, strict=False)
                            total_ips += network.num_addresses
                        except:
                            total_ips += 1
                    else:
                        total_ips += 1
        
        MAX_IPS = 2048
        if total_ips > MAX_IPS:
            return jsonify({
                'error': 'scan_too_large',
                'detail': f'El escaneo incluye {total_ips} IPs. Máximo permitido: {MAX_IPS}',
                'hint': 'Divide el escaneo en rangos más pequeños.'
            }), 400
        
        # =================================================================
        # AUDIT LOG: Registrar escaneo autorizado
        # =================================================================
        db['audit_log'].insert_one({
            'timestamp': datetime.utcnow(),
            'action': 'discovery_scan_authorized',
            'user_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'targets': targets,
            'total_ips': total_ips,
            'profile': profile
        })
        
        logger.info(f"✅ Discovery autorizado desde {request.remote_addr}: {total_ips} IPs en redes locales")
        
        # =================================================================
        # MÉTODO 1: DOCKER INSPECT (solo desarrollo/testing)
        # =================================================================
        try:
            import docker
            
            logger.info("🐳 Intentando discovery via Docker...")
            
            client = docker.from_env()
            network_name = "docker_open5gs_default"
            network = client.networks.get(network_name)
            
            containers = network.attrs.get('Containers', {})
            
            if not containers:
                raise Exception("No hay contenedores en la red Docker")
            
            # Procesar contenedores encontrados
            for container_id, container_info in containers.items():
                name = container_info.get('Name', '').lower()
                ip = container_info.get('IPv4Address', '').split('/')[0]
                
                if not ip:
                    continue
                
                # ============================================================
                # 🆕 DISCOVERY INTELIGENTE V2 (Heurística mejorada)
                # ============================================================
                from api.assets.port_scanner import scan_common_5g_ports
                import os

                DISCOVERY_MODE = os.getenv('DISCOVERY_MODE', 'auto')
                logger.debug(f"🔍 Discovery en {ip} ({name}) - Modo: {DISCOVERY_MODE}")

                services = []
                open_ports = []
                detection_method = 'unknown'

                if DISCOVERY_MODE == 'expected':
                    services = infer_services(name)
                    open_ports = [s.get('port') for s in services if s.get('port')]
                    detection_method = 'expected_services'
                    logger.info(f"📋 {ip} ({name}): Usando servicios esperados (modo forzado)")

                elif DISCOVERY_MODE == 'portscan':
                    try:
                        scan_result = scan_common_5g_ports(ip, timeout=0.5)
                        services = scan_result['services']
                        open_ports = scan_result['open_ports']
                        detection_method = 'port_scan'
                        logger.info(f"🔍 {ip} ({name}): {len(open_ports)} puertos detectados → {open_ports}")
                    except Exception as e:
                        logger.error(f"❌ Error en port scan {ip}: {e}")
                        services = infer_services(name)
                        open_ports = [s.get('port') for s in services if s.get('port')]
                        detection_method = 'expected_services_fallback'

                else:  # auto
                    try:
                        scan_result = scan_common_5g_ports(ip, timeout=0.5)
                        detected_ports = scan_result['open_ports']
                        
                        # ============================================================
                        # HEURÍSTICA MEJORADA: Detectar red compartida
                        # ============================================================
                        shared_network_detected = False
                        reason = ""
                        
                        # 1. Detectar puertos UDP que NO deberían estar
                        #    (2152 y 8805 son SOLO para UPF/SMF, no para otros componentes)
                        name_lower = name.lower()
                        suspicious_ports = []
                        
                        # Si NO es UPF/SMF pero tiene 2152 o 8805 → Red compartida
                        if not any(x in name_lower for x in ['upf', 'smf']):
                            if 2152 in detected_ports:
                                suspicious_ports.append('2152/GTP-U')
                            if 8805 in detected_ports:
                                suspicious_ports.append('8805/PFCP')
                        
                        if suspicious_ports:
                            shared_network_detected = True
                            reason = f"Puertos sospechosos detectados: {', '.join(suspicious_ports)}"
                        
                        # 2. Umbral de puertos (backup heuristic)
                        elif len(detected_ports) > 5:
                            shared_network_detected = True
                            reason = f"Demasiados puertos ({len(detected_ports)} > 5)"
                        
                        # ============================================================
                        # DECISIÓN
                        # ============================================================
                        if shared_network_detected:
                            logger.warning(
                                f"⚠️ {ip} ({name}): Red compartida detectada. "
                                f"Razón: {reason}. Usando servicios esperados."
                            )
                            services = infer_services(name)
                            open_ports = [s.get('port') for s in services if s.get('port')]
                            detection_method = 'expected_services_auto'
                        else:
                            # Port scan confiable
                            services = scan_result['services']
                            open_ports = detected_ports
                            detection_method = 'port_scan_auto'
                            logger.info(f"✅ {ip} ({name}): {len(open_ports)} puertos detectados → {open_ports}")
                    
                    except Exception as scan_error:
                        logger.warning(f"⚠️ Error en port scan {ip}: {scan_error}. Usando servicios esperados.")
                        services = infer_services(name)
                        open_ports = [s.get('port') for s in services if s.get('port')]
                        detection_method = 'expected_services_error'

                # ============================================================
                # INFERIR METADATOS
                # ============================================================
                role = infer_role_from_ports(open_ports) if open_ports else infer_role(name)
                confidence = calculate_confidence(name, open_ports)
                category = infer_category(name)

                component_5g_info = infer_component_5g(name=name, ports=open_ports)
                component_5g_info['services_detection_method'] = detection_method

                # ============================================================
                # DETECTAR VERSIÓN
                # ============================================================
                image_name = None
                try:
                    container_obj = client.containers.get(container_id)
                    if container_obj.image.tags:
                        image_name = container_obj.image.tags[0]
                except Exception as e:
                    logger.debug(f"No se pudo obtener imagen de {name}: {e}")

                # Verificar si ya está registrado en inventory oficial
                existing_in_inventory = db['network_assets'].find_one({'ip': ip})
                
                # ✅ DETECTAR VERSIÓN CON PRIORIDAD A DOCKER IMAGE
                import asyncio
                from api.assets.version_detector import VersionDetector
                
                detector = VersionDetector()
                
                # Método 1: Extraer de nombre de imagen Docker (PRIORITARIO)
                software_from_image, version_from_image = detector._extract_version_from_docker_image(image_name)
                
                if software_from_image and version_from_image != 'unknown':
                    version_info = {
                        'software': software_from_image,
                        'version': version_from_image,
                        'confidence': 'HIGH',
                        'method': 'docker_image_tag'
                    }
                    logger.info(f"✅ Versión desde Docker image: {software_from_image} {version_from_image}")
                else:
                    # Método 2: Detectar por red (fallback)
                    version_info = asyncio.run(detect_version_simple(ip, open_ports, name))
                
                # ============================================================
                # GUARDAR EN COLA DE PENDING
                # ============================================================
                db['discovered_assets'].update_one(
                    {'ip': ip},
                    {
                        '$set': {
                            'ip': ip,
                            'hostname': name,
                            'role': role,
                            'services': services,
                            'tags': [category, 'auto-discovered', 'docker'],
                            'discovery_method': 'docker',
                            'discovered_at': datetime.utcnow(),
                            'status': 'pending',
                            'confidence': confidence,
                            'already_registered': existing_in_inventory is not None,
                            'registered_at': existing_in_inventory.get('created_at') if existing_in_inventory else None,
                            'software': version_info.get('software'),
                            'version': version_info.get('version'),
                            'version_confidence': version_info.get('confidence'),
                            'version_method': version_info.get('method'),
                            **component_5g_info,  # component_5g, component_5g_confidence, component_5g_detection_method
                        }
                    },
                    upsert=True
                )
                discovered_count += 1
                
            method_used = 'docker'
            logger.info(f"✅ Docker discovery: {discovered_count} contenedores encontrados")
        
        except Exception as docker_error:
            logger.info(f"🌐 Docker no disponible ({docker_error}), usando network scan...")
            
            # =================================================================
            # MÉTODO 2: NETWORK SCAN (producción)
            # =================================================================
            
            if not targets or not any(targets.values()):
                return jsonify({
                    'error': 'missing_targets',
                    'detail': 'Docker no disponible. Debe especificar targets para network scan.'
                }), 400
            
            from scanning.plugins.smart_discovery import SmartDiscovery
            from scanning.plugin_base import ScanContext
            import asyncio
            
            # Crear contexto de escaneo
            ctx = ScanContext(
                job_id=f"discovery_{int(datetime.utcnow().timestamp())}",
                profile=profile,
                targets=targets,
                raw_targets=targets
            )
            
            # Ejecutar discovery
            plugin = SmartDiscovery()
            
            async def run_discovery():
                return await plugin.run(ctx)
            
            findings = asyncio.run(run_discovery())
            
            # Procesar hosts activos descubiertos
            for finding in findings:
                if 'active_host' not in finding.tags:
                    continue
                
                ip = finding.target
                if not ip:
                    continue
                
                # Inferir metadatos desde los findings
                hostname = f"host-{ip.replace('.', '-')}"
                role = "Unknown Service"
                services = []
                confidence = "MEDIUM"
                category = "unknown"
                
                # Intentar inferir desde evidencia del finding
                evidence = finding.evidence or {}
                
                # Si hay puertos abiertos, crear lista de servicios
                if evidence.get('open_ports'):
                    services = [
                        {
                            'name': infer_service_name(port),
                            'port': port,
                            'protocol': 'TCP'
                        }
                        for port in evidence['open_ports']
                    ]
                    confidence = "HIGH"
                
                # Intentar identificar componente 5G por puerto
                role = infer_role_from_ports(evidence.get('open_ports', []))
                category = infer_category_from_role(role)
                
                # Si hay hostname detectado, usarlo
                if evidence.get('hostname'):
                    hostname = evidence['hostname']
                    confidence = "HIGH"
                
                # Verificar si ya está registrado en inventory oficial
                existing_in_inventory = db['network_assets'].find_one({'ip': ip})
                
                # Detectar versión
                version_info = asyncio.run(detect_version_simple(
                    ip=ip,
                    ports=evidence.get('open_ports', []),
                    hostname=hostname
                ))
                
                # Guardar en cola de pending
                db['discovered_assets'].update_one(
                    {'ip': ip},
                    {
                        '$set': {
                            'ip': ip,
                            'hostname': hostname,
                            'role': role,
                            'services': services,
                            'tags': [category, 'auto-discovered', 'network-scan'],
                            'discovery_method': 'network',
                            'discovered_at': datetime.utcnow(),
                            'status': 'pending',
                            'confidence': confidence,
                            'evidence': evidence,
                            'already_registered': existing_in_inventory is not None,
                            'registered_at': existing_in_inventory.get('created_at') if existing_in_inventory else None,
                            'software': version_info.get('software'),
                            'version': version_info.get('version'),
                            'version_confidence': version_info.get('confidence'),
                            'version_method': version_info.get('method'),
                        }
                    },
                    upsert=True
                )
                discovered_count += 1
            
            method_used = 'network'
            logger.info(f"✅ Network discovery: {discovered_count} hosts activos encontrados")
        
        # Contar total pending
        total_pending = db['discovered_assets'].count_documents({'status': 'pending'})
        
        return jsonify({
            'status': 'ok',
            'message': f'Discovery completed via {method_used}',
            'method_used': method_used,
            'discovered_count': discovered_count,
            'total_pending': total_pending
        }), 202
    
    except Exception as e:
        logger.error(f"Error en discovery: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# ============================================================================
# CVE MATCHING ENDPOINTS
# ============================================================================

@bp_assets.route('/<ip>/cves', methods=['GET'])
def get_asset_cves(ip):
    """
    GET /api/v1/assets/{ip}/cves
    
    Retorna CVEs que afectan a un asset específico.
    
    Args:
        ip: Dirección IP del asset
    
    Query params:
        - limit: Máximo de CVEs (default: 50)
        - min_score: Score CVSS mínimo (default: 0)
    
    Returns:
        200: Lista de CVEs con match_method y confidence
        404: Asset no encontrado
        500: Error del servidor
    
    Example:
        GET /api/v1/assets/172.22.0.10/cves?limit=20&min_score=7.0
    """
    try:
        db = current_app.mongo.db
        
        # Verificar que el asset existe
        asset = db['network_assets'].find_one({'ip': ip})
        if not asset:
            return jsonify({
                'error': f'Asset {ip} no encontrado'
            }), 404
        
        # Parámetros
        limit = int(request.args.get('limit', 50))
        min_score = float(request.args.get('min_score', 0))
        
        # Buscar CVEs
        matcher = CVEMatcher(db)
        cves = matcher.match_asset_cves(asset, limit=limit)
        
        # Filtrar por score si se especifica
        if min_score > 0:
            cves = [
                cve for cve in cves
                if cve.get('cvssv3', {}).get('score', 0) >= min_score
            ]
        
        # Convertir ObjectId a string
        for cve in cves:
            cve['_id'] = str(cve['_id'])
        
        # Summary stats
        summary = {
            'total': len(cves),
            'critical': len([c for c in cves if c.get('cvssv3', {}).get('score', 0) >= 9.0]),
            'high': len([c for c in cves if 7.0 <= c.get('cvssv3', {}).get('score', 0) < 9.0]),
            'medium': len([c for c in cves if 4.0 <= c.get('cvssv3', {}).get('score', 0) < 7.0]),
            'by_confidence': {
                'HIGH': len([c for c in cves if c.get('confidence') == 'HIGH']),
                'MEDIUM': len([c for c in cves if c.get('confidence') == 'MEDIUM']),
                'LOW': len([c for c in cves if c.get('confidence') == 'LOW']),
            }
        }
        
        return jsonify({
            'asset': {
                'ip': asset['ip'],
                'hostname': asset.get('hostname'),
                'software': asset.get('software'),
                'version': asset.get('version'),
                'component_5g': asset.get('component_5g')
            },
            'cves': cves,
            'summary': summary
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo CVEs para asset: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/<ip>/report', methods=['GET'])
def get_asset_vulnerability_report(ip):
    """
    GET /api/v1/assets/{ip}/report
    
    Genera reporte completo de vulnerabilidades para un asset.
    
    Incluye:
    - Información del asset
    - CVEs críticos/altos
    - Estadísticas de exposición
    - Recomendaciones de remediación
    
    Args:
        ip: Dirección IP del asset
    
    Returns:
        200: Reporte completo
        404: Asset no encontrado
        500: Error del servidor
    """
    try:
        db = current_app.mongo.db
        matcher = CVEMatcher(db)
        
        report = matcher.generate_asset_report(ip)
        
        # Convertir ObjectIds
        report['asset']['_id'] = str(report['asset']['_id'])
        for cve in report['cves']:
            cve['_id'] = str(cve['_id'])
        
        return jsonify(report), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    
    except Exception as e:
        logger.error(f"Error generando reporte: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/match-all', methods=['POST'])
def match_all_assets_with_cves():
    """
    POST /api/v1/assets/match-all
    
    Correlaciona TODOS los assets del inventario con CVEs.
    
    Body (opcional):
    {
        "limit_per_asset": 20,
        "min_score": 7.0
    }
    
    Returns:
        200: Resultados del matching
        500: Error del servidor
    
    NOTA: Puede tardar varios segundos con muchos assets.
    """
    try:
        data = request.get_json() or {}
        limit_per_asset = data.get('limit_per_asset', 20)
        min_score = data.get('min_score', 0)
        
        db = current_app.mongo.db
        matcher = CVEMatcher(db)
        
        logger.info(f"🔄 Iniciando matching completo de assets con CVEs...")
        
        results = matcher.match_all_assets(limit_per_asset=limit_per_asset)
        
        # Filtrar por score si se especifica
        if min_score > 0:
            for ip in results:
                results[ip] = [
                    cve for cve in results[ip]
                    if cve.get('cvssv3', {}).get('score', 0) >= min_score
                ]
        
        # Convertir ObjectIds
        for ip in results:
            for cve in results[ip]:
                cve['_id'] = str(cve['_id'])
        
        # Summary global
        total_cves = sum(len(cves) for cves in results.values())
        assets_with_cves = len([ip for ip, cves in results.items() if cves])
        
        summary = {
            'total_assets': len(results),
            'assets_with_cves': assets_with_cves,
            'total_cves_found': total_cves,
            'avg_cves_per_asset': round(total_cves / len(results), 2) if results else 0
        }
        
        logger.info(f"✅ Matching completo: {assets_with_cves}/{len(results)} assets con CVEs")
        
        return jsonify({
            'status': 'ok',
            'results': results,
            'summary': summary
        }), 200
    
    except Exception as e:
        logger.error(f"Error en match-all: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/critical-exposure', methods=['GET'])
def get_critical_exposure():
    """
    GET /api/v1/assets/critical-exposure
    
    Retorna assets con CVEs críticos (CVSS >= 9.0).
    
    Query params:
        - min_score: Score mínimo (default: 9.0)
        - limit: Máximo de assets (default: 50)
    
    Returns:
        200: Lista de assets con exposición crítica
        500: Error del servidor
    """
    try:
        min_score = float(request.args.get('min_score', 9.0))
        limit = int(request.args.get('limit', 50))
        
        db = current_app.mongo.db
        matcher = CVEMatcher(db)
        
        # Obtener todos los assets
        assets = list(db['network_assets'].find({}).limit(limit))
        
        exposure = []
        
        for asset in assets:
            critical_cves = matcher.get_critical_cves_for_asset(asset, min_score=min_score)
            
            if critical_cves:
                # Convertir ObjectIds
                asset['_id'] = str(asset['_id'])
                for cve in critical_cves:
                    cve['_id'] = str(cve['_id'])
                
                exposure.append({
                    'asset': {
                        'ip': asset['ip'],
                        'hostname': asset.get('hostname'),
                        'component_5g': asset.get('component_5g'),
                        'software': asset.get('software'),
                        'version': asset.get('version'),
                        'criticality': asset.get('criticality')
                    },
                    'critical_cves': critical_cves,
                    'count': len(critical_cves),
                    'max_score': max(
                        cve.get('cvssv3', {}).get('score', 0)
                        for cve in critical_cves
                    )
                })
        
        # Ordenar por cantidad de CVEs críticos
        exposure.sort(key=lambda x: x['count'], reverse=True)
        
        return jsonify({
            'total_assets_at_risk': len(exposure),
            'exposure': exposure
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo exposición crítica: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_assets.route('/<ip>/remediation', methods=['GET'])
def get_remediation_plan(ip):
    """
    GET /api/v1/assets/{ip}/remediation
    
    Genera plan de remediación priorizado para un asset.
    
    Returns:
        200: Plan de remediación
        404: Asset no encontrado
    """
    try:
        db = current_app.mongo.db
        matcher = CVEMatcher(db)
        
        asset = db['network_assets'].find_one({'ip': ip})
        if not asset:
            return jsonify({'error': f'Asset {ip} no encontrado'}), 404
        
        # Obtener CVEs críticos/altos
        cves = matcher.get_critical_cves_for_asset(asset, min_score=7.0)
        
        # Priorizar por:
        # 1. Exploit probability (IA)
        # 2. CVSS Score
        # 3. CISA KEV
        
        remediation_tasks = []
        
        for cve in cves:
            score = cve.get('cvssv3', {}).get('score', 0)
            exploit_prob = cve.get('ia_analysis', {}).get('exploit_probability', 0)
            
            # Calcular prioridad
            priority = score * 10 + (exploit_prob * 100)
            
            task = {
                'cve_id': cve['cve_id'],
                'priority': round(priority, 2),
                'cvss_score': score,
                'exploit_probability': round(exploit_prob, 3),
                'summary': cve.get('nombre', 'N/A')[:100],
                'remediation': cve.get('recomendaciones_remediacion', 'No disponible')
            }
            
            remediation_tasks.append(task)
        
        # Ordenar por prioridad
        remediation_tasks.sort(key=lambda x: x['priority'], reverse=True)
        
        return jsonify({
            'asset': {
                'ip': ip,
                'hostname': asset.get('hostname'),
                'software': asset.get('software'),
                'version': asset.get('version')
            },
            'tasks': remediation_tasks,
            'total_tasks': len(remediation_tasks),
            'estimated_effort': 'TBD'  # Puedes agregar lógica de estimación
        }), 200
    
    except Exception as e:
        logger.error(f"Error generando plan de remediación: {e}", exc_info=True)
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