"""
API endpoints para generación de reglas Suricata
"""
import sys
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

from flask import Blueprint, jsonify, request, current_app
from services.rules.suricata_generator import SuricataRuleGenerator
import logging

logger = logging.getLogger(__name__)

bp_rules = Blueprint('rules', __name__, url_prefix='/api/v1/rules')


@bp_rules.route('/suricata/generate', methods=['POST'])
def generate_rules():
    """
    POST /api/v1/rules/suricata/generate
    
    Genera reglas Suricata basadas en criterios.
    
    Body (JSON):
    {
        "risk_levels": ["CRITICAL", "HIGH"],
        "attack_vectors": ["NETWORK"],
        "limit": 50,
        "auto_reload": true,
        "query": {  // opcional, consulta MongoDB personalizada
            "cvssv3.score": {"$gte": 8.0}
        }
    }
    
    Returns:
        JSON con estadísticas de generación
    """
    try:
        data = request.get_json() or {}
        
        # Parámetros
        risk_levels = data.get('risk_levels', ['CRITICAL', 'HIGH'])
        attack_vectors = data.get('attack_vectors', ['NETWORK'])
        limit = data.get('limit', 50)
        auto_reload = data.get('auto_reload', True)
        custom_query = data.get('query')
        
        # Inicializar generador
        generator = SuricataRuleGenerator(current_app.mongo.db)
        
        # Generar y desplegar
        stats = generator.generate_and_deploy(
            query=custom_query,
            risk_levels=risk_levels,
            attack_vectors=attack_vectors,
            limit=limit,
            auto_reload=auto_reload
        )
        
        return jsonify({
            'status': 'success',
            'message': f"{stats['rules_generated']} rules generated",
            'stats': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating rules: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp_rules.route('/suricata/cve/<cve_id>', methods=['GET'])
def generate_rule_for_cve(cve_id):
    """
    GET /api/v1/rules/suricata/cve/<cve_id>
    
    Genera regla Suricata para un CVE específico.
    
    Returns:
        JSON con la regla generada
    """
    try:
        # Buscar CVE en MongoDB
        cve_data = current_app.mongo.db.vulnerabilidades.find_one({'cve_id': cve_id})
        
        if not cve_data:
            return jsonify({
                'status': 'error',
                'message': f'CVE {cve_id} not found'
            }), 404
        
        # Generar regla
        generator = SuricataRuleGenerator(current_app.mongo.db)
        rule = generator.generate_rule_for_cve(cve_data)
        
        if not rule:
            return jsonify({
                'status': 'error',
                'message': f'Could not generate rule for {cve_id}'
            }), 500
        
        # Obtener SID asignado
        sids = generator.sid_allocator.get_sids_for_cve(cve_id)
        
        return jsonify({
            'status': 'success',
            'cve_id': cve_id,
            'rule': rule,
            'sid': sids[0] if sids else None
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating rule for {cve_id}: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp_rules.route('/suricata/top-risk', methods=['GET'])
def generate_top_risk_rules():
    """
    GET /api/v1/rules/suricata/top-risk?risk=CRITICAL&attack_vector=NETWORK&limit=20
    
    Genera reglas para CVEs de alto riesgo.
    
    Query params:
        - risk: CRITICAL|HIGH|MEDIUM|LOW (puede ser múltiple)
        - attack_vector: NETWORK|ADJACENT|LOCAL|PHYSICAL (puede ser múltiple)
        - limit: número máximo de reglas (default: 50)
        - deploy: true|false (auto-deploy a Suricata, default: true)
    
    Returns:
        JSON con reglas generadas y estadísticas
    """
    try:
        # Parámetros
        risk_param = request.args.get('risk', 'CRITICAL,HIGH')
        av_param = request.args.get('attack_vector', 'NETWORK')
        limit = int(request.args.get('limit', 50))
        deploy = request.args.get('deploy', 'true').lower() == 'true'
        
        risk_levels = [r.strip() for r in risk_param.split(',')]
        attack_vectors = [av.strip() for av in av_param.split(',')]
        
        # Generar reglas
        generator = SuricataRuleGenerator(current_app.mongo.db)
        
        if deploy:
            # Pipeline completo con deploy
            stats = generator.generate_and_deploy(
                risk_levels=risk_levels,
                attack_vectors=attack_vectors,
                limit=limit,
                auto_reload=True
            )
            
            return jsonify({
                'status': 'success',
                'message': f"{stats['rules_generated']} rules generated and deployed",
                'stats': stats
            }), 200
        else:
            # Solo generar, no escribir archivo
            rules = generator.generate_top_risk_rules(
                risk_levels=risk_levels,
                attack_vectors=attack_vectors,
                limit=limit
            )
            
            return jsonify({
                'status': 'success',
                'rules_count': len(rules),
                'rules': rules
            }), 200
    
    except Exception as e:
        logger.error(f"Error generating top-risk rules: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp_rules.route('/suricata/reload', methods=['POST'])
def reload_suricata():
    """
    POST /api/v1/rules/suricata/reload
    
    Recarga Suricata para aplicar nuevas reglas.
    
    Returns:
        JSON con resultado del reload
    """
    try:
        generator = SuricataRuleGenerator(current_app.mongo.db)
        success = generator.reload_suricata()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Suricata reloaded successfully'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to reload Suricata'
            }), 500
    
    except Exception as e:
        logger.error(f"Error reloading Suricata: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp_rules.route('/suricata/stats', methods=['GET'])
def get_sid_stats():
    """
    GET /api/v1/rules/suricata/stats
    
    Obtiene estadísticas de SIDs asignados.
    
    Returns:
        JSON con estadísticas de uso de SIDs
    """
    try:
        from services.rules.sid_allocator import SIDAllocator
        allocator = SIDAllocator()
        stats = allocator.get_stats()
        
        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting SID stats: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@bp_rules.route('/suricata/view', methods=['GET'])
def view_generated_rules():
    """
    GET /api/v1/rules/suricata/view
    
    Visualiza las reglas actualmente generadas.
    
    Returns:
        JSON con el contenido del archivo de reglas
    """
    try:
        from pathlib import Path
        rules_file = Path("/app/runtime/suricata/rules/generated.rules")
        
        if not rules_file.exists():
            return jsonify({
                'status': 'success',
                'message': 'No rules file found',
                'rules': []
            }), 200
        
        with open(rules_file, 'r') as f:
            content = f.read()
        
        # Separar en líneas, filtrar comentarios y vacías
        rules = [
            line for line in content.split('\n')
            if line.strip() and not line.strip().startswith('#')
        ]
        
        return jsonify({
            'status': 'success',
            'rules_count': len(rules),
            'rules': rules,
            'file_path': str(rules_file)
        }), 200
    
    except Exception as e:
        logger.error(f"Error viewing rules: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500