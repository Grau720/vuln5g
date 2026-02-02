"""
API endpoints para alertas de Suricata

ENDPOINTS:
- GET  /alerts/                    - Lista de alertas
- GET  /alerts/summary             - Resumen estadístico
- GET  /alerts/groups              - Lista de incidentes
- GET  /alerts/groups/<id>         - Detalle de incidente
- POST /alerts/groups/<id>/resolve - Resolver incidente
- POST /alerts/groups/<id>/reopen  - Reabrir incidente
- PATCH /alerts/groups/<id>/status - Cambiar estado
- POST /alerts/groups/<id>/link-cve - Vincular CVE
- POST /alerts/groups/<id>/unlink-cve - Desvincular CVE
- GET  /alerts/whitelist/stats     - Stats de whitelist
"""

import os
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app
from bson import ObjectId

# Importar todo desde el módulo de alertas
from api.alerts import (
    load_http_cache,
    get_http_data,
    parse_fast_log,
    enrich_alert,
    suggest_potential_cves,
    generate_statistics,
    generate_timeline,
    get_correlation_engine,
    get_whitelist_engine,
    get_asset_manager,
    is_alert_whitelisted,
    store_alert_in_mongodb
)

logger = logging.getLogger(__name__)

bp_alerts = Blueprint('alerts', __name__, url_prefix='/api/v1/alerts')


# ============================================================================
# ENDPOINTS - ALERTAS
# ============================================================================

@bp_alerts.route('/', methods=['GET'])
def get_alerts():
    """
    GET /api/v1/alerts/
    
    Obtiene alertas de Suricata con enriquecimiento profesional.
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        filter_severity = request.args.get('severity', type=int)
        filter_vuln_type = request.args.get('vuln_type')
        from_db = request.args.get('from_db', 'false').lower() == 'true'
        include_whitelisted = request.args.get('include_whitelisted', 'false').lower() == 'true'
        filter_enrichment = request.args.get('enrichment_status')
        
        load_http_cache()
        
        whitelisted_count = 0
        db = current_app.mongo.db
        asset_mgr = get_asset_manager(db)
        whitelist_eng = get_whitelist_engine(db)
        corr_engine = get_correlation_engine(db)
        cve_col = db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        
        if from_db:
            # Desde MongoDB
            query = {}
            if filter_severity:
                query['alert.severity'] = filter_severity
            if filter_vuln_type:
                query['vuln_type'] = {'$regex': filter_vuln_type, '$options': 'i'}
            if filter_enrichment:
                query['enrichment_status'] = filter_enrichment
            
            alerts = list(db['alerts'].find(query).sort('timestamp', -1).limit(limit))
            
            for alert in alerts:
                alert['_id'] = str(alert['_id'])
                if 'correlation_group_id' in alert:
                    alert['correlation_group_id'] = str(alert['correlation_group_id'])
        
        else:
            # Desde fast.log
            raw_alerts = parse_fast_log(limit=limit * 2)
            
            if filter_severity:
                raw_alerts = [a for a in raw_alerts if a.get('alert', {}).get('severity') == filter_severity]
            
            alerts = []
            for alert in raw_alerts:
                if len(alerts) >= limit:
                    break
                
                is_wl, reason = is_alert_whitelisted(alert, whitelist_eng)
                
                if is_wl and not include_whitelisted:
                    whitelisted_count += 1
                    continue
                
                alert = enrich_alert(
                    alert,
                    get_http_data,
                    asset_mgr,
                    lambda a, asset: suggest_potential_cves(a, asset, cve_col)
                )
                
                if filter_vuln_type and alert.get('vuln_type'):
                    if filter_vuln_type.lower() not in alert['vuln_type'].lower():
                        continue
                
                if filter_enrichment and alert.get('enrichment_status') != filter_enrichment:
                    continue
                
                if is_wl:
                    alert['whitelisted'] = True
                    alert['whitelist_reason'] = reason
                
                alert_id = store_alert_in_mongodb(alert, db, corr_engine, skip_whitelist=True)
                if alert_id:
                    alert['_id'] = str(alert_id)
                
                alerts.append(alert)
        
        stats = generate_statistics(alerts)
        
        return jsonify({
            'alerts': alerts,
            'total': len(alerts),
            'whitelisted_count': whitelisted_count,
            'summary': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo alertas: {e}", exc_info=True)
        return jsonify({'error': str(e), 'message': 'Fallo al obtener alertas'}), 500


@bp_alerts.route('/summary', methods=['GET'])
def get_summary():
    """GET /api/v1/alerts/summary - Resumen estadístico"""
    try:
        from collections import defaultdict
        
        hours = int(request.args.get('hours', 24))
        
        load_http_cache()
        raw_alerts = parse_fast_log(limit=1000)
        
        db = current_app.mongo.db
        asset_mgr = get_asset_manager(db)
        cve_col = db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        
        alerts = [
            enrich_alert(a, get_http_data, asset_mgr, lambda alert, asset: suggest_potential_cves(alert, asset, cve_col))
            for a in raw_alerts
        ]
        
        summary = {
            'period': f'{hours}h',
            'total_alerts': len(alerts),
            'by_severity': defaultdict(int),
            'by_vuln_type': defaultdict(int),
            'by_category': defaultdict(int),
            'by_enrichment_status': defaultdict(int),
            'top_attackers': defaultdict(int),
            'top_targets': defaultdict(int),
            'assets_targeted': {'known': 0, 'unknown': 0},
            'cve_suggestions_summary': {
                'with_suggestions': 0,
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0
            },
            'timeline': []
        }
        
        for alert in alerts:
            alert_data = alert.get('alert', {})
            
            summary['by_severity'][alert_data.get('severity', 3)] += 1
            summary['by_vuln_type'][alert.get('vuln_type') or 'Unknown'] += 1
            summary['by_category'][alert_data.get('category', 'Unknown')] += 1
            
            enrichment = alert.get('enrichment_status', 'UNKNOWN')
            summary['by_enrichment_status'][enrichment] += 1
            
            if enrichment == 'ASSET_KNOWN':
                summary['assets_targeted']['known'] += 1
            else:
                summary['assets_targeted']['unknown'] += 1
            
            summary['top_attackers'][alert.get('src_ip', 'Unknown')] += 1
            summary['top_targets'][alert.get('dest_ip', 'Unknown')] += 1
            
            suggestions = alert.get('cve_suggestions', [])
            if suggestions:
                summary['cve_suggestions_summary']['with_suggestions'] += 1
                for sug in suggestions:
                    conf = sug.get('confidence', 'LOW')
                    if conf == 'HIGH':
                        summary['cve_suggestions_summary']['high_confidence'] += 1
                    elif conf == 'MEDIUM':
                        summary['cve_suggestions_summary']['medium_confidence'] += 1
                    else:
                        summary['cve_suggestions_summary']['low_confidence'] += 1
        
        summary['by_severity'] = dict(summary['by_severity'])
        summary['by_vuln_type'] = dict(summary['by_vuln_type'])
        summary['by_category'] = dict(summary['by_category'])
        summary['by_enrichment_status'] = dict(summary['by_enrichment_status'])
        
        summary['top_attackers'] = sorted(
            [{'ip': k, 'count': v} for k, v in summary['top_attackers'].items()],
            key=lambda x: x['count'], reverse=True
        )[:10]
        
        summary['top_targets'] = sorted(
            [{'ip': k, 'count': v} for k, v in summary['top_targets'].items()],
            key=lambda x: x['count'], reverse=True
        )[:10]
        
        summary['timeline'] = generate_timeline(alerts, hours)
        
        return jsonify(summary), 200
    
    except Exception as e:
        logger.error(f"Error generando resumen: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ENDPOINTS - INCIDENTES (GRUPOS)
# ============================================================================

@bp_alerts.route('/groups', methods=['GET'])
def get_attack_groups():
    """GET /api/v1/alerts/groups - Lista de incidentes"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        status = request.args.get('status', 'all')
        severity = request.args.get('severity', type=int)
        src_ip = request.args.get('src_ip')
        dest_ip = request.args.get('dest_ip')
        vuln_type = request.args.get('vuln_type')
        
        engine = get_correlation_engine(current_app.mongo.db)
        engine.update_group_statuses()
        
        result = engine.get_all_groups(
            page=page, per_page=per_page, status=status, severity=severity,
            src_ip=src_ip, dest_ip=dest_ip, category=vuln_type
        )
        
        # ✅ AÑADIR: Stats globales
        groups_col = current_app.mongo.db['attack_groups']
        
        # Total sin filtros
        total_all = groups_col.count_documents({})
        
        # Stats por estado (sin otros filtros)
        active_all = groups_col.count_documents({'status': 'active'})
        resolved_all = groups_col.count_documents({'status': 'resolved'})
        reopened_all = groups_col.count_documents({'status': 're-opened'})
        
        # Stats de severidad (sin filtros)
        critical_all = groups_col.count_documents({'severity': 1})
        
        # Añadir al resultado
        if 'stats' not in result:
            result['stats'] = {}
        
        result['stats']['total_all_groups'] = total_all
        result['stats']['active_count'] = active_all
        result['stats']['resolved_count'] = resolved_all
        result['stats']['reopened_count'] = reopened_all
        result['stats']['critical_count'] = critical_all
        result['stats']['total_filtered_groups'] = result['pagination']['total']
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo grupos: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500 
        
@bp_alerts.route('/groups/<group_id>', methods=['GET'])
def get_attack_group_detail(group_id):
    """GET /api/v1/alerts/groups/{group_id} - Detalle de incidente"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
        
        engine = get_correlation_engine(current_app.mongo.db)
        result = engine.get_group_with_alerts(group_id, page=page, per_page=per_page)
        
        if not result:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if result.get('group'):
            result['group'] = engine._enrich_group_with_asset(result['group'])
            result['group']['_id'] = str(result['group']['_id'])
        
        for alert in result['alerts']:
            alert['_id'] = str(alert['_id'])
            if 'correlation_group_id' in alert:
                alert['correlation_group_id'] = str(alert['correlation_group_id'])
        
        # Agregar CVE suggestions agregadas
        all_suggestions = {}
        affected_assets = {}
        
        for alert in result['alerts']:
            for sug in alert.get('cve_suggestions', []):
                cve_id = sug['cve_id']
                if cve_id not in all_suggestions:
                    all_suggestions[cve_id] = {**sug, 'occurrence_count': 1}
                else:
                    all_suggestions[cve_id]['occurrence_count'] += 1
            
            target = alert.get('target_asset')
            if target and target.get('ip'):
                affected_assets[target['ip']] = target
        
        result['aggregated_cve_suggestions'] = sorted(
            all_suggestions.values(),
            key=lambda x: (x.get('occurrence_count', 0), x.get('cvss_score') or 0),
            reverse=True
        )
        result['affected_assets'] = list(affected_assets.values())
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo detalle del incidente: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/status', methods=['PATCH'])
def update_group_status(group_id):
    """PATCH /api/v1/alerts/groups/{group_id}/status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status != 'active':
            return jsonify({'error': 'Use /resolve o /reopen para esos estados'}), 400
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': ObjectId(group_id)},
            {'$set': {'status': 'active', 'manually_resolved': False, 'status_updated_at': datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Grupo no encontrado'}), 404
        
        logger.info(f"✅ Grupo {group_id} marcado como activo")
        return jsonify({'status': 'ok', 'new_status': 'active'}), 200
    
    except Exception as e:
        logger.error(f"Error actualizando estado: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/resolve', methods=['POST'])
def resolve_attack_group(group_id):
    """POST /api/v1/alerts/groups/{group_id}/resolve"""
    try:
        data = request.get_json() or {}
        confirmed = data.get('confirmed', False)
        reason = data.get('reason', 'Sin especificar')
        resolution_type = data.get('resolution_type', 'mitigated')
        
        if not confirmed:
            return jsonify({'error': 'Confirmación requerida'}), 400
        
        group_obj_id = ObjectId(group_id)
        engine = get_correlation_engine(current_app.mongo.db)
        
        if not engine.mark_group_resolved(group_obj_id, manually=True):
            return jsonify({'error': 'No se pudo resolver el incidente'}), 404
        
        current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {'$set': {'resolution_reason': reason, 'resolution_type': resolution_type, 'resolved_by': 'analyst'}}
        )
        
        group = current_app.mongo.db['attack_groups'].find_one({'_id': group_obj_id})
        logger.warning(f"⚠️ Incidente RESUELTO: {group.get('group_id')} - {resolution_type} - {reason}")
        
        return jsonify({
            'status': 'ok',
            'message': 'Incidente marcado como resuelto',
            'group_id': group.get('group_id', 'Unknown'),
            'resolution_type': resolution_type,
            'resolved_at': group.get('resolved_at', datetime.utcnow()).isoformat() + 'Z'
        }), 200
    
    except Exception as e:
        logger.error(f"Error resolviendo incidente: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/reopen', methods=['POST'])
def reopen_attack_group(group_id):
    """POST /api/v1/alerts/groups/{group_id}/reopen"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Reabierto manualmente')
        group_obj_id = ObjectId(group_id)
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {
                '$set': {'status': 're-opened', 'manually_resolved': False, 'reopened_at': datetime.utcnow(), 'reopen_reason': reason},
                '$unset': {'resolution_reason': '', 'resolution_type': ''}
            }
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Incidente no encontrado'}), 404
        
        group = current_app.mongo.db['attack_groups'].find_one({'_id': group_obj_id})
        logger.warning(f"⚠️ Incidente reabierto: {group.get('group_id')} - {reason}")
        
        return jsonify({'status': 'ok', 'message': 'Incidente reabierto', 'group_id': group.get('group_id', 'Unknown')}), 200
    
    except Exception as e:
        logger.error(f"Error reabriendo incidente: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/link-cve', methods=['POST'])
def link_cve_to_group(group_id):
    """POST /api/v1/alerts/groups/{group_id}/link-cve"""
    try:
        data = request.get_json() or {}
        cve_id = data.get('cve_id')
        
        if not cve_id:
            return jsonify({'error': 'cve_id requerido'}), 400
        
        group_obj_id = ObjectId(group_id)
        cve_col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        cve_data = cve_col.find_one({'cve_id': cve_id})
        
        if not cve_data:
            return jsonify({'error': f'CVE {cve_id} no encontrado en la base de datos'}), 404
        
        link_data = {
            'cve_id': cve_id,
            'confidence': data.get('confidence', 'ANALYST_CONFIRMED'),
            'notes': data.get('notes', ''),
            'linked_at': datetime.utcnow(),
            'linked_by': 'analyst',
            'cve_info': {
                'nombre': cve_data.get('nombre'),
                'cvss_score': cve_data.get('cvssv3', {}).get('score'),
                'tipo': cve_data.get('tipo'),
                'infraestructura_5g': cve_data.get('infraestructura_5g_afectada', [])
            }
        }
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {'$push': {'confirmed_cves': link_data}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Incidente no encontrado'}), 404
        
        logger.info(f"✅ CVE {cve_id} vinculado al incidente {group_id}")
        
        return jsonify({
            'status': 'ok',
            'message': f'CVE {cve_id} vinculado al incidente',
            'link_data': {**link_data, 'linked_at': link_data['linked_at'].isoformat() + 'Z'}
        }), 200
    
    except Exception as e:
        logger.error(f"Error vinculando CVE: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/unlink-cve', methods=['POST'])
def unlink_cve_from_group(group_id):
    """POST /api/v1/alerts/groups/{group_id}/unlink-cve"""
    try:
        data = request.get_json() or {}
        cve_id = data.get('cve_id')
        
        if not cve_id:
            return jsonify({'error': 'cve_id requerido'}), 400
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': ObjectId(group_id)},
            {'$pull': {'confirmed_cves': {'cve_id': cve_id}}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Incidente no encontrado'}), 404
        
        logger.info(f"🔗 CVE {cve_id} desvinculado del incidente {group_id}")
        return jsonify({'status': 'ok', 'message': f'CVE {cve_id} desvinculado'}), 200
    
    except Exception as e:
        logger.error(f"Error desvinculando CVE: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/whitelist/stats', methods=['GET'])
def get_whitelist_stats():
    """GET /api/v1/alerts/whitelist/stats"""
    try:
        engine = get_whitelist_engine(current_app.mongo.db)
        approved_rules = engine.list_approved_rules()
        pending_rules = engine.list_pending_rules()
        
        for rule in approved_rules + pending_rules:
            rule['_id'] = str(rule['_id'])
        
        return jsonify({
            'approved_rules_count': len(approved_rules),
            'pending_rules_count': len(pending_rules),
            'rules': {'approved': approved_rules, 'pending': pending_rules}
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo stats de whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
