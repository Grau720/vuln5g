"""
API endpoints para alertas de Suricata - VERSIÓN PROFESIONAL

ARQUITECTURA DE CORRELACIÓN:
============================

1. CAPA DE DETECCIÓN (Suricata)
   └─ Alertas brutas: SQLi, RCE, XSS detectados en tráfico

2. CAPA DE CORRELACIÓN (Este módulo)
   └─ Agrupa alertas en INCIDENTES por: src_ip + dest_ip + tipo_ataque + ventana_temporal
   └─ NO asigna CVEs automáticamente

3. CAPA DE ENRIQUECIMIENTO (Asset Inventory)
   └─ ¿Qué software/versión corre en dest_ip?
   └─ Solo si conocemos el asset podemos SUGERIR CVEs

4. CAPA DE INTELIGENCIA (CVE Suggestions)
   └─ CVEs como "potencialmente aplicables", NUNCA "confirmados"
   └─ Requiere validación manual del analista

PRINCIPIO FUNDAMENTAL:
======================
Una alerta de SQLi NO significa que se esté explotando CVE-XXXX.
Significa que alguien INTENTÓ inyección SQL.
La correlación CVE→Alerta solo tiene sentido si sabemos QUÉ SOFTWARE corre en el destino.
"""

import os
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from flask import Blueprint, jsonify, request, current_app
from collections import defaultdict
from bson import ObjectId
import sys

# Importar correlation engine
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

from correlation.correlation_engine import CorrelationEngine
from api.assets.inventory import AssetInventoryManager, WhitelistEngine

logger = logging.getLogger(__name__)

bp_alerts = Blueprint('alerts', __name__, url_prefix='/api/v1/alerts')

# Rutas de logs de Suricata
SURICATA_EVE_LOG = Path("/app/runtime/suricata/logs/eve.json")
SURICATA_FAST_LOG = Path("/app/runtime/suricata/logs/fast.log")

# Caches
_http_cache = {}
_correlation_engine = None
_whitelist_engine = None
_asset_manager = None


# ============================================================================
# INICIALIZACIÓN DE COMPONENTES
# ============================================================================

def get_correlation_engine():
    """Obtiene o inicializa el engine de correlación"""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine(current_app.mongo.db)
        _correlation_engine.create_indexes()
    return _correlation_engine


def get_whitelist_engine():
    """Obtiene o inicializa el WhitelistEngine"""
    global _whitelist_engine
    if _whitelist_engine is None:
        _whitelist_engine = WhitelistEngine(current_app.mongo.db)
    return _whitelist_engine


def get_asset_manager():
    """Obtiene o inicializa el AssetInventoryManager"""
    global _asset_manager
    if _asset_manager is None:
        _asset_manager = AssetInventoryManager(current_app.mongo.db)
    return _asset_manager


# ============================================================================
# EXTRACCIÓN DE INFORMACIÓN DE ALERTAS
# ============================================================================

# Mapeo de patrones a tipos de vulnerabilidad normalizados
VULN_TYPE_PATTERNS = {
    'SQL Injection': [
        r'sql\s*injection', r'sqli', r'\bsql\b.*inject', r'union.*select',
        r'or\s+1\s*=\s*1', r'drop\s+table', r'insert\s+into'
    ],
    'Remote Code Execution': [
        r'rce', r'remote\s*code', r'code\s*execution', r'command\s*execution',
        r'os\s*command', r'shell\s*injection'
    ],
    'Cross-Site Scripting': [
        r'xss', r'cross.site.script', r'<script', r'javascript:'
    ],
    'Path Traversal': [
        r'path\s*traversal', r'directory\s*traversal', r'\.\./', r'\.\.\\',
        r'local\s*file\s*inclusion', r'lfi'
    ],
    'Authentication Bypass': [
        r'auth.*bypass', r'privilege.*escalation', r'access\s*control',
        r'unauthorized\s*access', r'broken\s*auth'
    ],
    'Buffer Overflow': [
        r'buffer\s*overflow', r'stack\s*overflow', r'heap\s*overflow',
        r'memory\s*corruption'
    ],
    'XML External Entity': [
        r'xxe', r'xml\s*external', r'xml\s*injection'
    ],
    'Server-Side Request Forgery': [
        r'ssrf', r'server.side.request'
    ],
    'Denial of Service': [
        r'\bdos\b', r'denial.of.service', r'resource\s*exhaustion'
    ],
    'Information Disclosure': [
        r'info.*disclos', r'sensitive.*data', r'data\s*leak'
    ]
}


def extract_vulnerability_type(alert: dict) -> str | None:
    """
    Extrae el tipo de vulnerabilidad de la firma de alerta.
    
    Args:
        alert: Diccionario con datos de la alerta
    
    Returns:
        Tipo normalizado o None si no se puede determinar
    """
    signature = alert.get('alert', {}).get('signature', '').lower()
    category = alert.get('alert', {}).get('category', '').lower()
    
    # Combinar firma y categoría para búsqueda
    search_text = f"{signature} {category}"
    
    for vuln_type, patterns in VULN_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                return vuln_type
    
    return None


def extract_attack_vector(alert: dict) -> dict:
    """
    Extrae información del vector de ataque desde la alerta.
    
    Returns:
        Dict con: protocol, method, uri, params, payload_snippet
    """
    vector = {
        'protocol': alert.get('proto', 'TCP'),
        'dest_port': alert.get('dest_port'),
        'method': None,
        'uri': None,
        'params': [],
        'payload_snippet': None
    }
    
    # Si hay datos HTTP
    http_data = alert.get('http', {})
    if http_data:
        vector['method'] = http_data.get('http_method')
        vector['uri'] = http_data.get('url') or http_data.get('uri')
        vector['hostname'] = http_data.get('hostname')
        
        # Extraer parámetros de query string
        uri = vector['uri'] or ''
        if '?' in uri:
            query_string = uri.split('?', 1)[1]
            for param in query_string.split('&'):
                if '=' in param:
                    param_name = param.split('=', 1)[0]
                    vector['params'].append(param_name)
    
    return vector


def extract_cve_from_signature(signature: str) -> str | None:
    """Extrae CVE ID de la firma si está presente"""
    match = re.search(r'CVE-\d{4}-\d+', signature, re.IGNORECASE)
    return match.group(0).upper() if match else None


# ============================================================================
# SUGERENCIA DE CVEs (NO CORRELACIÓN)
# ============================================================================

def suggest_potential_cves(alert: dict, asset: dict | None) -> list[dict]:
    """
    SUGIERE CVEs potencialmente aplicables basándose en:
    1. Tipo de ataque detectado
    2. Asset conocido (si existe en inventario)
    3. Componente 5G (si aplica)
    
    IMPORTANTE: Estos son SUGERENCIAS, no correlaciones confirmadas.
    El analista debe validar manualmente.
    
    Args:
        alert: Datos de la alerta
        asset: Datos del asset destino (puede ser None)
    
    Returns:
        Lista de CVEs sugeridos con nivel de confianza
    """
    suggestions = []
    vuln_type = alert.get('vuln_type') or extract_vulnerability_type(alert)
    
    if not vuln_type:
        return []
    
    try:
        col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        
        # Construir query base
        query = {'tipo': {'$regex': vuln_type, '$options': 'i'}}
        
        # Si tenemos asset con información de componente 5G
        if asset:
            component_5g = asset.get('component_5g')
            software = asset.get('software')
            version = asset.get('version')
            
            if component_5g:
                # Buscar CVEs específicos del componente 5G
                query_5g = {
                    **query,
                    'infraestructura_5g_afectada': {'$regex': component_5g, '$options': 'i'}
                }
                cves_5g = list(col.find(query_5g).limit(5))
                
                for cve in cves_5g:
                    suggestions.append({
                        'cve_id': cve['cve_id'],
                        'nombre': cve.get('nombre', ''),
                        'cvss_score': cve.get('cvssv3', {}).get('score'),
                        'tipo': cve.get('tipo'),
                        'match_reason': f"Componente 5G ({component_5g}) + Tipo de ataque ({vuln_type})",
                        'confidence': 'MEDIUM',  # Medium porque tenemos contexto de asset
                        'requires_validation': True,
                        'infraestructura_5g': cve.get('infraestructura_5g_afectada', [])
                    })
            
            if software:
                # Buscar CVEs del software específico
                query_sw = {
                    **query,
                    '$or': [
                        {'componente_afectado': {'$regex': software, '$options': 'i'}},
                        {'etiquetas': {'$regex': software, '$options': 'i'}},
                        {'descripcion_general': {'$regex': software, '$options': 'i'}}
                    ]
                }
                cves_sw = list(col.find(query_sw).limit(5))
                
                for cve in cves_sw:
                    # Evitar duplicados
                    if not any(s['cve_id'] == cve['cve_id'] for s in suggestions):
                        suggestions.append({
                            'cve_id': cve['cve_id'],
                            'nombre': cve.get('nombre', ''),
                            'cvss_score': cve.get('cvssv3', {}).get('score'),
                            'tipo': cve.get('tipo'),
                            'match_reason': f"Software ({software}) + Tipo de ataque ({vuln_type})",
                            'confidence': 'MEDIUM',
                            'requires_validation': True,
                            'version_check_needed': version is not None
                        })
        
        else:
            # Sin asset conocido: sugerencias de BAJA confianza solo por tipo
            # Limitamos a 3 para no abrumar con falsos positivos
            cves_generic = list(col.find(query).sort('cvssv3.score', -1).limit(3))
            
            for cve in cves_generic:
                suggestions.append({
                    'cve_id': cve['cve_id'],
                    'nombre': cve.get('nombre', ''),
                    'cvss_score': cve.get('cvssv3', {}).get('score'),
                    'tipo': cve.get('tipo'),
                    'match_reason': f"Solo tipo de ataque ({vuln_type}) - Asset desconocido",
                    'confidence': 'LOW',
                    'requires_validation': True,
                    'warning': 'Asset no registrado en inventario - correlación poco fiable'
                })
        
        # Ordenar por CVSS score descendente
        suggestions.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
        
        return suggestions[:10]  # Máximo 10 sugerencias
    
    except Exception as e:
        logger.error(f"Error sugiriendo CVEs: {e}")
        return []


# ============================================================================
# PARSEO DE LOGS DE SURICATA
# ============================================================================

def load_http_cache():
    """Carga datos HTTP desde eve.json en memoria para enriquecimiento"""
    global _http_cache
    _http_cache = {}
    
    if not SURICATA_EVE_LOG.exists():
        logger.warning(f"eve.json not found at {SURICATA_EVE_LOG}")
        return
    
    try:
        with open(SURICATA_EVE_LOG, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line.strip())
                    
                    if event.get('http') and event.get('event_type') in ['alert', 'http']:
                        timestamp = event.get('timestamp', '')
                        src_ip = event.get('src_ip', '')
                        dest_ip = event.get('dest_ip', '')
                        dest_port = event.get('dest_port', 0)
                        
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                ts_key = dt.replace(microsecond=0).isoformat()
                            except:
                                ts_key = timestamp[:19]
                        else:
                            continue
                        
                        key = (ts_key, src_ip, dest_ip, dest_port)
                        _http_cache[key] = event.get('http')
                
                except json.JSONDecodeError:
                    continue
    
    except Exception as e:
        logger.error(f"Error leyendo eve.json: {e}")


def get_http_data(alert: dict) -> dict | None:
    """Busca datos HTTP en el cache para esta alerta"""
    try:
        timestamp = alert.get('timestamp', '')
        src_ip = alert.get('src_ip', '')
        dest_ip = alert.get('dest_ip', '')
        dest_port = alert.get('dest_port', 0)
        
        if not timestamp:
            return None
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            ts_key = dt.replace(microsecond=0).isoformat()
        except:
            ts_key = timestamp[:19]
        
        key = (ts_key, src_ip, dest_ip, dest_port)
        
        if key in _http_cache:
            return _http_cache[key]
        
        # Búsqueda aproximada (±1 segundo)
        for cached_key, http_data in _http_cache.items():
            if (cached_key[0][:19] == ts_key[:19] and
                cached_key[1] == src_ip and
                cached_key[2] == dest_ip and
                cached_key[3] == dest_port):
                return http_data
        
        return None
    
    except Exception as e:
        logger.debug(f"Error obteniendo datos HTTP: {e}")
        return None


def parse_fast_log(limit: int = 500) -> list[dict]:
    """Parsea el archivo fast.log de Suricata"""
    if not SURICATA_FAST_LOG.exists():
        logger.warning(f"fast.log no encontrado en {SURICATA_FAST_LOG}")
        return []
    
    alerts = []
    
    try:
        with open(SURICATA_FAST_LOG, 'r') as f:
            lines = f.readlines()
            for line in reversed(lines[-limit:]):
                if not line.strip():
                    continue
                
                try:
                    alert = parse_fast_log_line(line)
                    if alert:
                        alerts.append(alert)
                except Exception as e:
                    logger.debug(f"Error parseando fast.log: {e}")
                    continue
        
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    except Exception as e:
        logger.error(f"Error leyendo fast.log: {e}")
    
    return alerts[:limit]


def parse_fast_log_line(line: str) -> dict | None:
    """Parsea una línea del fast.log"""
    try:
        # Timestamp
        timestamp_match = re.match(r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)', line)
        if not timestamp_match:
            return None
        timestamp_str = timestamp_match.group(1)
        
        try:
            dt = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
            timestamp_iso = dt.isoformat() + 'Z'
        except:
            timestamp_iso = timestamp_str
        
        # Firma/Mensaje
        msg_match = re.search(r'\[\*\*\]\s*(.*?)\s*\[\*\*\]', line)
        signature = msg_match.group(1) if msg_match else "Unknown"
        
        # SID
        sid_match = re.search(r'\[1:(\d+):\d+\]', line)
        signature_id = int(sid_match.group(1)) if sid_match else 0
        
        # Prioridad
        priority_match = re.search(r'\[Priority:\s*(\d+)\]', line)
        priority = int(priority_match.group(1)) if priority_match else 3
        
        # Protocolo
        proto_match = re.search(r'\{(\w+)\}', line)
        proto = proto_match.group(1) if proto_match else "TCP"
        
        # IPs y puertos
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        src_ip = ip_match.group(1) if ip_match else "0.0.0.0"
        src_port = int(ip_match.group(2)) if ip_match else 0
        dest_ip = ip_match.group(3) if ip_match else "0.0.0.0"
        dest_port = int(ip_match.group(4)) if ip_match else 0
        
        # Clasificación
        classification_match = re.search(r'\[Classification:\s*(.*?)\]', line)
        category = classification_match.group(1) if classification_match else "Unknown"
        
        # CVE en firma (si existe)
        cve_in_signature = extract_cve_from_signature(signature)
        
        return {
            'timestamp': timestamp_iso,
            'alert': {
                'signature': signature,
                'signature_id': signature_id,
                'category': category,
                'severity': priority
            },
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'proto': proto,
            'event_type': 'alert',
            'cve_in_signature': cve_in_signature  # Solo referencia, no correlación
        }
    
    except Exception as e:
        logger.debug(f"Error parseando línea: {e}")
        return None


# ============================================================================
# ENRIQUECIMIENTO DE ALERTAS
# ============================================================================

def enrich_alert(alert: dict) -> dict:
    """
    Enriquece una alerta con:
    1. Tipo de vulnerabilidad detectado
    2. Datos HTTP (si disponible)
    3. Información del asset destino (si conocido)
    4. Sugerencias de CVEs (con nivel de confianza)
    
    NO hace correlación automática CVE→Alerta
    """
    # 1. Tipo de vulnerabilidad
    alert['vuln_type'] = extract_vulnerability_type(alert)
    
    # 2. Datos HTTP
    http_data = get_http_data(alert)
    if http_data:
        alert['http'] = http_data
        alert['attack_vector'] = extract_attack_vector(alert)
    
    # 3. Asset destino
    asset_mgr = get_asset_manager()
    dest_ip = alert.get('dest_ip')
    dest_asset = asset_mgr.get_asset(dest_ip) if dest_ip else None
    
    if dest_asset:
        alert['target_asset'] = {
            'ip': dest_asset.get('ip'),
            'hostname': dest_asset.get('hostname'),
            'role': dest_asset.get('role'),
            'component_5g': dest_asset.get('component_5g'),
            'software': dest_asset.get('software'),
            'version': dest_asset.get('version'),
            'criticality': dest_asset.get('criticality'),
            'owner': dest_asset.get('owner')
        }
        alert['enrichment_status'] = 'ASSET_KNOWN'
    else:
        alert['target_asset'] = None
        alert['enrichment_status'] = 'ASSET_UNKNOWN'
    
    # 4. Asset origen (atacante)
    src_ip = alert.get('src_ip')
    src_asset = asset_mgr.get_asset(src_ip) if src_ip else None
    
    if src_asset:
        alert['source_asset'] = {
            'ip': src_asset.get('ip'),
            'hostname': src_asset.get('hostname'),
            'role': src_asset.get('role'),
            'is_internal': True
        }
    else:
        alert['source_asset'] = {
            'ip': src_ip,
            'is_internal': False
        }
    
    # 5. Sugerencias de CVEs (NO correlación)
    alert['cve_suggestions'] = suggest_potential_cves(alert, dest_asset)
    
    return alert


# ============================================================================
# WHITELIST Y ALMACENAMIENTO
# ============================================================================

def is_alert_whitelisted(alert: dict) -> tuple[bool, str | None]:
    """Verifica si una alerta debe ser ignorada según whitelist"""
    try:
        engine = get_whitelist_engine()
        is_whitelisted, reason, rule_id = engine.is_whitelisted(alert)
        
        if is_whitelisted:
            logger.debug(f"🔇 Alerta whitelisted: {alert.get('src_ip')}→{alert.get('dest_ip')}:{alert.get('dest_port')} - {reason}")
        
        return is_whitelisted, reason
    
    except Exception as e:
        logger.warning(f"Error verificando whitelist: {e}")
        return False, None


def store_alert_in_mongodb(alert: dict, skip_whitelist: bool = False) -> ObjectId | None:
    """
    Almacena una alerta en MongoDB y la correlaciona con un INCIDENTE.
    
    IMPORTANTE: Correlaciona por INCIDENTE (campaña de ataque), NO por CVE.
    """
    try:
        # Verificar whitelist
        if not skip_whitelist:
            is_whitelisted, reason = is_alert_whitelisted(alert)
            if is_whitelisted:
                logger.info(f"🔇 Alerta IGNORADA (whitelisted): {alert.get('src_ip')}→{alert.get('dest_ip')}:{alert.get('dest_port')} - {reason}")
                return None
        
        alerts_col = current_app.mongo.db['alerts']
        
        # Metadatos de ingesta
        alert['ingested_at'] = datetime.utcnow()
        alert['source'] = 'suricata'
        
        # Correlacionar con INCIDENTE (no CVE)
        engine = get_correlation_engine()
        group_id = engine.correlate_alert(alert)
        
        if group_id:
            alert['correlation_group_id'] = group_id
        
        # Insertar
        result = alerts_col.insert_one(alert)
        
        logger.debug(f"✅ Alerta almacenada: {result.inserted_id}")
        return result.inserted_id
    
    except Exception as e:
        logger.error(f"Error almacenando alerta en MongoDB: {e}")
        return None


# ============================================================================
# ENDPOINTS DE LA API
# ============================================================================

@bp_alerts.route('/', methods=['GET'])
def get_alerts():
    """
    GET /api/v1/alerts/
    
    Obtiene alertas de Suricata con enriquecimiento profesional.
    
    Query params:
        - limit: número de alertas (default: 100, max: 500)
        - severity: filtrar por severidad (1, 2, 3)
        - vuln_type: filtrar por tipo de vulnerabilidad
        - from_db: obtener de MongoDB (default: false = fast.log)
        - include_whitelisted: incluir alertas whitelisted (default: false)
        - enrichment_status: ASSET_KNOWN | ASSET_UNKNOWN
    
    Returns:
        {
            "alerts": [...],
            "total": 50,
            "whitelisted_count": 5,
            "summary": {...}
        }
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        filter_severity = request.args.get('severity', type=int)
        filter_vuln_type = request.args.get('vuln_type')
        from_db = request.args.get('from_db', 'false').lower() == 'true'
        include_whitelisted = request.args.get('include_whitelisted', 'false').lower() == 'true'
        filter_enrichment = request.args.get('enrichment_status')
        
        # Cargar cache HTTP
        load_http_cache()
        
        whitelisted_count = 0
        
        if from_db:
            # Desde MongoDB
            alerts_col = current_app.mongo.db['alerts']
            query = {}
            
            if filter_severity:
                query['alert.severity'] = filter_severity
            if filter_vuln_type:
                query['vuln_type'] = {'$regex': filter_vuln_type, '$options': 'i'}
            if filter_enrichment:
                query['enrichment_status'] = filter_enrichment
            
            alerts = list(alerts_col.find(query).sort('timestamp', -1).limit(limit))
            
            # Convertir ObjectId
            for alert in alerts:
                alert['_id'] = str(alert['_id'])
                if 'correlation_group_id' in alert:
                    alert['correlation_group_id'] = str(alert['correlation_group_id'])
        
        else:
            # Desde fast.log (tiempo real)
            raw_alerts = parse_fast_log(limit=limit * 2)  # Obtener más por si hay whitelisted
            
            # Filtrar por severidad
            if filter_severity:
                raw_alerts = [a for a in raw_alerts if a.get('alert', {}).get('severity') == filter_severity]
            
            # Enriquecer y procesar
            alerts = []
            for alert in raw_alerts:
                if len(alerts) >= limit:
                    break
                
                # Verificar whitelist
                is_whitelisted, reason = is_alert_whitelisted(alert)
                
                if is_whitelisted and not include_whitelisted:
                    whitelisted_count += 1
                    continue
                
                # Enriquecer
                alert = enrich_alert(alert)
                
                # Filtrar por tipo de vulnerabilidad
                if filter_vuln_type and alert.get('vuln_type'):
                    if filter_vuln_type.lower() not in alert['vuln_type'].lower():
                        continue
                
                # Filtrar por enrichment status
                if filter_enrichment and alert.get('enrichment_status') != filter_enrichment:
                    continue
                
                # Marcar si whitelisted
                if is_whitelisted:
                    alert['whitelisted'] = True
                    alert['whitelist_reason'] = reason
                
                # Almacenar en MongoDB
                alert_id = store_alert_in_mongodb(alert, skip_whitelist=True)
                if alert_id:
                    alert['_id'] = str(alert_id)
                
                alerts.append(alert)
        
        # Generar estadísticas
        stats = generate_statistics(alerts)
        
        return jsonify({
            'alerts': alerts,
            'total': len(alerts),
            'whitelisted_count': whitelisted_count,
            'summary': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo alertas: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'message': 'Fallo al obtener alertas'
        }), 500


@bp_alerts.route('/summary', methods=['GET'])
def get_summary():
    """
    GET /api/v1/alerts/summary
    
    Resumen estadístico de alertas con métricas profesionales.
    """
    try:
        hours = int(request.args.get('hours', 24))
        
        load_http_cache()
        raw_alerts = parse_fast_log(limit=1000)
        alerts = [enrich_alert(a) for a in raw_alerts]
        
        summary = {
            'period': f'{hours}h',
            'total_alerts': len(alerts),
            'by_severity': defaultdict(int),
            'by_vuln_type': defaultdict(int),
            'by_category': defaultdict(int),
            'by_enrichment_status': defaultdict(int),
            'top_attackers': defaultdict(int),
            'top_targets': defaultdict(int),
            'assets_targeted': {
                'known': 0,
                'unknown': 0
            },
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
            
            # Por severidad
            severity = alert_data.get('severity', 3)
            summary['by_severity'][severity] += 1
            
            # Por tipo de vulnerabilidad
            vuln_type = alert.get('vuln_type') or 'Unknown'
            summary['by_vuln_type'][vuln_type] += 1
            
            # Por categoría
            category = alert_data.get('category', 'Unknown')
            summary['by_category'][category] += 1
            
            # Por estado de enriquecimiento
            enrichment = alert.get('enrichment_status', 'UNKNOWN')
            summary['by_enrichment_status'][enrichment] += 1
            
            # Assets
            if enrichment == 'ASSET_KNOWN':
                summary['assets_targeted']['known'] += 1
            else:
                summary['assets_targeted']['unknown'] += 1
            
            # Top atacantes
            src_ip = alert.get('src_ip', 'Unknown')
            summary['top_attackers'][src_ip] += 1
            
            # Top objetivos
            dest_ip = alert.get('dest_ip', 'Unknown')
            summary['top_targets'][dest_ip] += 1
            
            # Sugerencias CVE
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
        
        # Convertir defaultdicts
        summary['by_severity'] = dict(summary['by_severity'])
        summary['by_vuln_type'] = dict(summary['by_vuln_type'])
        summary['by_category'] = dict(summary['by_category'])
        summary['by_enrichment_status'] = dict(summary['by_enrichment_status'])
        
        # Top 10
        summary['top_attackers'] = sorted(
            [{'ip': k, 'count': v} for k, v in summary['top_attackers'].items()],
            key=lambda x: x['count'], reverse=True
        )[:10]
        
        summary['top_targets'] = sorted(
            [{'ip': k, 'count': v} for k, v in summary['top_targets'].items()],
            key=lambda x: x['count'], reverse=True
        )[:10]
        
        # Timeline
        summary['timeline'] = generate_timeline(alerts, hours)
        
        return jsonify(summary), 200
    
    except Exception as e:
        logger.error(f"Error generando resumen: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups', methods=['GET'])
def get_attack_groups():
    """
    GET /api/v1/alerts/groups
    
    Obtiene listado de INCIDENTES (grupos de ataque correlacionados).
    
    Query params:
        - page: página (default: 1)
        - per_page: por página (default: 10)
        - status: active | resolved | re-opened
        - severity: 1, 2, 3
        - src_ip: filtrar por IP origen
        - dest_ip: filtrar por IP destino
        - vuln_type: filtrar por tipo de vulnerabilidad
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        status = request.args.get('status', 'all')
        severity = request.args.get('severity', type=int)
        src_ip = request.args.get('src_ip')
        dest_ip = request.args.get('dest_ip')
        vuln_type = request.args.get('vuln_type')
        
        engine = get_correlation_engine()
        
        # Actualizar estados antes de consultar
        engine.update_group_statuses()
        
        result = engine.get_all_groups(
            page=page,
            per_page=per_page,
            status=status,
            severity=severity,
            src_ip=src_ip,
            dest_ip=dest_ip,
            category=vuln_type  # Usamos category para vuln_type en el engine
        )
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo grupos: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>', methods=['GET'])
def get_attack_group_detail(group_id):
    """
    GET /api/v1/alerts/groups/{group_id}
    
    Obtiene detalles de un INCIDENTE específico con sus alertas.
    
    Incluye:
    - Información del grupo/incidente
    - Alertas paginadas
    - Sugerencias de CVEs agregadas (de todas las alertas)
    - Información de assets afectados
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 25))
        
        engine = get_correlation_engine()
        result = engine.get_group_with_alerts(group_id, page=page, per_page=per_page)
        
        if not result:
            return jsonify({'error': 'Incidente no encontrado'}), 404

        if result.get('group'):
            result['group'] = engine._enrich_group_with_asset(result['group'])
        
        # Convertir ObjectId
        if result['group']:
            result['group']['_id'] = str(result['group']['_id'])
        
        for alert in result['alerts']:
            alert['_id'] = str(alert['_id'])
            if 'correlation_group_id' in alert:
                alert['correlation_group_id'] = str(alert['correlation_group_id'])
        
        # Agregar CVE suggestions de todas las alertas del grupo
        all_suggestions = {}
        affected_assets = {}
        
        for alert in result['alerts']:
            # Agregar sugerencias CVE
            for sug in alert.get('cve_suggestions', []):
                cve_id = sug['cve_id']
                if cve_id not in all_suggestions:
                    all_suggestions[cve_id] = {
                        **sug,
                        'occurrence_count': 1
                    }
                else:
                    all_suggestions[cve_id]['occurrence_count'] += 1
            
            # Agregar assets afectados
            target = alert.get('target_asset')
            if target and target.get('ip'):
                ip = target['ip']
                if ip not in affected_assets:
                    affected_assets[ip] = target
        
        # Ordenar sugerencias por ocurrencias y CVSS
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


@bp_alerts.route('/groups/<group_id>/resolve', methods=['POST'])
def resolve_attack_group(group_id):
    """
    POST /api/v1/alerts/groups/{group_id}/resolve
    
    Marca un INCIDENTE como RESUELTO.
    
    Body:
    {
        "confirmed": true,
        "reason": "Falso positivo - tráfico de testing",
        "resolution_type": "false_positive | mitigated | accepted_risk"
    }
    """
    try:
        data = request.get_json() or {}
        confirmed = data.get('confirmed', False)
        reason = data.get('reason', 'Sin especificar')
        resolution_type = data.get('resolution_type', 'mitigated')
        
        if not confirmed:
            return jsonify({
                'error': 'Confirmación requerida',
                'message': 'Debes confirmar que quieres marcar este incidente como resuelto'
            }), 400
        
        try:
            group_obj_id = ObjectId(group_id)
        except:
            return jsonify({'error': 'ID de incidente inválido'}), 400
        
        engine = get_correlation_engine()
        success = engine.mark_group_resolved(group_obj_id, manually=True)
        
        if not success:
            return jsonify({
                'error': 'No se pudo resolver el incidente',
                'message': 'Verifica que el incidente existe'
            }), 404
        
        # Actualizar con metadata adicional
        current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {'$set': {
                'resolution_reason': reason,
                'resolution_type': resolution_type,
                'resolved_by': 'analyst'  # En producción: usuario autenticado
            }}
        )
        
        group = current_app.mongo.db['attack_groups'].find_one({'_id': group_obj_id})
        
        logger.warning(f"⚠️ Incidente marcado como RESUELTO: {group.get('group_id')} - Tipo: {resolution_type} - Razón: {reason}")
        
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
    """
    POST /api/v1/alerts/groups/{group_id}/reopen
    
    Reabre un INCIDENTE previamente resuelto.
    """
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Reabierto manualmente')
        
        try:
            group_obj_id = ObjectId(group_id)
        except:
            return jsonify({'error': 'ID de incidente inválido'}), 400
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {
                '$set': {
                    'status': 're-opened',
                    'manually_resolved': False,
                    'reopened_at': datetime.utcnow(),
                    'reopen_reason': reason
                },
                '$unset': {
                    'resolution_reason': '',
                    'resolution_type': ''
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Incidente no encontrado'}), 404
        
        group = current_app.mongo.db['attack_groups'].find_one({'_id': group_obj_id})
        
        logger.warning(f"⚠️ Incidente reabierto: {group.get('group_id')} - Razón: {reason}")
        
        return jsonify({
            'status': 'ok',
            'message': 'Incidente reabierto',
            'group_id': group.get('group_id', 'Unknown')
        }), 200
    
    except Exception as e:
        logger.error(f"Error reabriendo incidente: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_alerts.route('/groups/<group_id>/status', methods=['PATCH'])
def update_group_status(group_id):
    """
    PATCH /api/v1/alerts/groups/{group_id}/status
    
    Cambia estado a 'active' (sin metadata adicional).
    Para resolved/re-opened usar endpoints específicos.
    """
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status != 'active':
            return jsonify({
                'error': 'Use /resolve o /reopen para esos estados'
            }), 400
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': ObjectId(group_id)},
            {'$set': {
                'status': 'active',
                'manually_resolved': False,
                'status_updated_at': datetime.utcnow()
            }}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Grupo no encontrado'}), 404
        
        logger.info(f"✅ Grupo {group_id} marcado como activo")
        
        return jsonify({'status': 'ok', 'new_status': 'active'}), 200
    
    except Exception as e:
        logger.error(f"Error actualizando estado: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@bp_alerts.route('/groups/<group_id>/link-cve', methods=['POST'])
def link_cve_to_group(group_id):
    """
    POST /api/v1/alerts/groups/{group_id}/link-cve
    
    Vincula MANUALMENTE un CVE a un incidente.
    
    Esto es para cuando el analista CONFIRMA que un CVE específico
    está siendo explotado en este incidente.
    
    Body:
    {
        "cve_id": "CVE-2024-1234",
        "confidence": "CONFIRMED",
        "notes": "Confirmado mediante análisis de payload"
    }
    """
    try:
        data = request.get_json() or {}
        cve_id = data.get('cve_id')
        confidence = data.get('confidence', 'ANALYST_CONFIRMED')
        notes = data.get('notes', '')
        
        if not cve_id:
            return jsonify({'error': 'cve_id requerido'}), 400
        
        try:
            group_obj_id = ObjectId(group_id)
        except:
            return jsonify({'error': 'ID de incidente inválido'}), 400
        
        # Verificar que el CVE existe en la BD
        cve_col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        cve_data = cve_col.find_one({'cve_id': cve_id})
        
        if not cve_data:
            return jsonify({
                'error': f'CVE {cve_id} no encontrado en la base de datos'
            }), 404
        
        # Añadir el CVE vinculado
        link_data = {
            'cve_id': cve_id,
            'confidence': confidence,
            'notes': notes,
            'linked_at': datetime.utcnow(),
            'linked_by': 'analyst',  # En producción: usuario autenticado
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
        
        logger.info(f"✅ CVE {cve_id} vinculado manualmente al incidente {group_id}")
        
        return jsonify({
            'status': 'ok',
            'message': f'CVE {cve_id} vinculado al incidente',
            'link_data': {
                **link_data,
                'linked_at': link_data['linked_at'].isoformat() + 'Z'
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error vinculando CVE: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bp_alerts.route('/groups/<group_id>/unlink-cve', methods=['POST'])
def unlink_cve_from_group(group_id):
    """
    POST /api/v1/alerts/groups/{group_id}/unlink-cve
    
    Elimina la vinculación manual de un CVE.
    
    Body:
    {
        "cve_id": "CVE-2024-1234"
    }
    """
    try:
        data = request.get_json() or {}
        cve_id = data.get('cve_id')
        
        if not cve_id:
            return jsonify({'error': 'cve_id requerido'}), 400
        
        try:
            group_obj_id = ObjectId(group_id)
        except:
            return jsonify({'error': 'ID de incidente inválido'}), 400
        
        result = current_app.mongo.db['attack_groups'].update_one(
            {'_id': group_obj_id},
            {'$pull': {'confirmed_cves': {'cve_id': cve_id}}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Incidente no encontrado'}), 404
        
        logger.info(f"🔗 CVE {cve_id} desvinculado del incidente {group_id}")
        
        return jsonify({
            'status': 'ok',
            'message': f'CVE {cve_id} desvinculado del incidente'
        }), 200
    
    except Exception as e:
        logger.error(f"Error desvinculando CVE: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ESTADÍSTICAS DE WHITELIST
# ============================================================================

@bp_alerts.route('/whitelist/stats', methods=['GET'])
def get_whitelist_stats():
    """
    GET /api/v1/alerts/whitelist/stats
    
    Estadísticas de reglas de whitelist.
    """
    try:
        engine = get_whitelist_engine()
        approved_rules = engine.list_approved_rules()
        pending_rules = engine.list_pending_rules()
        
        # Convertir ObjectId
        for rule in approved_rules:
            rule['_id'] = str(rule['_id'])
        for rule in pending_rules:
            rule['_id'] = str(rule['_id'])
        
        return jsonify({
            'approved_rules_count': len(approved_rules),
            'pending_rules_count': len(pending_rules),
            'rules': {
                'approved': approved_rules,
                'pending': pending_rules
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo stats de whitelist: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

def generate_statistics(alerts: list) -> dict:
    """Genera estadísticas de alertas"""
    stats = {
        'by_severity': defaultdict(int),
        'by_vuln_type': defaultdict(int),
        'by_category': defaultdict(int),
        'by_enrichment': defaultdict(int)
    }
    
    for alert in alerts:
        alert_data = alert.get('alert', {})
        
        severity = alert_data.get('severity', 3)
        stats['by_severity'][severity] += 1
        
        vuln_type = alert.get('vuln_type') or 'Unknown'
        stats['by_vuln_type'][vuln_type] += 1
        
        category = alert_data.get('category', 'Unknown')
        stats['by_category'][category] += 1
        
        enrichment = alert.get('enrichment_status', 'UNKNOWN')
        stats['by_enrichment'][enrichment] += 1
    
    return {
        'by_severity': dict(stats['by_severity']),
        'by_vuln_type': dict(stats['by_vuln_type']),
        'by_category': dict(stats['by_category']),
        'by_enrichment': dict(stats['by_enrichment'])
    }


def generate_timeline(alerts: list, hours: int) -> list:
    """Timeline de alertas por hora"""
    hourly = defaultdict(int)
    
    for alert in alerts:
        timestamp_str = alert.get('timestamp', '')
        if not timestamp_str:
            continue
        
        try:
            if 'T' in timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp_str)
            
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            hourly[hour_key] += 1
        except Exception:
            continue
    
    now = datetime.utcnow()
    timeline = []
    
    for i in range(hours):
        hour = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00')
        timeline.append({
            'hour': hour,
            'count': hourly.get(hour, 0)
        })
    
    return sorted(timeline, key=lambda x: x['hour'])