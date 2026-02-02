"""
Enriquecimiento de alertas con información de assets y CVE suggestions
"""

import re
import logging

logger = logging.getLogger(__name__)

# Patrones de tipos de vulnerabilidad
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


def enrich_alert(alert: dict, http_data_getter, asset_manager, cve_suggester) -> dict:
    """
    Enriquece una alerta con:
    1. Tipo de vulnerabilidad detectado
    2. Datos HTTP (si disponible)
    3. Información del asset destino (si conocido)
    4. Sugerencias de CVEs (con nivel de confianza)
    
    Args:
        alert: Alerta a enriquecer
        http_data_getter: Función para obtener datos HTTP
        asset_manager: AssetInventoryManager
        cve_suggester: Función para sugerir CVEs
    
    Returns:
        Alerta enriquecida
    """
    # 1. Tipo de vulnerabilidad
    alert['vuln_type'] = extract_vulnerability_type(alert)
    
    # 2. Datos HTTP
    http_data = http_data_getter(alert)
    if http_data:
        alert['http'] = http_data
        alert['attack_vector'] = extract_attack_vector(alert)
    
    # 3. Asset destino
    dest_ip = alert.get('dest_ip')
    dest_asset = asset_manager.get_asset(dest_ip) if dest_ip else None
    
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
    src_asset = asset_manager.get_asset(src_ip) if src_ip else None
    
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
    alert['cve_suggestions'] = cve_suggester(alert, dest_asset)
    
    return alert