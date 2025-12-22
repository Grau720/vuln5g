"""
Sistema de generación de reglas Suricata para VulnDB-5G
Versión 2.4 - Sprint 1 Complete
Mejoras:
- PCRE correctamente escapado (4 backslashes)
- SQLi mejorado con más patterns y parámetros
- Path Traversal más flexible (cualquier parámetro)
- Detección de técnicas de evasión
"""
from typing import Dict, List, Optional, Set
import re


class KeywordAnalyzer:
    """
    Analiza descripciones técnicas y keywords para extraer patrones de ataque.
    """
    
    ATTACK_PATTERNS = {
        'rce': [
            'shell', 'command', 'execute', 'exec', 'injection', 'metacharacters',
            'code execution', 'arbitrary code', 'remote code', 'system command'
        ],
        'sqli': [
            'sql injection', 'union', 'select', 'database', 'query', 'sql'
        ],
        'path_traversal': [
            'directory traversal', 'path traversal', '../', 'arbitrary file',
            'file read', 'file access', '/etc/passwd', 'file upload'
        ],
        'xxe': [
            'xml external entity', 'xxe', 'xml', 'entity', 'doctype'
        ],
        'xss': [
            'cross-site scripting', 'xss', '<script', 'javascript injection'
        ],
        'buffer_overflow': [
            'buffer overflow', 'heap overflow', 'stack overflow', 'memory corruption',
            'out-of-bounds', 'write beyond'
        ],
        'auth_bypass': [
            'authentication bypass', 'authorization bypass', 'access control',
            'privilege escalation', 'unauthorized access', 'without authentication'
        ],
        'dos': [
            'denial of service', 'dos', 'crash', 'consume resources', 'exhaust',
            'infinite loop', 'resource exhaustion'
        ],
        'ssrf': [
            'server-side request forgery', 'ssrf', 'internal request', 'localhost'
        ],
        'csrf': [
            'cross-site request forgery', 'csrf', 'forged request'
        ]
    }
    
    NETWORK_INDICATORS = [
        'remote', 'network', 'http', 'web', 'api', 'rest', 'endpoint',
        'attacker can', 'remote attacker', 'unauthenticated', 'without authentication'
    ]
    
    @classmethod
    def extract_attack_vectors(cls, cve_data: dict) -> Set[str]:
        """Extrae vectores de ataque desde descripción y keywords."""
        vectors = set()
        
        text = ' '.join([
            cve_data.get('descripcion_tecnica', ''),
            cve_data.get('tipo', ''),
            ' '.join(cve_data.get('palabras_clave_normalizadas', []))
        ]).lower()
        
        for vector_type, patterns in cls.ATTACK_PATTERNS.items():
            if any(pattern in text for pattern in patterns):
                vectors.add(vector_type)
        
        return vectors
    
    @classmethod
    def is_network_exploitable(cls, cve_data: dict) -> bool:
        """Determina si la vulnerabilidad es explotable por red."""
        text = ' '.join([
            cve_data.get('descripcion_tecnica', ''),
            cve_data.get('cvssv3', {}).get('vector', '')
        ]).lower()
        
        return any(indicator in text for indicator in cls.NETWORK_INDICATORS)


class SuricataRuleBuilder:
    """
    Constructor de reglas Suricata optimizado para tráfico duplicado (TEE).
    Usa TCP content matching en lugar de HTTP app-layer parsing.
    Versión 2.4 con todas las correcciones de Sprint 1.
    """
    
    @staticmethod
    def build_rce_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla específica para Remote Code Execution."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        # Detectar tipo de RCE
        if 'shell' in desc or 'metacharacter' in desc:
            # Shell metacharacters injection - FIXED: 4 backslashes
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: Shell command injection - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"cmd="; nocase; '
                # FIX: || literal como \|\| (antes había un escape inválido que rompía PCRE2)
                f'pcre:"/cmd=[^&\\\\\\\\s]*(;|%3b|\\\\|\\\\||%7c|&&|%26%26)/i"; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_Shell; '
                f'sid:{sid}; rev:1;)'
            )
        
        elif 'lua' in desc or 'json listener' in desc:
            # RPC/JSON-based RCE
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: JSON RPC command injection - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"application/json"; nocase; '
                f'content:"crtc"; distance:0; nocase; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_RPC; '
                f'sid:{sid}; rev:1;)'
            )
        
        else:
            # RCE genérico - buscar comandos en contexto HTTP
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: Command execution attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(GET|POST)[^\\\\\\\\r\\\\\\\\n]+[?&](cmd|command|exec|execute|system|run)=[^&\\\\\\\\s]*(whoami|ls|cat|pwd|id|uname|wget|curl|bash|sh|rm|chmod|nc)/i"; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_path_traversal_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla específica para Path Traversal - MEJORADA v2.4."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'firmware' in desc or 'upload' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-PathTraversal: Arbitrary firmware upload - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"POST"; depth:10; nocase; '
                f'content:"firmware"; nocase; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal_Upload; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            # Path traversal MEJORADO - más flexible, detecta evasión
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-PathTraversal: Directory traversal - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(GET|POST)[^\\\\\\\\r\\\\\\\\n]+[?&][^=]{{1,30}}=[^&\\\\\\\\s]*(\\\\\\\\.\\\\\\\\.[\\\\\\\\/]|%2e%2e|%252e|\\\\\\\\.\\\\\\\\.%2f|etc[\\\\\\\\/]passwd|boot\\\\\\\\.ini|win\\\\\\\\.ini)/i"; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_buffer_overflow_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para Buffer Overflow - DESHABILITADA por falsos positivos."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        componente = cve_data.get('componente_afectado', '').lower()
        
        if 'open5gs' in componente and 'pfcp' in componente:
            # Caso muy específico: PFCP en Open5GS
            return (
                f'alert udp any any -> any 8805 '
                f'(msg:"5G-Core: PFCP buffer overflow - {cve_id}"; '
                f'dsize:>2048; '
                f'content:"|21|"; depth:1; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-admin; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Buffer_Overflow, component Open5GS; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            # Regla comentada por defecto - demasiados falsos positivos
            return (
                f'# DISABLED: Too many false positives with TEE traffic\n'
                f'# alert tcp any any -> any any '
                f'# (msg:"5G-BufferOverflow: Large packet - {cve_id}"; '
                f'# flow:established; dsize:>4096; '
                f'# reference:cve,{cve_id}; classtype:attempted-admin; priority:2; '
                f'# metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Buffer_Overflow; '
                f'# sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_dos_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para Denial of Service - DESHABILITADA por falsos positivos."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'# DISABLED: DoS threshold rules cause false positives with TEE mirrored traffic\n'
            f'# alert tcp any any -> any any '
            f'# (msg:"5G-DoS: Potential denial of service - {cve_id}"; '
            f'# flow:established; threshold:type threshold, track by_src, count 5000, seconds 60; '
            f'# reference:cve,{cve_id}; classtype:attempted-dos; priority:3; '
            f'# metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type DoS; '
            f'# sid:{sid}; rev:1;)'
        )
    
    @staticmethod
    def build_access_control_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para control de acceso."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'proc file' in desc or '/proc/' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Proc filesystem access - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"/proc/"; nocase; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'admin' in desc or 'privilege' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Privilege escalation attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(GET|POST)[^\\\\\\\\r\\\\\\\\n]+[?&](admin|sudo|root|privilege)=/i"; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Unauthorized access - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"401"; '
                f'threshold:type threshold, track by_src, count 20, seconds 60; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'priority:3; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_xss_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para XSS - FIXED v2.4."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert tcp any any -> any any '
            f'(msg:"5G-XSS: Script injection - {cve_id}"; '
            f'flow:established,to_server; '
            # FIX: cerrar el grupo alternador con )
            f'pcre:"/(GET|POST)[^\\\\\\\\r\\\\\\\\n]+[?&][^=]+=[^&\\\\\\\\s]*(<script|javascript:|onerror=|onload=|eval\\\\\\\\(|alert\\\\\\\\())/i"; '
            f'reference:cve,{cve_id}; '
            f'classtype:web-application-attack; '
            f'priority:2; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type XSS; '
            f'sid:{sid}; rev:1;)'
        )
    
    @staticmethod
    def build_sqli_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para SQL Injection - MEJORADA v2.4."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert tcp any any -> any any '
            f'(msg:"5G-SQLi: SQL injection - {cve_id}"; '
            f'flow:established,to_server; '
            f"pcre:\"/(GET|POST)[^\\\\r\\\\n]+[?&](id|user|username|search|query|name|email|login|page|cat|category|product)=[^&\\\\s]*(UNION[^&\\\\s]+SELECT|SELECT[^&\\\\s]+FROM|INSERT[^&\\\\s]+INTO|DROP[^&\\\\s]+TABLE|DELETE[^&\\\\s]+FROM|UPDATE[^&\\\\s]+SET|OR[^&\\\\s]+1=1|OR[^&\\\\s]+\\\\'1\\\\'=\\\\'1|--|\\\\'\\\\s+OR|admin\\\\'--)/i\"; "
            f'reference:cve,{cve_id}; '
            f'classtype:web-application-attack; '
            f'priority:1; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SQL_Injection; '
            f'sid:{sid}; rev:1;)'
        )


class SuricataTemplates:
    """
    Sistema de generación de reglas Suricata V2.4
    Sprint 1 Complete:
    - PCRE correctamente escapado
    - SQLi detection mejorado
    - Path Traversal más flexible
    - XSS arreglado
    """
    
    @staticmethod
    def select_template(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Selecciona y genera la regla más apropiada."""
        attack_vectors = KeywordAnalyzer.extract_attack_vectors(cve_data)
        tipo = cve_data.get('tipo', '').lower()
        
        builder = SuricataRuleBuilder()
        
        if 'rce' in attack_vectors or 'ejecución' in tipo or 'execution' in tipo:
            return builder.build_rce_rule(cve_data, ia_data, sid)
        
        if 'sqli' in attack_vectors or 'sql' in tipo or 'inyección sql' in tipo:
            return builder.build_sqli_rule(cve_data, ia_data, sid)
        
        if 'path_traversal' in attack_vectors or 'traversal' in tipo:
            return builder.build_path_traversal_rule(cve_data, ia_data, sid)
        
        if 'buffer_overflow' in attack_vectors or 'overflow' in tipo or 'desbordamiento' in tipo:
            return builder.build_buffer_overflow_rule(cve_data, ia_data, sid)
        
        if 'xss' in attack_vectors or 'cross-site' in tipo:
            return builder.build_xss_rule(cve_data, ia_data, sid)
        
        if 'auth_bypass' in attack_vectors or 'acceso' in tipo or 'authorization' in tipo:
            return builder.build_access_control_rule(cve_data, ia_data, sid)
        
        if 'dos' in attack_vectors or 'denegación' in tipo or 'denial' in tipo:
            return builder.build_dos_rule(cve_data, ia_data, sid)
        
        return SuricataTemplates._build_generic_rule(cve_data, ia_data, sid)
    
    @staticmethod
    def _build_generic_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla genérica mejorada - thresholds altos para evitar falsos positivos."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        attack_vector = ia_data.get('attack_vector', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        
        if cvss_score >= 9.0:
            threshold = 1000
        elif cvss_score >= 7.0:
            threshold = 2000
        else:
            threshold = 5000
        
        if KeywordAnalyzer.is_network_exploitable(cve_data):
            protocol = 'tcp'
            flow = 'flow:established; '
        else:
            protocol = 'ip'
            flow = ''
        
        return (
            f'alert {protocol} any any -> any any '
            f'(msg:"5G-Generic: {tipo} - {cve_id}"; '
            f'{flow}'
            f'threshold:type threshold, track by_src, count {threshold}, seconds 60; '
            f'reference:cve,{cve_id}; '
            # FIX: classtype válido en Suricata (evita warning)
            f'classtype:attempted-recon; '
            f'priority:3; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_vector {attack_vector}; '
            f'sid:{sid}; rev:1;)'
        )
