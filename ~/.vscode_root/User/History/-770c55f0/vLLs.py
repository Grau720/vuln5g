"""
Sistema inteligente de generación de reglas Suricata para VulnDB-5G
Versión 2.0 - Análisis contextual de CVEs
"""
from typing import Dict, List, Optional, Set
import re


class KeywordAnalyzer:
    """
    Analiza descripciones técnicas y keywords para extraer patrones de ataque.
    """
    
    # Patrones críticos de ataque por categoría
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
    
    # Indicadores de explotabilidad en red
    NETWORK_INDICATORS = [
        'remote', 'network', 'http', 'web', 'api', 'rest', 'endpoint',
        'attacker can', 'remote attacker', 'unauthenticated', 'without authentication'
    ]
    
    @classmethod
    def extract_attack_vectors(cls, cve_data: dict) -> Set[str]:
        """
        Extrae vectores de ataque desde descripción y keywords.
        
        Returns:
            Set de vectores identificados (ej: {'rce', 'path_traversal'})
        """
        vectors = set()
        
        # Texto a analizar
        text = ' '.join([
            cve_data.get('descripcion_tecnica', ''),
            cve_data.get('tipo', ''),
            ' '.join(cve_data.get('palabras_clave_normalizadas', []))
        ]).lower()
        
        # Buscar patrones
        for vector_type, patterns in cls.ATTACK_PATTERNS.items():
            if any(pattern in text for pattern in patterns):
                vectors.add(vector_type)
        
        return vectors
    
    @classmethod
    def extract_critical_keywords(cls, cve_data: dict) -> List[str]:
        """
        Extrae keywords críticas para detección.
        
        Returns:
            Lista de keywords específicas y accionables
        """
        keywords = []
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        # Extraer paths/archivos mencionados
        file_patterns = re.findall(r'(/[a-z0-9_/.]+)', desc)
        keywords.extend(file_patterns[:3])  # Top 3
        
        # Extraer funciones/métodos vulnerables
        func_patterns = re.findall(r'(\w+)\s+function', desc)
        keywords.extend(func_patterns[:2])
        
        # Extraer endpoints mencionados
        endpoint_patterns = re.findall(r'(/api/[a-z0-9_/]+)', desc)
        keywords.extend(endpoint_patterns[:3])
        
        # Keywords de la descripción que indican métodos de explotación
        exploit_keywords = [
            'inject', 'bypass', 'execute', 'upload', 'read', 'write',
            'metacharacters', 'unsanitized', 'unvalidated'
        ]
        
        for word in exploit_keywords:
            if word in desc:
                keywords.append(word)
        
        return list(set(keywords))[:5]  # Top 5 únicos
    
    @classmethod
    def is_network_exploitable(cls, cve_data: dict) -> bool:
        """
        Determina si la vulnerabilidad es explotable por red.
        """
        text = ' '.join([
            cve_data.get('descripcion_tecnica', ''),
            cve_data.get('cvssv3', {}).get('vector', '')
        ]).lower()
        
        return any(indicator in text for indicator in cls.NETWORK_INDICATORS)


class SuricataRuleBuilder:
    """
    Constructor inteligente de reglas Suricata con análisis contextual.
    """
    
    @staticmethod
    def build_rce_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla específica para Remote Code Execution.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        # Detectar tipo de RCE
        if 'shell' in desc or 'metacharacter' in desc:
            # Shell metacharacters injection
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-RCE: Shell metacharacter injection attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(;|\\||&|`|\\$\\(|\\$\\{{)[\\s]*[a-z]/i"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_Shell; '
                f'sid:{sid}; rev:1;)'
            )
        
        elif 'lua' in desc or 'json listener' in desc:
            # RPC/JSON-based RCE
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-RCE: JSON RPC command injection - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"application/json"; http_header; '
                f'pcre:"/crtc|rpc|exec|cmd/i"; http_client_body; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_RPC; '
                f'sid:{sid}; rev:1;)'
            )
        
        else:
            # RCE genérico
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-RCE: Remote command execution attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(ls|whoami|cat|id|uname|nc|curl|wget|ping)/i"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_path_traversal_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla específica para Path Traversal / Arbitrary File Access.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        # Detectar si menciona firmware upload
        if 'firmware' in desc or 'upload' in desc:
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-PathTraversal: Arbitrary firmware upload - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"POST"; http_method; '
                f'pcre:"/fw_upgrade|firmware|crtcfwimage/i"; http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal_Upload; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            # Path traversal clásico
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-PathTraversal: Directory traversal attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'pcre:"/(\\.\\.\\/|\\.\\.\\\|%2e%2e%2f|%2e%2e%5c)/i"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_buffer_overflow_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla para Buffer Overflow / Memory Corruption.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        componente = cve_data.get('componente_afectado', '').lower()
        
        # Si es Open5GS específicamente
        if 'open5gs' in componente:
            return (
                f'alert ip any any -> any any '
                f'(msg:"5G-Core: Buffer overflow attempt in Open5GS - {cve_id}"; '
                f'dsize:>8192; '
                f'content:"|90 90 90 90|"; '  # NOP sled
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-admin; '
                f'priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Buffer_Overflow, component Open5GS; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-BufferOverflow: Memory corruption attempt - {cve_id}"; '
                f'flow:established; '
                f'dsize:>4096; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-admin; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Buffer_Overflow; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_dos_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla para Denial of Service.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        # DoS basado en threshold - más permisivo para detectar floods
        threshold_count = 200 if cvss_score >= 7.0 else 500
        
        return (
            f'alert tcp any any -> any any '
            f'(msg:"5G-DoS: Potential denial of service - {cve_id}"; '
            f'flow:established; '
            f'threshold:type threshold, track by_src, count {threshold_count}, seconds 60; '
            f'reference:cve,{cve_id}; '
            f'classtype:attempted-dos; '
            f'priority:3; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type DoS; '
            f'sid:{sid}; rev:1;)'
        )
    
    @staticmethod
    def build_access_control_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla para problemas de control de acceso / auth bypass.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        # Detectar si es lectura no autorizada de archivos del sistema
        if 'proc file' in desc or '/proc/' in desc:
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-AccessControl: Unauthorized proc filesystem access - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"/proc/"; http_uri; nocase; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            # Control de acceso genérico
            return (
                f'alert http any any -> any any '
                f'(msg:"5G-AccessControl: Unauthorized access attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'http.method; content:"GET|7c|POST"; nocase; '
                f'content:!"Authorization:"; http_header; '
                f'threshold:type threshold, track by_src, count 50, seconds 60; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'priority:3; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_xss_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para Cross-Site Scripting."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert http any any -> any any '
            f'(msg:"5G-XSS: Cross-site scripting attempt - {cve_id}"; '
            f'flow:established,to_server; '
            f'pcre:"/<script|javascript:|onerror=|onload=/i"; '
            f'http_uri; '
            f'reference:cve,{cve_id}; '
            f'classtype:web-application-attack; '
            f'priority:2; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type XSS; '
            f'sid:{sid}; rev:1;)'
        )
    
    @staticmethod
    def build_sqli_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para SQL Injection."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert http any any -> any any '
            f'(msg:"5G-SQLi: SQL injection attempt - {cve_id}"; '
            f'flow:established,to_server; '
            f'pcre:"/(union|select|insert|update|delete|drop|;--|\'\\s+or\\s+)/i"; '
            f'http_uri; '
            f'reference:cve,{cve_id}; '
            f'classtype:web-application-attack; '
            f'priority:1; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SQL_Injection; '
            f'sid:{sid}; rev:1;)'
        )


class SuricataTemplates:
    """
    Sistema de generación de reglas Suricata V2.0
    Con análisis inteligente de CVEs y contexto 5G.
    """
    
    @staticmethod
    def select_template(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Selecciona y genera la regla más apropiada basándose en análisis contextual.
        
        Args:
            cve_data: Datos del CVE desde MongoDB
            ia_data: Datos de predicción de la IA
            sid: SID asignado
        
        Returns:
            Regla Suricata optimizada
        """
        # Analizar CVE
        attack_vectors = KeywordAnalyzer.extract_attack_vectors(cve_data)
        tipo = cve_data.get('tipo', '').lower()
        
        # Prioridad de detección por severidad
        builder = SuricataRuleBuilder()
        
        # 1. RCE (máxima prioridad)
        if 'rce' in attack_vectors or 'ejecución' in tipo or 'execution' in tipo:
            return builder.build_rce_rule(cve_data, ia_data, sid)
        
        # 2. SQL Injection
        if 'sqli' in attack_vectors or 'sql' in tipo or 'inyección sql' in tipo:
            return builder.build_sqli_rule(cve_data, ia_data, sid)
        
        # 3. Path Traversal / File Upload
        if 'path_traversal' in attack_vectors or 'traversal' in tipo:
            return builder.build_path_traversal_rule(cve_data, ia_data, sid)
        
        # 4. Buffer Overflow
        if 'buffer_overflow' in attack_vectors or 'overflow' in tipo or 'desbordamiento' in tipo:
            return builder.build_buffer_overflow_rule(cve_data, ia_data, sid)
        
        # 5. XSS
        if 'xss' in attack_vectors or 'cross-site' in tipo:
            return builder.build_xss_rule(cve_data, ia_data, sid)
        
        # 6. Access Control
        if 'auth_bypass' in attack_vectors or 'acceso' in tipo or 'authorization' in tipo:
            return builder.build_access_control_rule(cve_data, ia_data, sid)
        
        # 7. DoS
        if 'dos' in attack_vectors or 'denegación' in tipo or 'denial' in tipo:
            return builder.build_dos_rule(cve_data, ia_data, sid)
        
        # Fallback: regla genérica contextual
        return SuricataTemplates._build_generic_rule(cve_data, ia_data, sid)
    
    @staticmethod
    def _build_generic_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Regla genérica mejorada para CVEs sin clasificación clara.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        attack_vector = ia_data.get('attack_vector', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        
        # Ajustar threshold según riesgo
        if cvss_score >= 9.0:
            threshold = 10
        elif cvss_score >= 7.0:
            threshold = 50
        else:
            threshold = 100
        
        # Determinar protocolo base
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
            f'classtype:suspicious-traffic; '
            f'priority:3; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_vector {attack_vector}; '
            f'sid:{sid}; rev:1;)'
        )