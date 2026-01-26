"""
Sistema de generación de reglas Suricata para VulnDB-5G
Versión 4.0 - OPTIMIZADO para producción + SOPORTE 5G
- Añadidos thresholds para evitar alertas duplicadas
- Patrones PCRE más específicos
- http.uri y http.header para mejor rendimiento
- fast_pattern para optimización de matching
- Detección de protocolos 5G: GTP, PFCP, SBI, NGAP
"""
from typing import Dict, List, Optional, Set
import re


class KeywordAnalyzer:
    """Analiza descripciones técnicas y keywords para extraer patrones de ataque."""
    
    ATTACK_PATTERNS = {
        'sqli': ['sql injection', 'union', 'select', 'database', 'query', 'sql'],
        'rce': ['shell', 'command', 'execute', 'exec', 'injection', 'metacharacters', 'code execution', 'arbitrary code', 'remote code', 'system command'],
        'path_traversal': ['directory traversal', 'path traversal', '../', 'arbitrary file', 'file read', 'file access', '/etc/passwd', 'file upload'],
        'xxe': ['xml external entity', 'xxe', 'xml', 'entity', 'doctype'],
        'xss': ['cross-site scripting', 'xss', '<script', 'javascript injection'],
        'buffer_overflow': ['buffer overflow', 'heap overflow', 'stack overflow', 'memory corruption', 'out-of-bounds', 'write beyond'],
        'auth_bypass': ['authentication bypass', 'authorization bypass', 'access control', 'privilege escalation', 'unauthorized access', 'without authentication'],
        'dos': ['denial of service', 'dos', 'crash', 'consume resources', 'exhaust', 'infinite loop', 'resource exhaustion'],
        'ssrf': ['server-side request forgery', 'ssrf', 'internal request', 'localhost'],
        'csrf': ['cross-site request forgery', 'csrf', 'forged request'],
        # Patrones 5G
        'gtp_attack': ['gtp', 'gtp-u', 'gtp-c', 'gtpu', 'gtpc', 'tunnel', 'teid', 'user plane', 'bearer'],
        'pfcp_attack': ['pfcp', 'session establishment', 'session management', 'smf', 'upf', 'packet forwarding'],
        'ngap_attack': ['ngap', 'n2', 'ng-ap', 'ran', 'gnb', 'amf', 'initial context', 'ue context', 'handover'],
        'nas_attack': ['nas', 'n1', 'non-access stratum', 'registration', 'authentication', 'security mode', 'pdu session'],
        'sbi_attack': ['sbi', 'service-based interface', 'http/2', 'nrf', 'ausf', 'udm', 'udr', 'nssf', 'pcf', 'api', 'openapi', 'json', 'service discovery'],
        'diameter_attack': ['diameter', 's6a', 's6d', 'hss', 'authentication vector', 'avp', 'diameter routing']
    }
    
    NETWORK_INDICATORS = ['remote', 'network', 'http', 'web', 'api', 'rest', 'endpoint', 'attacker can', 'remote attacker', 'unauthenticated', 'without authentication']
    
    FIVEG_COMPONENTS = [
        'open5gs', 'free5gc', 'openairinterface', 'oai',
        'amf', 'smf', 'upf', 'ausf', 'udm', 'udr', 'nrf',
        'pcf', 'nssf', 'gnb', 'ueransim', '5g core'
    ]
    
    @classmethod
    def extract_attack_vectors(cls, cve_data: dict) -> Set[str]:
        vectors = set()
        text = ' '.join([cve_data.get('descripcion_tecnica', ''), cve_data.get('tipo', ''), ' '.join(cve_data.get('palabras_clave_normalizadas', []))]).lower()
        for vector_type, patterns in cls.ATTACK_PATTERNS.items():
            if any(pattern in text for pattern in patterns):
                vectors.add(vector_type)
        return vectors
    
    @classmethod
    def is_network_exploitable(cls, cve_data: dict) -> bool:
        text = ' '.join([cve_data.get('descripcion_tecnica', ''), cve_data.get('cvssv3', {}).get('vector', '')]).lower()
        return any(indicator in text for indicator in cls.NETWORK_INDICATORS)
    
    @classmethod
    def extract_5g_attack_vectors(cls, cve_data: dict) -> Set[str]:
        """
        Detecta si un CVE afecta protocolos/componentes 5G.
        
        Returns:
            Set de vectores 5G: {'gtp_attack', 'sbi_attack', ...}
        """
        vectors = set()
        
        # Texto a analizar
        text_sources = [
            cve_data.get('descripcion_tecnica', ''),
            cve_data.get('descripcion_general', ''),
            cve_data.get('tipo', ''),
            cve_data.get('componente_afectado', ''),
            ' '.join(cve_data.get('palabras_clave_normalizadas', [])),
            ' '.join(cve_data.get('infraestructura_5g_afectada', []))
        ]
        
        text = ' '.join(text_sources).lower()
        
        # Buscar patrones 5G específicos
        fiveg_patterns = {
            'gtp_attack': cls.ATTACK_PATTERNS['gtp_attack'],
            'pfcp_attack': cls.ATTACK_PATTERNS['pfcp_attack'],
            'ngap_attack': cls.ATTACK_PATTERNS['ngap_attack'],
            'nas_attack': cls.ATTACK_PATTERNS['nas_attack'],
            'sbi_attack': cls.ATTACK_PATTERNS['sbi_attack'],
            'diameter_attack': cls.ATTACK_PATTERNS['diameter_attack']
        }
        
        for vector_type, patterns in fiveg_patterns.items():
            if any(pattern in text for pattern in patterns):
                vectors.add(vector_type)
        
        return vectors
    
    @classmethod
    def get_5g_component(cls, cve_data: dict) -> Optional[str]:
        """
        Identifica el componente 5G afectado.
        
        Returns:
            Nombre del componente o None
        """
        text = ' '.join([
            cve_data.get('componente_afectado', ''),
            ' '.join(cve_data.get('infraestructura_5g_afectada', []))
        ]).lower()
        
        for component in cls.FIVEG_COMPONENTS:
            if component in text:
                return component
        
        return None


class SuricataRuleBuilder:
    """Constructor de reglas Suricata - PCRE2 compatible y optimizado."""
    
    @staticmethod
    def build_rce_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'shell' in desc or 'metacharacter' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: Shell command injection - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"cmd="; nocase; http.uri; '
                f'pcre:"/cmd=[^&\\\\s]*(whoami|ls|cat|id|pwd|uname|wget|curl|bash|sh|nc)/i"; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_Shell; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'lua' in desc or 'json listener' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: JSON RPC command injection - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"application/json"; nocase; http.header; content:"crtc"; nocase; distance:0; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE_RPC; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-RCE: Command execution attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"cmd"; nocase; http.uri; '
                f'pcre:"/(cmd|command|exec|execute|system|run)=[^&\\\\s]*(whoami|ls|cat|id|bash|sh|rm|wget|curl)/i"; '
                f'threshold:type limit, track by_src, count 1, seconds 300; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type RCE; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_path_traversal_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'firmware' in desc or 'upload' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-PathTraversal: Arbitrary firmware upload - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"firmware"; nocase; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal_Upload; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-PathTraversal: Directory traversal - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:".."; http.uri; '
                f'pcre:"/[?&][^=]{{1,30}}=[^&\\\\s]*(\\\\.\\\\.[\\\\/]|%2e%2e|%252e|etc[\\\\/]passwd)/i"; '
                f'threshold:type limit, track by_src, count 1, seconds 120; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Path_Traversal; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_buffer_overflow_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        componente = cve_data.get('componente_afectado', '').lower()
        
        if 'open5gs' in componente and 'pfcp' in componente:
            return (
                f'alert udp any any -> any 8805 '
                f'(msg:"5G-Core: PFCP buffer overflow - {cve_id}"; '
                f'dsize:>2048; content:"|21|"; depth:1; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:attempted-admin; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Buffer_Overflow, component Open5GS; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return f'# DISABLED: Buffer overflow rule for {cve_id} (too many false positives)'
    
    @staticmethod
    def build_dos_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        return f'# DISABLED: DoS rule for {cve_data.get("cve_id", "UNKNOWN")} (threshold rules with TEE traffic)'
    
    @staticmethod
    def build_access_control_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'proc file' in desc or '/proc/' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Proc filesystem access - {cve_id}"; '
                f'flow:established,to_server; content:"/proc/"; nocase; '
                f'threshold:type limit, track by_src, count 1, seconds 120; '
                f'reference:cve,{cve_id}; classtype:attempted-user; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'admin' in desc or 'privilege' in desc:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Privilege escalation attempt - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"admin"; nocase; http.uri; '
                f'pcre:"/[?&](admin|sudo|root|privilege)=/i"; '
                f'threshold:type limit, track by_src, count 1, seconds 120; '
                f'reference:cve,{cve_id}; classtype:attempted-user; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any any '
                f'(msg:"5G-AccessControl: Unauthorized access attempts - {cve_id}"; '
                f'flow:established,from_server; content:"401"; '
                f'threshold:type threshold, track by_src, count 20, seconds 60; '
                f'reference:cve,{cve_id}; classtype:attempted-user; priority:3; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type Access_Control; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_xss_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert tcp any any -> any any '
            f'(msg:"5G-XSS: Script injection - {cve_id}"; '
            f'flow:established,to_server; '
            f'content:"<script"; nocase; http.uri; '
            f'pcre:"/<script|javascript:|onerror=|onload=/i"; '
            f'threshold:type limit, track by_src, count 1, seconds 60; '
            f'reference:cve,{cve_id}; classtype:web-application-attack; priority:2; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type XSS; '
            f'sid:{sid}; rev:1;)'
        )
    
    @staticmethod
    def build_sqli_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert tcp any any -> any any '
            f'(msg:"5G-SQLi: SQL injection - {cve_id}"; '
            f'flow:established,to_server; '
            f'content:"="; http.uri; '
            f'pcre:"/[?&](id|user|search|query|name)=[^&\\\\s]*(UNION|SELECT|INSERT|DROP|DELETE|UPDATE|OR[^&\\\\s]+1=1|--)/i"; '
            f'threshold:type limit, track by_src, count 1, seconds 120; '
            f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SQL_Injection; '
            f'sid:{sid}; rev:1;)'
        )
    
    # ========================================================================
    # REGLAS ESPECÍFICAS PARA PROTOCOLOS 5G
    # ========================================================================
    
    @staticmethod
    def build_gtp_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para ataques GTP-U (puerto 2152)"""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'malformed' in desc or 'invalid' in desc or 'corrupt' in desc:
            return (
                f'alert udp any any -> any 2152 '
                f'(msg:"5G-GTP-U: Malformed packet - {cve_id}"; '
                f'content:!"|30|"; offset:0; depth:1; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:protocol-command-decode; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type GTP_Malformed, interface N3; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'flood' in desc or 'dos' in desc or 'exhaust' in desc:
            return (
                f'alert udp any any -> any 2152 '
                f'(msg:"5G-GTP-U: Packet flooding - {cve_id}"; '
                f'threshold:type both, track by_src, count 100, seconds 1; '
                f'reference:cve,{cve_id}; classtype:attempted-dos; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type GTP_Flood, interface N3; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'teid' in desc or 'tunnel' in desc or 'spoof' in desc:
            return (
                f'alert udp any any -> any 2152 '
                f'(msg:"5G-GTP-U: Possible TEID spoofing - {cve_id}"; '
                f'content:"|30|"; offset:0; depth:1; '
                f'content:"|00 00 00 00|"; offset:4; depth:4; '
                f'content:!"|01|"; offset:1; depth:1; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:protocol-command-decode; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type GTP_TEID_Spoof, interface N3; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert udp any any -> any 2152 '
                f'(msg:"5G-GTP-U: Anomalous traffic pattern - {cve_id}"; '
                f'dsize:>2000; '
                f'threshold:type both, track by_src, count 50, seconds 10; '
                f'reference:cve,{cve_id}; classtype:protocol-command-decode; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type GTP_Anomaly, interface N3; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_pfcp_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para ataques PFCP (puerto 8805)"""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        
        if 'session' in desc and ('flood' in desc or 'exhaust' in desc):
            return (
                f'alert udp any any -> any 8805 '
                f'(msg:"5G-PFCP: Session establishment flooding - {cve_id}"; '
                f'content:"|20|"; offset:0; depth:1; '
                f'threshold:type both, track by_src, count 50, seconds 10; '
                f'reference:cve,{cve_id}; classtype:attempted-dos; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type PFCP_Flood, interface N4; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'delete' in desc or 'unauthorized' in desc:
            return (
                f'alert udp any any -> any 8805 '
                f'(msg:"5G-PFCP: Unauthorized session deletion - {cve_id}"; '
                f'content:"|20 05|"; offset:0; depth:2; '
                f'threshold:type limit, track by_src, count 1, seconds 30; '
                f'reference:cve,{cve_id}; classtype:attempted-admin; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type PFCP_Unauth, interface N4; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert udp any any -> any 8805 '
                f'(msg:"5G-PFCP: Invalid message format - {cve_id}"; '
                f'content:!"|20|"; offset:0; depth:1; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:protocol-command-decode; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type PFCP_Invalid, interface N4; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_sbi_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para ataques SBI HTTP/2 (puertos 7777, 8080, 29518, etc.)"""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        desc = cve_data.get('descripcion_tecnica', '').lower()
        component = cve_data.get('componente_afectado', '').lower()
        
        sbi_ports = '7777,8080,29518,29510,29504,29503,29502,29509'
        
        if 'ausf' in component or 'authentication' in desc:
            return (
                f'alert tcp any any -> any [{sbi_ports}] '
                f'(msg:"5G-SBI: AUSF authentication bypass - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"POST"; http.method; '
                f'content:"/nausf"; http.uri; '
                f'content:"application/json"; http.header; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SBI_Auth, interface N11, nf AUSF; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'udm' in component or 'subscriber' in desc:
            return (
                f'alert tcp any any -> any [{sbi_ports}] '
                f'(msg:"5G-SBI: UDM subscriber data access - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"/nudm"; http.uri; '
                f'pcre:"/nudm-[a-z]+\\/(v1|v2)\\//i"; '
                f'threshold:type limit, track by_src, count 1, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SBI_Data, interface N11, nf UDM; '
                f'sid:{sid}; rev:1;)'
            )
        elif 'unauthorized' in desc or 'bypass' in desc:
            return (
                f'alert tcp any any -> any [{sbi_ports}] '
                f'(msg:"5G-SBI: Unauthorized API access - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"POST"; http.method; '
                f'pcre:"/\\/(nausf|nudm|nsmf|namf|npcf|nnrf)-/i"; '
                f'content:!"Authorization:"; http.header; '
                f'threshold:type limit, track by_src, count 3, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:1; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SBI_Unauth, interface N11; '
                f'sid:{sid}; rev:1;)'
            )
        else:
            return (
                f'alert tcp any any -> any [{sbi_ports}] '
                f'(msg:"5G-SBI: Suspicious API call - {cve_id}"; '
                f'flow:established,to_server; '
                f'content:"application/json"; http.header; '
                f'pcre:"/\\/(nausf|nudm|nsmf|namf|npcf|nnrf|nssf|nudr)-/i"; '
                f'threshold:type threshold, track by_src, count 100, seconds 60; '
                f'reference:cve,{cve_id}; classtype:web-application-attack; priority:2; '
                f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type SBI_Generic, interface N11; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def build_ngap_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla para ataques NGAP/N2 (SCTP)"""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        
        return (
            f'alert ip any any -> any any '
            f'(msg:"5G-NGAP: Abnormal signaling traffic - {cve_id}"; '
            f'ip_proto:132; dsize:>1000; '
            f'threshold:type both, track by_src, count 50, seconds 10; '
            f'reference:cve,{cve_id}; classtype:protocol-command-decode; priority:2; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_type NGAP_Flood, interface N2; '
            f'sid:{sid}; rev:1;)'
        )
        
class SuricataTemplates:
    """Sistema de generación de reglas Suricata V4.0 - Optimizado con soporte 5G."""
    
    @staticmethod
    def select_template(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Selecciona y genera la regla Suricata apropiada para un CVE.
        VERSIÓN EXTENDIDA con soporte para protocolos 5G.
        """
        # 1. Detectar vectores de ataque tradicionales
        attack_vectors = KeywordAnalyzer.extract_attack_vectors(cve_data)
        tipo = cve_data.get('tipo', '').lower()
        
        # 2. Detectar vectores 5G PRIMERO (tienen prioridad)
        fiveg_vectors = KeywordAnalyzer.extract_5g_attack_vectors(cve_data)
        builder = SuricataRuleBuilder()
        
        # 3. Si es ataque 5G específico, usar builders 5G
        if 'gtp_attack' in fiveg_vectors:
            return builder.build_gtp_rule(cve_data, ia_data, sid)
        
        if 'pfcp_attack' in fiveg_vectors:
            return builder.build_pfcp_rule(cve_data, ia_data, sid)
        
        if 'sbi_attack' in fiveg_vectors:
            # SBI puede tener TAMBIÉN ataques tradicionales (RCE, SQLi)
            # Preferir regla específica SBI si no hay otro vector dominante
            if not attack_vectors or len(attack_vectors) == 1:
                return builder.build_sbi_rule(cve_data, ia_data, sid)
        
        if 'ngap_attack' in fiveg_vectors:
            return builder.build_ngap_rule(cve_data, ia_data, sid)
        
        # 4. Fallback a builders tradicionales
        if 'sqli' in attack_vectors or 'sql' in tipo or 'inyección sql' in tipo:
            return builder.build_sqli_rule(cve_data, ia_data, sid)
        
        if 'rce' in attack_vectors or 'ejecución' in tipo or 'execution' in tipo:
            return builder.build_rce_rule(cve_data, ia_data, sid)
        
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
        
        # 5. Regla genérica
        return SuricataTemplates._build_generic_rule(cve_data, ia_data, sid)
    
    @staticmethod
    def _build_generic_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """Regla genérica para CVEs sin patrón específico identificado."""
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'MEDIUM')
        attack_vector = ia_data.get('attack_vector', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        
        threshold = 1000 if cvss_score >= 9.0 else (2000 if cvss_score >= 7.0 else 5000)
        
        if KeywordAnalyzer.is_network_exploitable(cve_data):
            protocol, flow = 'tcp', 'flow:established; '
        else:
            protocol, flow = 'ip', ''
        
        return (
            f'alert {protocol} any any -> any any '
            f'(msg:"5G-Generic: {tipo} - {cve_id}"; {flow}'
            f'threshold:type threshold, track by_src, count {threshold}, seconds 60; '
            f'reference:cve,{cve_id}; classtype:attempted-recon; priority:3; '
            f'metadata:cve {cve_id}, cvss {cvss_score}, risk {risk_level}, attack_vector {attack_vector}; '
            f'sid:{sid}; rev:1;)'
        )