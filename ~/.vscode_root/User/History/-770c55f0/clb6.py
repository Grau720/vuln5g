"""
Plantillas de reglas Suricata para diferentes protocolos 5G
"""
from typing import Dict, List, Optional

class SuricataTemplates:
    """
    Generador de plantillas de reglas Suricata basadas en CVEs y contexto 5G.
    
    Las reglas son DEFENSIVAS (detección, no explotación).
    """
    
    @staticmethod
    def generate_http2_sba_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla para tráfico HTTP/2 en Service-Based Architecture (SBA).
        
        MEJORADO: Detecta patrones específicos de ataque, no solo métodos HTTP.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        tipo = cve_data.get('tipo', 'Unknown').lower()
        infra = ', '.join(cve_data.get('infraestructura_5g_afectada', ['Unknown']))
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        
        # Construir regla específica según tipo de vulnerabilidad
        
        # ===== SQL INJECTION =====
        if 'sql' in tipo or 'injection' in tipo:
            msg = f'5G-SBA: SQL Injection detected - {cve_id}'
            
            # Múltiples patrones SQL Injection
            patterns = [
                # Patrón 1: UNION SELECT
                (
                    f'alert http any any -> any any '
                    f'(msg:"{msg} (UNION)"; '
                    f'flow:established,to_server; '
                    f'content:"UNION"; http_uri; nocase; '
                    f'content:"SELECT"; http_uri; nocase; distance:0; '
                    f'reference:cve,{cve_id}; '
                    f'classtype:web-application-attack; '
                    f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type SQL_Injection; '
                    f'sid:{sid}; rev:1;)'
                ),
                # Patrón 2: OR 1=1
                (
                    f'alert http any any -> any any '
                    f'(msg:"{msg} (OR bypass)"; '
                    f'flow:established,to_server; '
                    f'content:"OR"; http_uri; nocase; '
                    f'pcre:"/1\\s*=\\s*1/i"; '
                    f'reference:cve,{cve_id}; '
                    f'classtype:web-application-attack; '
                    f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type SQL_Injection; '
                    f'sid:{sid+1}; rev:1;)'
                ),
                # Patrón 3: Comment injection
                (
                    f'alert http any any -> any any '
                    f'(msg:"{msg} (Comment)"; '
                    f'flow:established,to_server; '
                    f'content:"--"; http_uri; '
                    f'reference:cve,{cve_id}; '
                    f'classtype:web-application-attack; '
                    f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type SQL_Injection; '
                    f'sid:{sid+2}; rev:1;)'
                )
            ]
            
            # Retornar primera regla (puedes devolver múltiples separadas por \n)
            return patterns[0]
        
        # ===== PATH TRAVERSAL =====
        elif 'traversal' in tipo or 'path' in tipo or 'directory' in tipo:
            msg = f'5G-SBA: Path Traversal detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'content:"../"; http_uri; '
                f'depth:100; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type Path_Traversal; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== XXE (XML EXTERNAL ENTITY) =====
        elif 'xxe' in tipo or 'xml' in tipo:
            msg = f'5G-SBA: XXE Attack detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'content:"<!ENTITY"; http_client_body; nocase; '
                f'content:"SYSTEM"; http_client_body; nocase; distance:0; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type XXE; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== RCE (REMOTE CODE EXECUTION) =====
        elif 'ejecución' in tipo or 'execution' in tipo or 'rce' in tipo:
            msg = f'5G-SBA: RCE attempt detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'pcre:"/[;&|]\\s*(ls|whoami|cat|nc|curl|wget)/i"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type RCE; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== XSS (CROSS-SITE SCRIPTING) =====
        elif 'xss' in tipo or 'cross-site' in tipo or 'script' in tipo:
            msg = f'5G-SBA: XSS attempt detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'content:"<script"; http_uri; nocase; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type XSS; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== SSRF (SERVER-SIDE REQUEST FORGERY) =====
        elif 'ssrf' in tipo:
            msg = f'5G-SBA: SSRF attempt detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'pcre:"/https?:\\/\\/(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0)/i"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type SSRF; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== BUFFER OVERFLOW =====
        elif 'overflow' in tipo or 'buffer' in tipo or 'memoria' in tipo:
            msg = f'5G-SBA: Buffer Overflow attempt - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'dsize:>4096; '
                f'content:"|90 90 90 90|"; '  # NOP sled
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-admin; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type Buffer_Overflow; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== CSRF (CROSS-SITE REQUEST FORGERY) =====
        elif 'csrf' in tipo or 'forgery' in tipo:
            msg = f'5G-SBA: CSRF attempt detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'http.method; content:"POST"; '
                f'content:!"X-CSRF-Token"; http_header; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type CSRF; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== LDAP INJECTION =====
        elif 'ldap' in tipo:
            msg = f'5G-SBA: LDAP Injection detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'pcre:"/[*()&|]/"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type LDAP_Injection; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== COMMAND INJECTION =====
        elif 'command' in tipo or 'comandos' in tipo:
            msg = f'5G-SBA: Command Injection detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'pcre:"/(;|\\||&amp;|`|\\$\\()/"; '
                f'http_uri; '
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type Command_Injection; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== ACCESO NO AUTORIZADO / CONTROL DE ACCESO =====
        elif 'acceso' in tipo or 'autenticación' in tipo or 'authorization' in tipo:
            msg = f'5G-SBA: Unauthorized Access attempt - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'http.method; content:"GET|7c|POST|7c|PUT|7c|DELETE"; nocase; '
                f'content:!"Authorization:"; http_header; '
                f'content:!"Cookie:"; http_header; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-user; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type Unauthorized_Access; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== DENEGACIÓN DE SERVICIO (DOS) =====
        elif 'denegación' in tipo or 'dos' in tipo or 'denial' in tipo:
            msg = f'5G-SBA: DoS attempt detected - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'threshold:type threshold, track by_src, count 100, seconds 10; '
                f'reference:cve,{cve_id}; '
                f'classtype:attempted-dos; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_type DoS; '
                f'sid:{sid}; rev:1;)'
            )
        
        # ===== FALLBACK: Regla genérica mejorada =====
        else:
            msg = f'5G-SBA: Suspicious HTTP activity - {cve_id}'
            
            return (
                f'alert http any any -> any any '
                f'(msg:"{msg}"; '
                f'flow:established,to_server; '
                f'http.method; content:"POST|7c|PUT|7c|DELETE"; nocase; '
                f'content:!"User-Agent:"; http_header; '  # Sin User-Agent = sospechoso
                f'reference:cve,{cve_id}; '
                f'classtype:web-application-attack; '
                f'metadata:cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, tipo {tipo[:30]}; '
                f'sid:{sid}; rev:1;)'
            )
    
    @staticmethod
    def generate_pfcp_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla para tráfico PFCP (Packet Forwarding Control Protocol).
        
        Detecta anomalías en comunicación SMF-UPF.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        
        msg = f'5G-PFCP: Suspicious PFCP traffic - {cve_id}'
        
        metadata = f'cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, protocol PFCP'
        
        # PFCP usa UDP puerto 8805
        rule = (
            f'alert udp any any -> any 8805 '
            f'(msg:"{msg}"; '
            f'dsize:>1024; '  # Paquetes grandes sospechosos
            f'reference:cve,{cve_id}; '
            f'classtype:protocol-command-decode; '
            f'metadata:{metadata}; '
            f'sid:{sid}; rev:1;)'
        )
        
        return rule
    
    @staticmethod
    def generate_ngap_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla para tráfico NGAP (NG Application Protocol).
        
        Detecta anomalías en comunicación gNB-AMF.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        
        msg = f'5G-NGAP: Suspicious SCTP/NGAP traffic - {cve_id}'
        
        metadata = f'cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, protocol NGAP'
        
        # NGAP usa SCTP
        rule = (
            f'alert sctp any any -> any any '
            f'(msg:"{msg}"; '
            f'dsize:>2048; '
            f'reference:cve,{cve_id}; '
            f'classtype:protocol-command-decode; '
            f'metadata:{metadata}; '
            f'sid:{sid}; rev:1;)'
        )
        
        return rule
    
    @staticmethod
    def generate_diameter_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla para tráfico Diameter.
        
        Detecta anomalías en señalización Diameter (HSS, PCRF).
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        
        msg = f'5G-Diameter: Suspicious Diameter traffic - {cve_id}'
        
        metadata = f'cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, protocol Diameter'
        
        # Diameter usa TCP/SCTP puerto 3868
        rule = (
            f'alert tcp any any -> any 3868 '
            f'(msg:"{msg}"; '
            f'flow:established,to_server; '
            f'dsize:>1024; '
            f'reference:cve,{cve_id}; '
            f'classtype:protocol-command-decode; '
            f'metadata:{metadata}; '
            f'sid:{sid}; rev:1;)'
        )
        
        return rule
    
    @staticmethod
    def generate_sip_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla para tráfico SIP.
        
        Detecta anomalías en señalización VoIP/IMS.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        
        msg = f'5G-SIP: Suspicious SIP traffic - {cve_id}'
        
        metadata = f'cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, protocol SIP'
        
        # SIP usa UDP/TCP puerto 5060
        rule = (
            f'alert tcp any any -> any 5060 '
            f'(msg:"{msg}"; '
            f'flow:established,to_server; '
            f'content:"INVITE|0d 0a|"; nocase; '
            f'reference:cve,{cve_id}; '
            f'classtype:attempted-dos; '
            f'metadata:{metadata}; '
            f'sid:{sid}; rev:1;)'
        )
        
        return rule
    
    @staticmethod
    def generate_generic_network_rule(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Genera regla genérica de red para CVEs sin protocolo específico.
        
        Regla de visibilidad y tagging.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        tipo = cve_data.get('tipo', 'Unknown')
        attack_vector = ia_data.get('attack_vector', 'UNKNOWN')
        infra = ', '.join(cve_data.get('infraestructura_5g_afectada', ['Unknown']))
        
        msg = f'5G-Generic: {tipo} - {cve_id}'
        
        metadata = f'cve {cve_id}, cvss_score {cvss_score}, risk_level {risk_level}, attack_vector {attack_vector}, infra {infra}'
        
        # Regla genérica basada en attack vector
        if attack_vector == 'NETWORK':
            rule = (
                f'alert ip any any -> any any '
                f'(msg:"{msg}"; '
                f'threshold:type limit, track by_src, count 100, seconds 60; '
                f'reference:cve,{cve_id}; '
                f'classtype:suspicious-traffic; '
                f'metadata:{metadata}; '
                f'sid:{sid}; rev:1;)'
            )
        elif attack_vector == 'ADJACENT':
            rule = (
                f'alert ip any any -> any any '
                f'(msg:"{msg}"; '
                f'threshold:type limit, track by_src, count 50, seconds 60; '
                f'reference:cve,{cve_id}; '
                f'classtype:suspicious-traffic; '
                f'metadata:{metadata}; '
                f'sid:{sid}; rev:1;)'
            )
        else:  # LOCAL, PHYSICAL
            rule = (
                f'alert ip any any -> any any '
                f'(msg:"{msg}"; '
                f'threshold:type limit, track by_src, count 10, seconds 60; '
                f'reference:cve,{cve_id}; '
                f'classtype:suspicious-traffic; '
                f'metadata:{metadata}; '
                f'sid:{sid}; rev:1;)'
            )
        
        return rule
    
    @staticmethod
    def select_template(cve_data: dict, ia_data: dict, sid: int) -> str:
        """
        Selecciona y genera la regla apropiada según el protocolo/contexto.
        
        Args:
            cve_data: Datos del CVE desde MongoDB
            ia_data: Datos de predicción de la IA
            sid: SID asignado
        
        Returns:
            Regla Suricata generada
        """
        protocolo = cve_data.get('protocolo_principal', '').lower() if cve_data.get('protocolo_principal') else ''
        
        # Seleccionar plantilla según protocolo
        if 'http' in protocolo or 'sba' in protocolo or 'rest' in protocolo:
            return SuricataTemplates.generate_http2_sba_rule(cve_data, ia_data, sid)
        elif 'pfcp' in protocolo or 'gtp' in protocolo:
            return SuricataTemplates.generate_pfcp_rule(cve_data, ia_data, sid)
        elif 'ngap' in protocolo or 'sctp' in protocolo:
            return SuricataTemplates.generate_ngap_rule(cve_data, ia_data, sid)
        elif 'diameter' in protocolo:
            return SuricataTemplates.generate_diameter_rule(cve_data, ia_data, sid)
        elif 'sip' in protocolo:
            return SuricataTemplates.generate_sip_rule(cve_data, ia_data, sid)
        else:
            return SuricataTemplates.generate_generic_network_rule(cve_data, ia_data, sid)