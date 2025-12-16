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
        
        Detecta patrones sospechosos en APIs REST de la arquitectura 5G Core.
        """
        cve_id = cve_data.get('cve_id', 'UNKNOWN')
        cvss_score = cve_data.get('cvssv3', {}).get('score', 0)
        tipo = cve_data.get('tipo', 'Unknown')
        infra = ', '.join(cve_data.get('infraestructura_5g_afectada', ['Unknown']))
        risk_level = ia_data.get('risk_level', 'UNKNOWN')
        
        # Componentes afectados comunes en 5G SBA
        componente = cve_data.get('componente_afectado', '').lower()
        
        # Construir content patterns basados en el tipo de vulnerabilidad
        content_patterns = []
        
        if 'injection' in tipo.lower() or 'sql' in tipo.lower():
            content_patterns.append('content:"|27|"; content:"OR"; distance:0;')
        elif 'xss' in tipo.lower() or 'script' in tipo.lower():
            content_patterns.append('content:"<script"; nocase;')
        elif 'path traversal' in tipo.lower() or 'directory' in tipo.lower():
            content_patterns.append('content:"../"; depth:50;')
        elif 'overflow' in tipo.lower() or 'buffer' in tipo.lower():
            content_patterns.append('dsize:>2048;')
        
        # Construir metadata
        metadata_parts = [
            f'cve {cve_id}',
            f'cvss_score {cvss_score}',
            f'risk_level {risk_level}',
            f'infra {infra}',
            f'tipo {tipo[:30]}'  # Limitar longitud
        ]
        metadata = ', '.join(metadata_parts)
        
        # Construir mensaje
        msg = f'5G-SBA: Possible {tipo} attempt - {cve_id}'
        
        # Regla básica HTTP/2
        rule_parts = [
            'alert http2 any any -> any any',
            f'(msg:"{msg}";',
            'flow:established,to_server;',
            'http.method; content:"POST|7c|PUT|7c|DELETE"; nocase;'  # Métodos sospechosos
        ]
        
        # Añadir content patterns si existen
        if content_patterns:
            rule_parts.extend(content_patterns)
        
        # Añadir metadata y cierre
        rule_parts.extend([
            f'reference:cve,{cve_id};',
            f'classtype:web-application-attack;',
            f'metadata:{metadata};',
            f'sid:{sid}; rev:1;)'
        ])
        
        return ' '.join(rule_parts)
    
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