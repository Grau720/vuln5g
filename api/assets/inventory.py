"""
MÓDULO DE ASSET INVENTORY Y WHITELIST

Este módulo contiene las clases principales (sin dependencias Flask)
para gestionar el inventario de assets y las reglas de whitelist.

Se puede usar tanto en la API Flask como en scripts standalone.

CORREGIDO: Bug en register_expected_connection que causaba conflicto
en MongoDB al usar $setOnInsert y $inc sobre el mismo campo.
"""

import logging
from datetime import datetime
import ipaddress
import re

logger = logging.getLogger(__name__)


class AssetInventoryManager:
    """
    Mantiene inventario de assets (máquinas, servicios)
    
    En producción REAL: Se sincroniza con CMDB, Kubernetes API, 
    AWS/Azure APIs, Terraform state, etc.
    """
    
    def __init__(self, db):
        """
        Args:
            db: Instancia de MongoDB (pymongo Database object)
        """
        self.db = db
        self.assets_col = db['network_assets']
        self.connections_col = db['expected_connections']
    
    def create_asset(self, asset_data):
        """
        Registra un asset (máquina/servicio)
        
        Args:
            asset_data (dict): Datos del asset con estructura:
                {
                    "ip": "172.22.0.52",
                    "hostname": "api-server",
                    "domain": "internal",
                    "role": "API Backend",
                    "owner": "backend-team",
                    "os": "Linux",
                    "services": [
                        {"name": "Python Flask", "port": 5000, "protocol": "TCP"}
                    ],
                    "expected_connections": [
                        {"dest_ip": "172.22.0.50", "dest_port": 27017, "service": "mongodb"}
                    ],
                    "allowed_inbound_ports": [5000],
                    "allowed_outbound_ips": ["172.22.0.50", "172.22.0.53"],
                    "criticality": "HIGH",
                    "tags": ["production", "5g-platform"],
                }
        
        Returns:
            pymongo.results.UpdateResult
        """
        asset = {
            'ip': asset_data['ip'],
            'hostname': asset_data.get('hostname', 'unknown'),
            'domain': asset_data.get('domain', 'internal'),
            'role': asset_data.get('role', 'unknown'),
            'owner': asset_data.get('owner', 'unknown'),
            'os': asset_data.get('os', 'unknown'),
            'services': asset_data.get('services', []),
            'expected_connections': asset_data.get('expected_connections', []),
            'allowed_inbound_ports': asset_data.get('allowed_inbound_ports', []),
            'allowed_outbound_ips': asset_data.get('allowed_outbound_ips', []),
            'criticality': asset_data.get('criticality', 'MEDIUM'),
            'tags': asset_data.get('tags', []),
            'version': asset_data.get('version', []),
            'version_confidence': asset_data.get('version_confidence', []),
            'version_method': asset_data.get('version_method', []),
            'software': asset_data.get('software', []),
            'last_scanned': datetime.utcnow(),
            'created_at': datetime.utcnow()
        }
        
        result = self.assets_col.update_one(
            {'ip': asset['ip']},
            {'$set': asset},
            upsert=True
        )
        
        logger.info(f"✅ Asset registered: {asset['ip']} ({asset['hostname']})")
        return result
    
    def get_asset(self, ip):
        """
        Obtiene asset por IP
        
        Args:
            ip (str): Dirección IP
        
        Returns:
            dict or None: Documento del asset o None si no existe
        """
        return self.assets_col.find_one({'ip': ip})
    
    def list_assets(self, query=None):
        """
        Lista assets con filtros opcionales
        
        Args:
            query (dict, optional): Filtros de MongoDB
        
        Returns:
            list: Lista de assets
        """
        if query is None:
            query = {}
        return list(self.assets_col.find(query))
    
    def is_known_asset(self, ip):
        """
        ¿Esta IP es un asset conocido?
        
        Args:
            ip (str): Dirección IP
        
        Returns:
            bool: True si el asset existe
        """
        return self.assets_col.find_one({'ip': ip}) is not None
    
    def register_expected_connection(self, src_ip, dest_ip, dest_port, service_name):
        """
        Registra una comunicación como "esperada"
        
        Ejemplo: API → MongoDB conexión TCP:27017
        
        Args:
            src_ip (str): IP origen
            dest_ip (str): IP destino
            dest_port (int): Puerto destino
            service_name (str): Nombre del servicio
        
        CORREGIDO: Separar la lógica de insert vs update para evitar
        conflictos entre $setOnInsert y $inc sobre el mismo campo.
        """
        filter_query = {
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'dest_port': dest_port
        }
        
        # Verificar si ya existe el documento
        existing = self.connections_col.find_one(filter_query)
        
        if existing:
            # UPDATE: Documento existe, solo actualizar last_seen e incrementar contador
            self.connections_col.update_one(
                filter_query,
                {
                    '$set': {'last_seen': datetime.utcnow()},
                    '$inc': {'occurrence_count': 1}
                }
            )
        else:
            # INSERT: Documento no existe, crear nuevo con valores iniciales
            self.connections_col.insert_one({
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'service': service_name,
                'first_seen': datetime.utcnow(),
                'last_seen': datetime.utcnow(),
                'occurrence_count': 1,
                'status': 'EXPECTED'
            })

    def is_expected_connection(self, src_ip, dest_ip, dest_port):
        """
        ¿Esta comunicación es esperada?
        
        Args:
            src_ip (str): IP origen
            dest_ip (str): IP destino
            dest_port (int): Puerto destino
        
        Returns:
            tuple: (is_expected: bool, reason: str)
        """
        # Búsqueda en conexiones explícitas
        connection = self.connections_col.find_one({
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'status': 'EXPECTED'
        })
        
        if connection:
            return True, f"Expected: {connection['service']}"
        
        # Búsqueda en asset inventory
        src_asset = self.assets_col.find_one({'ip': src_ip})
        if src_asset:
            for expected in src_asset.get('expected_connections', []):
                if (expected.get('dest_ip') == dest_ip and
                    expected.get('dest_port') == dest_port):
                    return True, f"Expected (from inventory): {expected.get('service', 'unknown')}"
        
        return False, "Not in expected connections"
    
    def get_expected_connections(self):
        """
        Retorna todas las conexiones esperadas registradas
        
        Returns:
            list: Lista de conexiones esperadas
        """
        return list(self.connections_col.find({'status': 'EXPECTED'}))

class WhitelistEngine:
    """
    Whitelist profesional: basado en asset inventory, no suposiciones
    
    Tipos de reglas soportadas:
    - IP: IP específica
    - CIDR: Rango de IPs
    - COMMUNICATION: Par IP:Puerto
    - SIGNATURE_PATTERN: Patrón de firma de alerta
    - SEVERITY_MAX: Ignorar alertas por debajo de severidad
    """
    
    def __init__(self, db):
        """
        Args:
            db: Instancia de MongoDB
        """
        self.db = db
        self.assets_mgr = AssetInventoryManager(db)
        self.whitelist_col = db['whitelist_rules']
    
    def add_whitelist_rule(self, rule):
        """
        Añade regla de whitelist explícita
        
        Args:
            rule (dict): Estructura de la regla con al menos:
                {
                    "type": "IP|CIDR|COMMUNICATION|SIGNATURE_PATTERN|SEVERITY_MAX",
                    "description": "descripción clara",
                    ...otros campos según tipo
                }
        """
        rule['created_at'] = datetime.utcnow()
        rule['creator'] = 'system'  # En producción: usuario
        
        # Solo establecer approved=False si no viene ya definido
        if 'approved' not in rule:
            rule['approved'] = False
        
        self.whitelist_col.insert_one(rule)
        logger.info(f"Whitelist rule added: {rule.get('description', 'N/A')}")
    
    def approve_rule(self, rule_id):
        """
        Aprueba una regla de whitelist (cambia approved=True)
        
        Args:
            rule_id (str): ID de MongoDB de la regla
        """
        from bson import ObjectId
        self.whitelist_col.update_one(
            {'_id': ObjectId(rule_id)},
            {'$set': {'approved': True, 'approved_at': datetime.utcnow()}}
        )
        logger.info(f"Whitelist rule approved: {rule_id}")
    
    def is_whitelisted(self, alert):
        """
        ¿Esta alerta está whitelisteada?
        
        Args:
            alert (dict): Estructura de alerta con:
                {
                    "src_ip": "172.22.0.52",
                    "dest_ip": "172.22.0.50",
                    "dest_port": 27017,
                    "alert": {
                        "signature": "algo",
                        "severity": 2
                    }
                }
        
        Returns:
            tuple: (is_whitelisted: bool, reason: str, rule_id: str or None)
        """
        src_ip = alert.get('src_ip')
        dest_ip = alert.get('dest_ip')
        dest_port = alert.get('dest_port')
        signature = alert.get('alert', {}).get('signature', '').lower()
        
        # 1. Revisar conexiones esperadas
        is_expected, reason = self.assets_mgr.is_expected_connection(
            src_ip, dest_ip, dest_port
        )
        if is_expected:
            return True, reason, None
        
        # 2. Revisar reglas de whitelist explícitas
        for rule in self.whitelist_col.find({'approved': True}):
            if self._matches_rule(alert, rule):
                return True, rule.get('description', 'Whitelist rule'), str(rule['_id'])
        
        # 3. Puertos efímeros (respuestas TCP normales)
        if dest_port and dest_port >= 49152:
            return True, "Ephemeral port (TCP response)", None
        
        return False, None, None
    
    def _matches_rule(self, alert, rule):
        """
        Verifica si alerta coincide con regla
        
        Args:
            alert (dict): Estructura de alerta
            rule (dict): Regla de whitelist
        
        Returns:
            bool: True si coincide
        """
        rule_type = rule.get('type')
        
        try:
            if rule_type == 'IP':
                return alert.get('src_ip') == rule.get('value')
            
            elif rule_type == 'CIDR':
                try:
                    network = ipaddress.ip_network(rule.get('value'), strict=False)
                    return ipaddress.ip_address(alert.get('src_ip')) in network
                except (ValueError, TypeError):
                    return False
            
            elif rule_type == 'COMMUNICATION':
                return (alert.get('src_ip') == rule.get('src_ip') and
                        alert.get('dest_ip') == rule.get('dest_ip') and
                        alert.get('dest_port') == rule.get('dest_port'))
            
            elif rule_type == 'SIGNATURE_PATTERN':
                pattern = rule.get('pattern', '')
                sig = alert.get('alert', {}).get('signature', '')
                return re.search(pattern, sig, re.IGNORECASE) is not None
            
            elif rule_type == 'SEVERITY_MAX':
                alert_severity = alert.get('alert', {}).get('severity', 0)
                return alert_severity > rule.get('max_severity', 0)
            
            return False
        
        except Exception as e:
            logger.warning(f"Error evaluating rule {rule.get('_id')}: {e}")
            return False
    
    def list_pending_rules(self):
        """
        Lista reglas pendientes de aprobación
        
        Returns:
            list: Reglas no aprobadas
        """
        return list(self.whitelist_col.find({'approved': False}))
    
    def list_approved_rules(self):
        """
        Lista reglas aprobadas
        
        Returns:
            list: Reglas aprobadas
        """
        return list(self.whitelist_col.find({'approved': True}))

def initialize_default_assets(db):
    """
    Registra los assets por defecto del entorno Docker
    
    Llama esto UNA VEZ al iniciar la aplicación (o desde manage.py)
    
    Args:
        db: Instancia de MongoDB
    """
    mgr = AssetInventoryManager(db)
    
    assets = [
        {
            'ip': '172.22.0.50',
            'hostname': 'mongodb',
            'role': 'Database',
            'owner': 'devops',
            'os': 'Linux',
            'services': [
                {'name': 'MongoDB', 'port': 27017, 'protocol': 'TCP'}
            ],
            'criticality': 'CRITICAL',
            'tags': ['database', 'persistence'],
        },
        {
            'ip': '172.22.0.51',
            'hostname': 'ingest',
            'role': 'Data Ingestion',
            'owner': 'backend-team',
            'os': 'Linux',
            'services': [
                {'name': 'Python Ingest', 'port': 5000, 'protocol': 'TCP'}
            ],
            'expected_connections': [
                {'dest_ip': '172.22.0.50', 'dest_port': 27017, 'service': 'mongodb'}
            ],
            'criticality': 'HIGH',
            'tags': ['processing', '5g-platform'],
        },
        {
            'ip': '172.22.0.52',
            'hostname': 'api',
            'role': 'API Backend',
            'owner': 'backend-team',
            'os': 'Linux',
            'services': [
                {'name': 'Flask API', 'port': 5000, 'protocol': 'TCP'}
            ],
            'allowed_inbound_ports': [5000],
            'expected_connections': [
                {'dest_ip': '172.22.0.50', 'dest_port': 27017, 'service': 'mongodb'},
                {'dest_ip': '172.22.0.53', 'dest_port': 5000, 'service': 'ia-service'}
            ],
            'criticality': 'CRITICAL',
            'tags': ['api', 'production', '5g-platform'],
        },
        {
            'ip': '172.22.0.53',
            'hostname': 'ia-sandbox',
            'role': 'AI/ML Analysis',
            'owner': 'ml-team',
            'os': 'Linux',
            'services': [
                {'name': 'Python ML', 'port': 5000, 'protocol': 'TCP'}
            ],
            'expected_connections': [
                {'dest_ip': '172.22.0.50', 'dest_port': 27017, 'service': 'mongodb'}
            ],
            'criticality': 'HIGH',
            'tags': ['ml', '5g-platform'],
        },
        {
            'ip': '172.22.0.54',
            'hostname': 'suricata',
            'role': 'IDS/IPS',
            'owner': 'security-team',
            'os': 'Linux',
            'services': [
                {'name': 'Suricata IDS', 'port': 0, 'protocol': 'N/A'}
            ],
            'criticality': 'CRITICAL',
            'tags': ['security', 'monitoring'],
        },
    ]
    
    for asset in assets:
        mgr.create_asset(asset)
    
    # Registrar conexiones esperadas
    expected_connections = [
        ('172.22.0.51', '172.22.0.50', 27017, 'mongodb'),
        ('172.22.0.52', '172.22.0.50', 27017, 'mongodb'),
        ('172.22.0.52', '172.22.0.53', 5000, 'ia-service'),
        ('172.22.0.53', '172.22.0.50', 27017, 'mongodb'),
    ]
    
    for src, dest, port, service in expected_connections:
        mgr.register_expected_connection(src, dest, port, service)
    
    logger.info("✅ Default assets initialized")

def initialize_open5gs_assets(db):
    """
    Registra los assets del Core 5G (Open5GS) y RAN (UERANSIM)
    basados en el docker-compose del entorno de laboratorio.

    Llamar UNA VEZ.
    """
    mgr = AssetInventoryManager(db)

    assets = [
        # =========================
        # 5G CORE - CONTROL PLANE
        # =========================
        {
            "ip": "172.22.0.10",
            "hostname": "nrf",
            "role": "5G NRF",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "CRITICAL",
            "tags": ["5g", "core", "control-plane"]
        },
        {
            "ip": "172.22.0.11",
            "hostname": "scp",
            "role": "5G SCP",
            "services": [
                {"name": "SBI Proxy", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "CRITICAL",
            "tags": ["5g", "core", "service-mesh"]
        },
        {
            "ip": "172.22.0.12",
            "hostname": "amf",
            "role": "5G AMF",
            "services": [
                {"name": "NGAP (N2)", "port": 38412, "protocol": "SCTP"},
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "expected_connections": [
                {"dest_ip": "172.22.0.30", "dest_port": 38412, "service": "gnb-ngap"},
                {"dest_ip": "172.22.0.11", "dest_port": 7777, "service": "scp"}
            ],
            "criticality": "CRITICAL",
            "tags": ["5g", "amf", "core"]
        },
        {
            "ip": "172.22.0.13",
            "hostname": "smf",
            "role": "5G SMF",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"},
                {"name": "PFCP", "port": 8805, "protocol": "UDP"}
            ],
            "expected_connections": [
                {"dest_ip": "172.22.0.20", "dest_port": 8805, "service": "pfcp-upf"}
            ],
            "criticality": "CRITICAL",
            "tags": ["5g", "smf", "core"]
        },
        {
            "ip": "172.22.0.14",
            "hostname": "ausf",
            "role": "5G AUSF",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "HIGH",
            "tags": ["5g", "core", "auth"]
        },
        {
            "ip": "172.22.0.15",
            "hostname": "udm",
            "role": "5G UDM",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "HIGH",
            "tags": ["5g", "core", "subscriber-db"]
        },
        {
            "ip": "172.22.0.16",
            "hostname": "udr",
            "role": "5G UDR",
            "services": [
                {"name": "DB Access", "port": 27017, "protocol": "TCP"}
            ],
            "criticality": "HIGH",
            "tags": ["5g", "core", "database"]
        },
        {
            "ip": "172.22.0.17",
            "hostname": "pcf",
            "role": "5G PCF",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "HIGH",
            "tags": ["5g", "core", "policy"]
        },
        {
            "ip": "172.22.0.18",
            "hostname": "nssf",
            "role": "5G NSSF",
            "services": [
                {"name": "SBI", "port": 7777, "protocol": "HTTP/2"}
            ],
            "criticality": "MEDIUM",
            "tags": ["5g", "core", "slicing"]
        },

        # =========================
        # 5G CORE - USER PLANE
        # =========================
        {
            "ip": "172.22.0.20",
            "hostname": "upf",
            "role": "5G UPF",
            "services": [
                {"name": "GTP-U (N3)", "port": 2152, "protocol": "UDP"},
                {"name": "PFCP", "port": 8805, "protocol": "UDP"}
            ],
            "criticality": "CRITICAL",
            "tags": ["5g", "upf", "user-plane"]
        },

        # =========================
        # RAN
        # =========================
        {
            "ip": "172.22.0.30",
            "hostname": "gnb",
            "role": "5G gNB (UERANSIM)",
            "services": [
                {"name": "NGAP", "port": 38412, "protocol": "SCTP"},
                {"name": "GTP-U", "port": 2152, "protocol": "UDP"}
            ],
            "criticality": "HIGH",
            "tags": ["5g", "ran"]
        },

        # =========================
        # UE
        # =========================
        {
            "ip": "172.22.0.31",
            "hostname": "ue1",
            "role": "5G UE (UERANSIM)",
            "services": [],
            "criticality": "LOW",
            "tags": ["5g", "ue", "simulation"]
        }
    ]

    for asset in assets:
        mgr.create_asset(asset)

    logger.info("✅ Open5GS / UERANSIM assets initialized")

def initialize_default_whitelist(db):
    """
    Registra whitelist rules por defecto
    
    Llama esto UNA VEZ al iniciar la aplicación (o desde manage.py)
    
    Args:
        db: Instancia de MongoDB
    """
    engine = WhitelistEngine(db)
    
    rules = [
        {
            'type': 'COMMUNICATION',
            'src_ip': '172.22.0.52',
            'dest_ip': '172.22.0.50',
            'dest_port': 27017,
            'description': 'API→MongoDB (expected internal connection)',
            'approved': True
        },
        {
            'type': 'COMMUNICATION',
            'src_ip': '172.22.0.51',
            'dest_ip': '172.22.0.50',
            'dest_port': 27017,
            'description': 'Ingest→MongoDB (expected internal connection)',
            'approved': True
        },
        {
            'type': 'SEVERITY_MAX',
            'max_severity': 3,
            'description': 'Ignore low-severity alerts',
            'approved': True
        },
    ]
    
    for rule in rules:
        engine.add_whitelist_rule(rule)
    
    logger.info("✅ Default whitelist initialized")