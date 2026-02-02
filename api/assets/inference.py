"""
Módulo de inferencia para asset discovery.

Contiene lógica para identificar componentes 5G, servicios, y roles
basándose en puertos, nombres, y patrones conocidos.
"""

# ============================================================================
# PORT MAPPINGS
# ============================================================================

KNOWN_PORTS = {
    # 5G Core
    7777: "SBI (HTTP/2)",
    38412: "NGAP",
    2152: "GTP-U",
    8805: "PFCP",
    3868: "Diameter",
    
    # Management
    22: "SSH",
    443: "HTTPS",
    80: "HTTP",
    161: "SNMP",
    830: "NETCONF",
    
    # Databases
    27017: "MongoDB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    
    # Messaging
    5672: "AMQP",
    9092: "Kafka",
    
    # Monitoring
    9090: "Prometheus",
    3000: "Grafana",
    9200: "Elasticsearch"
}

# ============================================================================
# ROLE MAPPINGS
# ============================================================================

# Componentes 5G por puertos característicos
PORT_PATTERNS_5G = {
    frozenset([38412, 7777]): "5G AMF",
    frozenset([8805, 7777]): "5G SMF",
    frozenset([2152, 8805]): "5G UPF",
}

# Mapeo de nombres a roles (para Docker)
NAME_TO_ROLE = {
    "amf": "5G AMF",
    "smf": "5G SMF",
    "upf": "5G UPF",
    "nrf": "5G NRF",
    "ausf": "5G AUSF",
    "udm": "5G UDM",
    "pcf": "5G PCF",
    "nssf": "5G NSSF",
    "scp": "5G SCP",
    "udr": "5G UDR",
    "mongo": "Database (MongoDB)",
    "redis": "Database (Redis)",
    "postgres": "Database (PostgreSQL)",
    "mysql": "Database (MySQL)",
    "api": "API Backend",
    "gnb": "gNodeB",
    "enb": "eNodeB",
}

# Servicios típicos por componente (para Docker)
NAME_TO_SERVICES = {
    "amf": [{"name": "NGAP", "port": 38412, "protocol": "SCTP"}],
    "smf": [{"name": "PFCP", "port": 8805, "protocol": "UDP"}],
    "upf": [{"name": "GTP-U", "port": 2152, "protocol": "UDP"}],
    "nrf": [{"name": "SBI", "port": 7777, "protocol": "TCP"}],
    "mongo": [{"name": "MongoDB", "port": 27017, "protocol": "TCP"}],
    "redis": [{"name": "Redis", "port": 6379, "protocol": "TCP"}],
    "api": [{"name": "HTTP", "port": 5000, "protocol": "TCP"}],
}

# Categorías por rol
ROLE_TO_CATEGORY = {
    "core": ["amf", "smf", "udm", "ausf", "pcf", "nrf", "nssf", "scp", "udr"],
    "transport": ["upf", "gtp"],
    "ran": ["gnb", "enb", "ran"],
    "support": ["mongo", "database", "redis", "postgres", "mysql", "monitoring", "grafana", "prometheus"],
}

# ============================================================================
# INFERENCE FUNCTIONS
# ============================================================================

def infer_service_name(port: int) -> str:
    """
    Retorna el nombre del servicio basado en puerto conocido.
    
    Args:
        port: Número de puerto
    
    Returns:
        Nombre del servicio o "Port {port}" si desconocido
    """
    return KNOWN_PORTS.get(port, f"Port {port}")


def infer_role_from_ports(ports: list) -> str:
    """
    Identifica componente 5G o servicio basándose en puertos abiertos.
    
    Args:
        ports: Lista de puertos detectados abiertos
    
    Returns:
        Rol identificado del componente
    """
    if not ports:
        return "Unknown Service"
    
    ports_set = set(ports)
    
    # Verificar patrones de puertos conocidos
    for pattern, role in PORT_PATTERNS_5G.items():
        if pattern.issubset(ports_set):
            return role
    
    # Identificación por puerto individual
    if 7777 in ports_set:
        return "5G NF (SBI enabled)"
    elif 3868 in ports_set:
        return "Diameter Node (HSS/DRA)"
    elif 2152 in ports_set:
        return "GTP Node"
    elif 27017 in ports_set:
        return "Database (MongoDB)"
    elif 6379 in ports_set:
        return "Database (Redis)"
    elif 9090 in ports_set or 3000 in ports_set:
        return "Monitoring System"
    elif 22 in ports_set and 161 in ports_set:
        return "Network Element (Managed)"
    else:
        return "Network Service"


def infer_role_from_name(name: str) -> str:
    """
    Identifica rol basándose en hostname/nombre del contenedor.
    
    Args:
        name: Nombre del host o contenedor
    
    Returns:
        Rol identificado
    """
    name_lower = name.lower()
    
    for key, role in NAME_TO_ROLE.items():
        if key in name_lower:
            return role
    
    return "Unknown Service"


def infer_services_from_name(name: str) -> list:
    """
    Retorna lista de servicios esperados basándose en nombre.
    
    Args:
        name: Nombre del host o contenedor
    
    Returns:
        Lista de servicios típicos del componente
    """
    name_lower = name.lower()
    
    for key, services in NAME_TO_SERVICES.items():
        if key in name_lower:
            return services
    
    return []


def infer_category_from_role(role: str) -> str:
    """
    Categoriza asset según su rol identificado.
    
    Args:
        role: Rol del componente
    
    Returns:
        Categoría (core, transport, ran, support, unknown)
    """
    role_lower = role.lower()
    
    for category, keywords in ROLE_TO_CATEGORY.items():
        if any(keyword in role_lower for keyword in keywords):
            return category
    
    return "unknown"


def calculate_confidence(name: str, ports: list = None) -> str:
    """
    Calcula nivel de confianza en la identificación.
    
    Args:
        name: Nombre del asset
        ports: Puertos detectados (opcional)
    
    Returns:
        Nivel de confianza: HIGH, MEDIUM, LOW
    """
    name_lower = name.lower()
    known_patterns = list(NAME_TO_ROLE.keys())
    
    # Alta confianza si coincide con patrón conocido
    if any(pattern in name_lower for pattern in known_patterns):
        return "HIGH"
    
    # Media confianza si tiene puertos característicos
    if ports and any(port in KNOWN_PORTS for port in ports):
        return "MEDIUM"
    
    # Baja confianza en otros casos
    return "LOW"


# ============================================================================
# CONVENIENCE WRAPPERS (para compatibilidad)
# ============================================================================

def infer_category(name: str) -> str:
    """
    Wrapper de compatibilidad: infiere categoría desde nombre.
    """
    role = infer_role_from_name(name)
    return infer_category_from_role(role)


def infer_role(name: str) -> str:
    """
    Wrapper de compatibilidad: alias de infer_role_from_name.
    """
    return infer_role_from_name(name)


def infer_services(name: str) -> list:
    """
    Wrapper de compatibilidad: alias de infer_services_from_name.
    """
    return infer_services_from_name(name)