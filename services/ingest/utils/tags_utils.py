import re

_PROTO_KWS = [
    "http/2", "http2", "http", "https", "ngap", "diameter", "sctp", "gtp", "gtp-u", "gtp-c",
    "pfcp", "tls", "ssh", "snmp", "udp", "tcp", "icmp", "quic", "coap", "mqtt"
]
_IFACE_KWS = [
    "n1", "n2", "n3", "n4", "n6", "n9", "n11", "n22", "n26", "n32", "s1", "x2", "ng", "e1", "f1"
]

def extraer_etiquetas(texto: str) -> list:
    """
    Etiquetas mejoradas - más restrictivas para evitar falsos positivos
    VERSIÓN MEJORADA con mejor detección de 5G y patrones adicionales
    """
    if not texto:
        return []
    
    t = _norm(texto)
    tags = set()

    # === Categorías de ataque - términos ESPECÍFICOS ===
    
    # DoS - requiere mención explícita
    if "denial of service" in t or "denial-of-service" in t:
        tags.add("DoS")
    elif "resource exhaustion" in t or "infinite loop" in t:
        tags.add("DoS")
    
    # RCE - términos claros
    if any(k in t for k in [
        "remote code execution", "execute arbitrary code", 
        "arbitrary code execution", "rce"
    ]):
        tags.add("RCE")
    
    # Overflow - específico
    if any(k in t for k in [
        "buffer overflow", "heap overflow", "stack overflow",
        "out-of-bounds", "memory corruption"
    ]):
        tags.add("Overflow")
    
    # Info disclosure - términos explícitos
    if any(k in t for k in [
        "information disclosure", "info leak", "data leak",
        "leak sensitive", "expose sensitive"
    ]):
        tags.add("Info-Disclosure")
    
    # Memory leak específico
    if any(k in t for k in [
        "kernel memory", "uninitialized memory", "memory leak"
    ]):
        tags.add("Info-Disclosure")
    
    # Privilege escalation
    if any(k in t for k in [
        "privilege escalation", "elevate privileges", "escalate privileges"
    ]):
        tags.add("Priv-Esc")
    
    # XSS
    if "cross-site scripting" in t or "xss" in t.split():
        tags.add("XSS")
    
    # SQLi
    if "sql injection" in t or "sqli" in t:
        tags.add("SQLi")
    
    # CSRF
    if "csrf" in t or "cross-site request forgery" in t:
        tags.add("CSRF")
    
    # Path Traversal
    if any(k in t for k in ["path traversal", "directory traversal", "../"]):
        tags.add("Path-Traversal")
    
    # Code/Command Injection
    if "code injection" in t:
        tags.add("Code-Injection")
    
    if any(k in t for k in ["command injection", "shell injection"]):
        tags.add("Command-Injection")
    
    # Auth Bypass
    if any(k in t for k in ["authentication bypass", "auth bypass"]):
        tags.add("Auth-Bypass")
    
    # Misconfiguration
    if any(k in t for k in ["insecure default", "misconfiguration", "default credential"]):
        tags.add("Misconfiguration")
    
    # Race Condition
    if "race condition" in t:
        tags.add("Race-Condition")
    
    # Integer issues
    if any(k in t for k in ["integer overflow", "integer underflow"]):
        tags.add("Integer-Overflow")
    
    # === Protocolos 5G/Telecom - MEJORADOS ===
    
    # 5G - detección mejorada con regex
    if re.search(r'\b5g\b', t, re.IGNORECASE):
        tags.add("5G")
    elif any(k in t for k in ['fifth generation', '5g network', '5g core', '5g ran']):
        tags.add("5G")
    
    if "ngap" in t:
        tags.add("NGAP")
    
    if "sctp" in t:
        tags.add("SCTP")
    
    # GTP - mejorado
    if re.search(r'\bgtp\b', t):
        tags.add("GTP")
    elif any(k in t for k in ['gtp-u', 'gtp-c', 'gprs tunneling']):
        tags.add("GTP")
    
    if "pfcp" in t:
        tags.add("PFCP")
    
    if "diameter" in t:
        tags.add("Diameter")
    
    if "http/2" in t or "http2" in t:
        tags.add("HTTP/2")

    return sorted(tags)

def clasificar_infra(text: str):
    """
    VERSIÓN MEJORADA: Clasificación de infraestructura 5G más agresiva
    """
    if not text:
        return []
    t = text.lower()
    tags = set()
    
    # RAN - MEJORADO
    if any(w in t for w in ["gnb", "enb", "ran", "cpri", "fronthaul", "rru", "radio access"]):
        tags.add("RAN")
    
    # Core - MEJORADO (AÑADIR AQUÍ)
    core_keywords = [
        "core", "amf", "smf", "upf", "ausf", "udm", "pcf", "nef", "nssf", "scp",
        # NUEVOS KEYWORDS MÁS GENERALES:
        "5g core", "network function", "service-based", "sba",
        "control plane", "user plane", "nrf", "udr", "bsf"
    ]
    if any(w in t for w in core_keywords):
        tags.add("Core")
    
    # Detección específica de "NF" (Network Function) solo si hay contexto 5G
    if "nf" in t and any(k in t for k in ["5g", "core", "sba", "service-based"]):
        tags.add("Core")
    
    # MEC - MEJORADO
    if any(w in t for w in ["mec", "multi-access edge", "mobile edge computing"]):
        tags.add("MEC")
    
    # Backhaul - MEJORADO
    if any(w in t for w in ["backhaul", "transport", "midhaul", "xhaul"]):
        tags.add("Backhaul")
    
    return sorted(tags)

def extract_protocols(text: str):
    if not text:
        return []
    t = text.lower()
    found = set()
    for kw in _PROTO_KWS:
        if kw in t:
            norm = "http/2" if kw in ("http2", "http/2") else kw
            found.add(norm.upper())
    return sorted(found)

def extract_interfaces(text: str):
    if not text:
        return []
    t = text.lower()
    found = set()
    for kw in _IFACE_KWS:
        if re.search(rf"\b{re.escape(kw)}\b", t):
            found.add(kw.upper())
    return sorted(found)

def _norm(t: str) -> str:
    return (t or "").lower().strip()
