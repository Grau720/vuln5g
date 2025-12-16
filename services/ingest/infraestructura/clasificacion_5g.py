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
