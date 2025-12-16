import re

def _unescape_cpe(s: str) -> str:
    if not isinstance(s, str):
        return s
    return (
        s.replace(r"\(", "(")
         .replace(r"\)", ")")
         .replace(r"\/", "/")
         .replace(r"\+", "+")
         .replace(r"\!", "!")
         .replace(r"\_", "_")
    )

def _collect_nodes_from_configs(configs):
    """Devuelve la lista de nodos a partir de 'configurations' sea dict o list."""
    nodes = []
    if isinstance(configs, dict):
        nodes = configs.get("nodes", []) or []
    elif isinstance(configs, list):
        for block in configs:
            if isinstance(block, dict):
                if isinstance(block.get("nodes"), list):
                    nodes.extend(block["nodes"])
                else:
                    nodes.append(block)
    return nodes

def _parse_vendor_product_from_cpe(cpe_uri: str) -> tuple[str | None, str | None]:
    """
    cpe:2.3:part:vendor:product:version:...
    Devuelve (vendor, product) desescapados o (None, None) si no aplica.
    """
    if not isinstance(cpe_uri, str) or not cpe_uri.startswith("cpe:2.3:"):
        return None, None
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return None, None
    vendor = _unescape_cpe(parts[3]).strip() or None
    product = _unescape_cpe(parts[4]).strip() or None
    return vendor, product

def _pretty_component(vendor: str | None, product: str | None) -> str | None:
    if not vendor and not product:
        return None
    v = (vendor or "").strip()
    p = (product or "").strip()
    if v and p and v.lower() == p.lower():
        base = p
    else:
        base = " ".join(x for x in (v, p) if x)

    M = {
        "apache http_server": "Apache HTTP Server",
        "apache tomcat": "Apache Tomcat",
        "apple swiftnio_http/2": "Apple SwiftNIO HTTP/2",
        "ietf http": "HTTP/2",
        "envoyproxy envoy": "Envoy",
    }
    return M.get(base.lower(), base)

def _parse_refs_for_vendor_hint(cve) -> bool:
    refs = cve.get("references") or []
    for r in refs:
        url = (r.get("url") or "").lower()
        if any(k in url for k in ("advisories", "advisory", "security", "changelog", "releases", "patch", "kb", "support")):
            return True
    return False

def _is_valid_component(comp: str) -> bool:
    """
    NUEVA FUNCIÓN: Valida que un componente extraído sea válido.
    Filtra falsos positivos como "In the Linux", "A component", etc.
    """
    if not comp or not isinstance(comp, str):
        return False
    
    comp_lower = comp.lower().strip()
    
    # Patrones inválidos
    invalid_patterns = [
        r'^in\s+the\b',       # "In the Linux"
        r'^a\s+\b',           # "A component"
        r'^the\s+\b',         # "The software"
        r'^an\s+\b',          # "An application"
        r'^\d+$',             # Solo números
        r'^[\W_]+$',          # Solo caracteres especiales
        r'^(component|software|application|product|system)$',  # Términos genéricos
    ]
    
    for pattern in invalid_patterns:
        if re.match(pattern, comp_lower):
            return False
    
    # Debe tener al menos 2 caracteres alfanuméricos
    if len(re.findall(r'[a-zA-Z0-9]', comp)) < 2:
        return False
    
    # No debe empezar con artículos o preposiciones comunes
    if comp_lower.split()[0] in ['in', 'the', 'a', 'an', 'of', 'for', 'with', 'by']:
        return False
    
    return True

def _is_cwe_description(comp: str) -> bool:
    """Detect if component is actually a CWE description"""
    cwe_keywords = ['improper', 'incorrect', 'insufficient', 'missing', 
                    'unrestricted', 'uncontrolled', 'inadequate']
    comp_lower = comp.lower()
    return any(comp_lower.startswith(kw) for kw in cwe_keywords)
