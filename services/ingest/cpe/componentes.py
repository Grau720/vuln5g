from .parse_utils import _pretty_component, _is_valid_component, _collect_nodes_from_configs, _parse_vendor_product_from_cpe
from ..kev.kev_loader import load_kev_dataset
import re

def extraer_componente_afectado(item: dict) -> tuple[str | None, str]:
    """
    Versión mejorada con múltiples estrategias de fallback y validación.
    Retorna (componente, fuente).
    """
    
    # Estrategia 1: CPE (método original)
    configs = None
    if isinstance(item.get("configurations"), (dict, list)):
        configs = item["configurations"]
    elif isinstance(item.get("cve"), dict) and isinstance(item["cve"].get("configurations"), (dict, list)):
        configs = item["cve"]["configurations"]

    if configs is not None:
        nodes = _collect_nodes_from_configs(configs)
        
        def walk(node: dict) -> str | None:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                cpe = m.get("criteria") or m.get("cpe23Uri") or ""
                vendor, product = _parse_vendor_product_from_cpe(cpe)
                comp = _pretty_component(vendor, product)
                if comp and _is_valid_component(comp):
                    return comp

            for ch in node.get("nodes", []) or []:
                if isinstance(ch, dict):
                    r = walk(ch)
                    if r:
                        return r
            return None

        for n in nodes:
            if isinstance(n, dict):
                r = walk(n)
                if r:
                    return r, "CPE"
    
    # Estrategia 2: KEV dataset
    cve_id = item.get("cve", {}).get("id", "").upper()
    if cve_id:
        kev = load_kev_dataset().get(cve_id)
        if kev:
            vendor = str(kev.get("vendorProject", "")).strip()
            product = str(kev.get("product", "")).strip()
            if vendor or product:
                comp = _pretty_component(vendor, product)
                if comp and _is_valid_component(comp):
                    return comp, "KEV"
    
    # Estrategia 3: Extraer de referencias (URLs oficiales)
    cve_dict = item.get("cve", {})
    refs = cve_dict.get("references", [])
    
    # Prioridad 1: GitHub repos
    for ref in refs:
        url = ref.get("url", "").lower()
        if "github.com" in url:
            match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
            if match:
                vendor, product = match.groups()
                # Limpiar sufijos como /issues, /security, etc.
                product = re.sub(r'\.(git|issues|security|advisories).*$', '', product)
                comp = _pretty_component(vendor, product)
                if comp and _is_valid_component(comp):
                    return comp, "REFERENCES"
    
    # Prioridad 2: Dominios de vendor conocidos
    vendor_domains = {
        "oracle.com": "Oracle",
        "microsoft.com": "Microsoft",
        "cisco.com": "Cisco",
        "juniper.net": "Juniper",
        "huawei.com": "Huawei",
        "redhat.com": "Red Hat",
        "apple.com": "Apple",
        "google.com": "Google",
        "mozilla.org": "Mozilla",
        "apache.org": "Apache",
        "nginx.org": "Nginx",
        "openssl.org": "OpenSSL",
        "debian.org": "Debian",
        "ubuntu.com": "Ubuntu",
        "suse.com": "SUSE",
        "vmware.com": "VMware",
        "ibm.com": "IBM",
        "sap.com": "SAP",
        "fortinet.com": "Fortinet",
        "paloaltonetworks.com": "Palo Alto Networks",
    }
    
    for ref in refs:
        url = ref.get("url", "").lower()
        for domain, vendor in vendor_domains.items():
            if domain in url:
                if _is_valid_component(vendor):
                    return vendor, "REFERENCES"
    
    # Estrategia 4: Parsing de descripción con regex (MEJORADO)
    descriptions = cve_dict.get("descriptions", [])
    comp_from_desc = _extraer_desde_descripcion(descriptions)
    if comp_from_desc:
        return comp_from_desc, "DESCRIPTION"
    
    return None, "NONE"

def _extraer_desde_referencias(cve: dict) -> str | None:
    """
    Busca en URLs de referencias patrones como:
    - github.com/vendor/product
    - vendor.com/security/CVE-xxxx
    - vendor.com/products/product-name
    """
    refs = cve.get("references", [])
    
    # Prioridad 1: GitHub repos
    for ref in refs:
        url = ref.get("url", "").lower()
        if "github.com" in url:
            # github.com/open5gs/open5gs/issues/123
            match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
            if match:
                vendor, product = match.groups()
                return _pretty_component(vendor, product)
    
    # Prioridad 2: Dominios de vendor conocidos
    vendor_domains = {
        "oracle.com": "Oracle",
        "microsoft.com": "Microsoft",
        "cisco.com": "Cisco",
        "juniper.net": "Juniper",
        "huawei.com": "Huawei",
        # Expandir esta lista
    }
    
    for ref in refs:
        url = ref.get("url", "").lower()
        for domain, vendor in vendor_domains.items():
            if domain in url:
                # Intentar extraer producto del path
                # oracle.com/security-alerts/cpujan2023.html → Oracle Database
                # Heurística simple por ahora
                return vendor
    
    return None

def _extraer_desde_descripcion(descriptions: list) -> str | None:
    """
    Usa regex patterns para extraer vendor/product de la descripción.
    MEJORADO: Filtra componentes inválidos
    """
    if not descriptions:
        return None
    
    texto = descriptions[0].get("value", "")
    if not texto:
        return None
    
    # Patrón 1: "Vendor Product versión X.Y.Z"
    patterns = [
        # "Cisco IOS 15.6" → Cisco IOS
        r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+([A-Z][\w\-\.]+)',
        
        # "Apache HTTP Server 2.4.x" → Apache HTTP Server
        r'(Apache|Nginx|MySQL|PostgreSQL)\s+([\w\s]+?)(?:\s+\d|\s+version|$)',
        
        # "Open5GS 2.1.3" → Open5GS
        r'(Open5GS|OpenSSL|Kubernetes|Docker)\s+',
        
        # "Oracle WebLogic Server" → Oracle WebLogic Server
        r'(Oracle|Microsoft|IBM|SAP)\s+([\w\s]+?)(?:\s+\d|\s+version|$)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, texto)
        if match:
            if match.lastindex == 2:
                vendor, product = match.groups()
                comp = _pretty_component(vendor, product)
            else:
                comp = match.group(1)
            
            # NUEVO: Filtrar componentes inválidos
            if comp and _is_valid_component(comp):
                return comp
    
    return None
