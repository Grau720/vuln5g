from ..ingest.cpe.parse_utils import _collect_nodes_from_configs, _parse_vendor_product_from_cpe, _is_cwe_description, _pretty_component

def _extraer_desde_cpe(item: dict) -> tuple[str | None, str]:
    """
    Extrae componente desde CPE (configuraciones).
    Retorna (componente, fuente).
    """
    configs = None
    if isinstance(item.get("configurations"), (dict, list)):
        configs = item["configurations"]
    elif isinstance(item.get("cve"), dict) and isinstance(item["cve"].get("configurations"), (dict, list)):
        configs = item["cve"]["configurations"]

    if configs is None:
        return None, "NONE"

    nodes = _collect_nodes_from_configs(configs)
    
    def walk(node: dict) -> str | None:
        for m in node.get("cpeMatch", []) or []:
            if not m.get("vulnerable", False):
                continue
            cpe = m.get("criteria") or m.get("cpe23Uri") or ""
            vendor, product = _parse_vendor_product_from_cpe(cpe)
            comp = _pretty_component(vendor, product)
            if comp:
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
    
    if comp and not _is_cwe_description(comp):
        return comp, "CPE"
    
    return None, "NONE"
