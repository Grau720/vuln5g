from ..versiones.rangos import _consolidar_rangos
from ..versiones.semver_utils import _version_sort_key
from ..cpe.parse_utils import _collect_nodes_from_configs, _unescape_cpe

def extraer_versiones_afectadas(item: dict):
    """
    Versión mejorada con consolidación de rangos y ordenamiento semántico.
    Devuelve una lista de strings con versiones o rangos.
    """
    versiones = set()

    configs = None
    if isinstance(item.get("configurations"), (dict, list)):
        configs = item["configurations"]
    elif isinstance(item.get("cve"), dict) and isinstance(item["cve"].get("configurations"), (dict, list)):
        configs = item["cve"]["configurations"]

    if configs is None:
        return []

    nodes = _collect_nodes_from_configs(configs)

    def walk(node: dict):
        for m in node.get("cpeMatch", []) or []:
            if not m.get("vulnerable", False):
                continue

            cpe = m.get("criteria") or m.get("cpe23Uri") or ""
            parts = cpe.split(":")
            version = _unescape_cpe(parts[5]) if len(parts) > 5 else None

            s_incl = m.get("versionStartIncluding")
            s_excl = m.get("versionStartExcluding")
            e_incl = m.get("versionEndIncluding")
            e_excl = m.get("versionEndExcluding")

            rango_parts = []
            if s_incl:
                rango_parts.append(f">= {s_incl}")
            if s_excl:
                rango_parts.append(f"> {s_excl}")
            if e_incl:
                rango_parts.append(f"<= {e_incl}")
            if e_excl:
                rango_parts.append(f"< {e_excl}")

            # Versión exacta
            if version and version not in ("*", "-"):
                versiones.add(version)
                continue

            # Rango
            if rango_parts:
                versiones.add(" y ".join(rango_parts))
                continue

        for child in node.get("nodes", []) or []:
            if isinstance(child, dict):
                walk(child)

    for n in nodes:
        if isinstance(n, dict):
            walk(n)

    # Consolidar rangos redundantes
    versiones_list = list(versiones)
    versiones_consolidadas = _consolidar_rangos(versiones_list)
    
    # Ordenar semánticamente
    return sorted(versiones_consolidadas, key=_version_sort_key)
