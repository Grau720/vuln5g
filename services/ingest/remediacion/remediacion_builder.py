from .workarounds import _generic_workarounds
from ..kev.kev_loader import load_kev_dataset
from .version_inference import _infer_min_safe_from_ranges
from ..cpe.parse_utils import _parse_refs_for_vendor_hint

def _build_remediacion(cve_id: str, cve: dict, descripcion: str, versiones: list[str],
                       etiquetas: list[str], protos: list[str], extra_mitre: dict) -> str:

    partes = []

    mitre_txt = (extra_mitre or {}).get("remediacion_mitre")
    if mitre_txt:
        partes.append(mitre_txt.strip())

    kev = load_kev_dataset().get((cve_id or "").upper())
    if kev and kev.get("requiredAction"):
        partes.append(f"KEV/CISA: {kev['requiredAction'].strip()} (fecha límite: {kev.get('dueDate','N/D')}).")

    min_safe = _infer_min_safe_from_ranges(versiones or [])
    if min_safe:
        partes.append(f"Actualizar a una versión **≥ {min_safe}** provista por el fabricante.")

    if _parse_refs_for_vendor_hint(cve):
        partes.append("Aplicar parches oficiales del fabricante según las referencias del CVE.")

    workarounds = _generic_workarounds(descripcion, etiquetas or [], protos or [])
    if workarounds:
        partes.append("Medidas transitorias:")
        for w in workarounds:
            partes.append(f" - {w}")

    if not partes:
        partes.append("Consultar el boletín oficial y actualizar a la versión corregida disponible.")

    return "\n".join(partes).strip()
