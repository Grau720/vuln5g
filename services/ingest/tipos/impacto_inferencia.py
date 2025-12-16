def inferir_tipo_por_impacto(cvss_data: dict) -> str | None:
    """
    Usa los impactos de confidencialidad/integridad/disponibilidad para inferir tipo cuando
    la descripción no da suficiente contexto.
    """
    if not isinstance(cvss_data, dict):
        return None

    c = (cvss_data.get("confidentialityImpact") or "").upper()
    i = (cvss_data.get("integrityImpact") or "").upper()
    a = (cvss_data.get("availabilityImpact") or "").upper()

    if c in ("HIGH", "PARTIAL") and i in ("NONE", "") and a in ("NONE", ""):
        return "Divulgación de información"

    if a in ("HIGH", "PARTIAL") and c in ("NONE", "") and i in ("NONE", ""):
        return "Denegación de servicio"

    if i in ("HIGH", "PARTIAL") and c in ("NONE", ""):
        return "Desbordamiento de memoria"

    return None
