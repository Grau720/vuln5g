def _map_cia(val: str) -> str:
    if not val:
        return "Desconocida"
    v = val.upper()
    if v == "NONE":
        return "Ninguna"
    if v == "LOW":
        return "Baja"
    if v == "HIGH":
        return "Alta"
    return "Desconocida"

def extraer_impacto(cvss_data: dict) -> dict:
    """
    Interpreta confidencialidad/integridad/disponibilidad desde CVSS (v3 o v2).
    """
    if not isinstance(cvss_data, dict):
        return {
            "confidencialidad": "Desconocida",
            "integridad": "Desconocida",
            "disponibilidad": "Desconocida",
        }

    c = cvss_data.get("confidentialityImpact") or cvss_data.get("C")
    i = cvss_data.get("integrityImpact") or cvss_data.get("I")
    a = cvss_data.get("availabilityImpact") or cvss_data.get("A")

    return {
        "confidencialidad": _map_cia(c),
        "integridad": _map_cia(i),
        "disponibilidad": _map_cia(a),
    }
