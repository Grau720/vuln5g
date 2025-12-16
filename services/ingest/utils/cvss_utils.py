
def obtener_cvss(metrics: dict) -> dict:
    if not isinstance(metrics, dict):
        return {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if isinstance(arr, list) and arr:
            data = arr[0].get("cvssData") or {}
            if "baseScore" in data:
                return data
            if "baseScore" in arr[0]:
                return {"baseScore": arr[0]["baseScore"], "vectorString": arr[0].get("vectorString", "")}
            return data
    return {}

def riesgo_from_score(score: float) -> str:
    if score is None:
        return "desconocido"
    if score >= 9.0:
        return "crítico"
    if score >= 7.0:
        return "alto"
    if score >= 4.0:
        return "medio"
    return "bajo"

def dificultad_from_vector(vector: str) -> str:
    if not vector or not isinstance(vector, str):
        return "Desconocida"
    v = vector.upper()
    score = 0
    if "AC:H" in v:
        score += 2
    if "PR:H" in v:
        score += 2
    elif "PR:L" in v:
        score += 1
    if "UI:R" in v:
        score += 1
    if "AV:N" in v:
        score -= 1
    if score <= 0:
        return "Baja"
    if score <= 2:
        return "Media"
    return "Alta"

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
