def obtener_cvss(metrics: dict) -> dict:
    """
    Extrae CVSS con prioridad:
    1. CVSS v3.1 Primary (oficial NVD)
    2. CVSS v3.0 Primary
    3. CVSS v4.0 Primary (nuevo estándar)
    4. CVSS v3.1 Secondary (del vendor)
    5. CVSS v2.0 (legacy)
    
    MEJORAS:
    - Soporte para CVSS v4.0
    - Prioriza type="Primary" sobre "Secondary"
    - Convierte v4.0 a formato compatible con v3.1
    """
    if not isinstance(metrics, dict):
        return {}
    
    # ========================================================
    # FASE 1: Buscar CVSS Primary (más confiable)
    # ========================================================
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        arr = metrics.get(version_key) or []
        if not isinstance(arr, list):
            continue
        
        # Buscar Primary primero
        for entry in arr:
            if entry.get("type") == "Primary":
                cvss_data = entry.get("cvssData") or {}
                if "baseScore" in cvss_data:
                    return _normalize_cvss(cvss_data, version_key)
    
    # ========================================================
    # FASE 2: Fallback a Secondary (del vendor)
    # ========================================================
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        arr = metrics.get(version_key) or []
        if not isinstance(arr, list):
            continue
        
        for entry in arr:
            cvss_data = entry.get("cvssData") or {}
            if "baseScore" in cvss_data:
                return _normalize_cvss(cvss_data, version_key)
            
            # Formato alternativo (legacy)
            if "baseScore" in entry:
                return {
                    "baseScore": entry["baseScore"],
                    "vectorString": entry.get("vectorString", "N/A"),
                    "version": "3.1" if "V31" in version_key else "3.0"
                }
    
    # ========================================================
    # FASE 3: CVSS v2 (último recurso)
    # ========================================================
    arr_v2 = metrics.get("cvssMetricV2") or []
    if isinstance(arr_v2, list) and arr_v2:
        entry = arr_v2[0]
        cvss_data = entry.get("cvssData") or {}
        if "baseScore" in cvss_data:
            return {
                "baseScore": cvss_data.get("baseScore"),
                "vectorString": cvss_data.get("vectorString", "N/A"),
                "version": "2.0"
            }
    
    return {}


def _normalize_cvss(cvss_data: dict, version_key: str) -> dict:
    """
    Normaliza CVSS a formato uniforme, incluyendo v4.0
    """
    result = {
        "baseScore": cvss_data.get("baseScore"),
        "vectorString": cvss_data.get("vectorString", "N/A")
    }
    
    # Detectar versión
    if "V40" in version_key or cvss_data.get("version") == "4.0":
        result["version"] = "4.0"
        # CVSS v4.0 tiene estructura diferente, mapear campos principales
        result["baseSeverity"] = cvss_data.get("baseSeverity", "UNKNOWN")
        result["attackVector"] = cvss_data.get("attackVector", "UNKNOWN")
        result["attackComplexity"] = cvss_data.get("attackComplexity", "UNKNOWN")
        
    elif "V31" in version_key or cvss_data.get("version") == "3.1":
        result["version"] = "3.1"
        
    elif "V30" in version_key or cvss_data.get("version") == "3.0":
        result["version"] = "3.0"
        
    else:
        result["version"] = cvss_data.get("version", "unknown")
    
    return result