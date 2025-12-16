import requests
import json
import logging

logger = logging.getLogger("ingest-nvd-kev")

_kev_cache = None  

def load_kev_dataset():
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        data = r.json()
        kev_map = {}
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID", "").upper()
            if cve_id:
                kev_map[cve_id] = item
        _kev_cache = kev_map
    except Exception as e:
        logger.warning(f"[!] No se pudo cargar KEV: {e}")
        _kev_cache = {}
    return _kev_cache
