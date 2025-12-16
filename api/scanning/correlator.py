# api/scanning/correlator.py
import os, requests, logging
from typing import List, Dict, Any

logger = logging.getLogger("scanner-correlator")

API_URL = os.getenv("CVE_API_URL", "http://localhost:5000/api/v1/cves")

def correlate_findings(findings: List[Dict[str, Any]], min_score=0, max_candidates=5):
    
    out = []
    for f in findings:
        logger.debug(f"[correlator] Processing finding: {f.get('finding_id')} | protocol={f.get('protocol')} | service={f.get('service')}")
        terms = []
        proto = f.get("protocol")
        if proto and proto not in ("—", None, ""):
            terms.append(f"proto:{proto}")

        svc = f.get("service")
        if svc:
            terms.append(f"nombre:{svc}")

        banner = (f.get("evidence") or {}).get("banner")
        if banner:
            terms.append(f'descripcion:"{banner}"')

        if not terms:
            out.append(f)
            continue

        q = " OR ".join(terms)   
        try:
            logger.info(f"[correlator] Querying {API_URL} with q='{q}'")
            r = requests.get(
                API_URL,
                params={"q": q, "min_score": min_score, "per_page": max_candidates},
                timeout=8,
            )
            r.raise_for_status()
            data = r.json()
            logger.debug(f"[correlator] API Response: {data}")
            cves = [c.get("cve_id") for c in data.get("cves", []) if c.get("cve_id")]
            if cves:
                f["cve_candidates"] = cves
                logger.info(f"[correlator] ✅ {f.get('finding_id')} → {cves}")
            else:
                logger.warning(f"[correlator] ❌ {f.get('finding_id')} → No CVEs found for query '{q}'")
        except Exception as e:
            logger.warning(f"[correlator] error correlando {f.get('finding_id')}: {e}")

        out.append(f)
    return out
