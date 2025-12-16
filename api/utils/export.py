# api/utils/export.py
import json, csv, io
from datetime import datetime
from typing import Dict, Any, Iterable, List

def cve_to_stix_vulnerability(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convierte un documento CVE de Mongo a un SDO STIX 2.1 'vulnerability'."""
    cve_id = doc.get("cve_id") or f"VULN-{doc.get('_id')}"
    created = doc.get("fecha_ingesta")
    modified = doc.get("fecha_actualizacion") or created

    sdo = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{cve_id}",
        "created": created,
        "modified": modified,
        "name": doc.get("nombre") or cve_id,
        "description": doc.get("descripcion_general", "")[:10_000],
        "external_references": [
            {"source_name": "cve", "external_id": cve_id}
        ],
    }

    score = (doc.get("cvssv3") or {}).get("score")
    if isinstance(score, (int, float)):
        sdo["x_cvss_v3"] = score

    etiquetas = doc.get("etiquetas") or []
    if isinstance(etiquetas, list) and etiquetas:
        sdo["labels"] = [e for e in etiquetas if isinstance(e, str)]

    return sdo

def build_stix_bundle(docs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Crea un STIX Bundle 2.1 con los SDO resultantes."""
    now_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    objs: List[Dict[str, Any]] = [cve_to_stix_vulnerability(d) for d in docs]
    return {
        "type": "bundle",
        "id": f"bundle--{now_id}",
        "spec_version": "2.1",
        "objects": objs,
    }

def dumps_bundle(bundle: Dict[str, Any]) -> str:
    return json.dumps(bundle, indent=2, ensure_ascii=False)

def export_cves_to_csv(cves):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=cves[0].keys())
    writer.writeheader()
    writer.writerows(cves)
    return output.getvalue()

def export_cves_to_json(cves):
    return json.dumps(cves, ensure_ascii=False, indent=2)