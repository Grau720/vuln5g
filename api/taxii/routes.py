# api/taxii/routes.py
import os
import base64
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, current_app, request, jsonify, Response

from utils.export import cve_to_stix_vulnerability

bp_taxii = Blueprint("taxii", __name__, url_prefix="/taxii2")

TAXII_CT = 'application/taxii+json; version=2.1'

# Config mínima
API_ROOT_PATH = "/taxii2/api"
COLLECTIONS = [
    {
        "id": "vulnerabilities",
        "title": "5G Vulnerabilities",
        "description": "Colección de vulnerabilidades 5G (SDO type: vulnerability).",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json; version=2.1"],
    }
]

def _taxii_json(data: Dict[str, Any], status: int = 200) -> Response:
    return Response(json.dumps(data, ensure_ascii=False, indent=2),
                    status=status, mimetype=TAXII_CT)

def _parse_added_after(val: Optional[str]) -> Optional[datetime]:
    if not val: 
        return None
    try:
        # RFC3339/ISO-like
        return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None

def _encode_token(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode()

def _decode_token(token: Optional[str]) -> int:
    if not token:
        return 0
    try:
        return int(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:
        return 0

@bp_taxii.route("/", methods=["GET"])
def discovery():
    """TAXII Discovery"""
    base_url = request.host_url.rstrip("/")
    data = {
        "title": "VulnDB 5G TAXII",
        "description": "Discovery de endpoints TAXII 2.1",
        "default": f"{base_url}{API_ROOT_PATH}",
        "api_roots": [f"{base_url}{API_ROOT_PATH}"],
    }
    return _taxii_json(data)

@bp_taxii.route("/api", methods=["GET"])
def api_root():
    """TAXII API Root"""
    data = {
        "title": "VulnDB 5G API Root",
        "versions": ["2.1"],
        "max_content_length": 10485760,  # 10 MB
    }
    return _taxii_json(data)

@bp_taxii.route("/api/collections", methods=["GET"])
def collections():
    data = {"collections": [
        {
            "id": c["id"],
            "title": c["title"],
            "description": c.get("description", ""),
            "can_read": c.get("can_read", True),
            "can_write": c.get("can_write", False),
            "media_types": c.get("media_types", ["application/stix+json; version=2.1"]),
        } for c in COLLECTIONS
    ]}
    return _taxii_json(data)

@bp_taxii.route("/api/collections/<cid>", methods=["GET"])
def collection_detail(cid: str):
    c = next((x for x in COLLECTIONS if x["id"] == cid), None)
    if not c:
        return _taxii_json({"title": "Not Found", "description": "Collection not found"}, 404)
    data = {
        "id": c["id"],
        "title": c["title"],
        "description": c.get("description", ""),
        "can_read": c.get("can_read", True),
        "can_write": c.get("can_write", False),
        "media_types": c.get("media_types", ["application/stix+json; version=2.1"]),
    }
    return _taxii_json(data)

@bp_taxii.route("/api/collections/<cid>/objects", methods=["GET"])
def objects(cid: str):
    """Devuelve objetos STIX (SDOs) de la colección en formato TAXII."""
    if cid != "vulnerabilities":
        return _taxii_json({"title": "Not Found", "description": "Collection not found"}, 404)

    col = current_app.mongo.db[os.getenv("MONGO_COLLECTION")]

    # Filtros TAXII básicos
    match_type = request.args.getlist("match[type]")  # p.ej. vulnerability
    match_id = request.args.getlist("match[id]")      # id STIX (vulnerability--CVE-XXXX-YYYY)
    added_after = _parse_added_after(request.args.get("added_after"))

    limit = min(200, max(1, request.args.get("limit", default=50, type=int)))
    next_token = request.args.get("next")
    offset = _decode_token(next_token)

    # Construir query Mongo (sobre CVEs crudos)
    q: Dict[str, Any] = {}

    # Filtrado por "match[type]" solo permitimos vulnerability
    if match_type:
        # si el tipo no incluye "vulnerability" no devolvemos nada
        if "vulnerability" not in match_type:
            return _taxii_json({"objects": [], "more": False}, 200)

    # Filtrado por match[id] -> extraemos cve_id de "vulnerability--CVE-YYYY-NNNN"
    if match_id:
        cve_ids = []
        for sid in match_id:
            if sid.startswith("vulnerability--"):
                cve_ids.append(sid.split("vulnerability--", 1)[1])
        if cve_ids:
            q["cve_id"] = {"$in": cve_ids}
        else:
            return _taxii_json({"objects": [], "more": False}, 200)

    # added_after -> usamos fecha_actualizacion o fecha_ingesta
    if added_after:
        q["$or"] = [
            {"fecha_actualizacion_dt": {"$gt": added_after}},
            {"fecha_ingesta_dt": {"$gt": added_after}},
        ]

    # Orden consistente (por fecha_actualizacion_dt desc, fallback cve_id)
    sort = [("fecha_actualizacion_dt", -1), ("cve_id", 1)]

    cursor = (col.find(q, {"_id": 0})
                .sort(sort)
                .skip(offset)
                .limit(limit + 1))  # +1 para saber si hay 'more'

    docs = list(cursor)
    has_more = len(docs) > limit
    page_docs = docs[:limit]

    # Mapear a STIX SDOs
    sdos = [cve_to_stix_vulnerability(d) for d in page_docs]

    resp: Dict[str, Any] = {
        "objects": sdos,
        "more": has_more,
    }
    if has_more:
        resp["next"] = _encode_token(offset + limit)

    return _taxii_json(resp)
