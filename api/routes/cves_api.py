# api/routes/cves_api.py
import os, re, json, uuid, io, csv
from datetime import datetime
from flask import Blueprint, request, current_app, jsonify, Response

# ✅ ahora el parser avanzado vive en utils/query_parser
from utils.query_parser import parse_advanced_query
# ✅ helpers de API reusables
from utils.api_utils import build_meta, risk_label as _risk_label, build_query_from_request as _build_query_from_request

bp_api = Blueprint("cves_api", __name__, url_prefix="/api/v1")

# =========================
#  ENDPOINT PRINCIPAL
# =========================

@bp_api.route("/cves")
def list_cves():
    col = current_app.mongo.db[os.getenv("MONGO_COLLECTION")]

    q_parts = []
    year = request.args.get("year", type=str)
    min_score = request.args.get("min_score", type=float)
    tipo = request.args.get("tipo", type=str)
    etiquetas = request.args.getlist("etiquetas")
    infra = request.args.getlist("infra")
    adv = request.args.get("q", "", type=str)

    if min_score is not None and min_score > 0:
        q_parts.append({"cvssv3.score": {"$gte": float(min_score)}})
    if year:
        try:
            y = int(year)
            q_parts.append({"fecha_publicacion_dt": {"$gte": datetime(y,1,1), "$lt": datetime(y+1,1,1)}})
        except Exception:
            q_parts.append({"fecha_publicacion": {"$regex": f"^{year}"}})
    if tipo:
        q_parts.append({"tipo": {"$regex": f"^{tipo}$", "$options": "i"}})
    if etiquetas:
        q_parts.append({"etiquetas": {"$all": etiquetas}})
    if infra:
        q_parts.append({"infraestructura_5g_afectada": {"$all": infra}})

    # ✅ usar parser avanzado común
    adv_q = parse_advanced_query(adv) if adv else {}
    if adv_q:
        q_parts.append(adv_q)

    q = {"$and": q_parts} if q_parts else {}

    # ---- paginación / orden ----
    page = max(1, request.args.get("page", default=1, type=int))
    per_page = min(200, max(1, request.args.get("per_page", default=20, type=int)))
    sort_by = request.args.get("sort_by", default="fecha_publicacion", type=str)
    sort_dir = request.args.get("sort_dir", default="desc", type=str)

    sort_field = {
        "cvss": "cvssv3.score",
        "cve_id": "cve_id",
        "tipo": "tipo",
        "nombre": "nombre",
        "fecha_publicacion": "fecha_publicacion_dt",
    }.get(sort_by, "fecha_publicacion_dt")
    sort_order = 1 if sort_dir == "asc" else -1

    total = col.count_documents(q)
    cursor = (col.find(q, {"_id": 0})
                .sort(sort_field, sort_order)
                .skip((page - 1) * per_page)
                .limit(per_page))
    cves = list(cursor)

    meta = build_meta(col, q)

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "cves": cves,
        "meta": meta
    })

# =========================
#  EXPORT STIX / CSV / JSON
# =========================

@bp_api.route("/export/stix")
def export_stix():
    col, q, sort_field, sort_dir = _build_query_from_request(request)

    try:
        limit = int(request.args.get("limit", 5000))
    except Exception:
        limit = 5000
    limit = max(1, min(limit, 20000))

    cursor = (col.find(q, {"_id": 0})
                .sort(sort_field, sort_dir)
                .limit(limit))

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    objs = []
    for d in cursor:
        cve_id = d.get("cve_id") or f"NO-CVE-{uuid.uuid4()}"
        desc = d.get("descripcion_general") or d.get("nombre") or ""
        score = (d.get("cvssv3") or {}).get("score", 0.0)
        vector = (d.get("cvssv3") or {}).get("vector", "N/A")
        etiquetas = d.get("etiquetas") or []
        infra = d.get("infraestructura_5g_afectada") or []
        tipo = d.get("tipo") or ""
        refs_mitre = d.get("referencias_mitre") or []

        ext_refs = [{
            "source_name": "cve",
            "external_id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }]
        for r in refs_mitre:
            if r:
                ext_refs.append({"source_name": "mitre", "url": r})

        vul = {
            "type": "vulnerability",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": cve_id,
            "description": desc[:10000],
            "external_references": ext_refs,
            "labels": [x for x in ["5g", (tipo.strip() or None), _risk_label(score)] if x],
            "x_cvss": {"score": score, "vector": vector},
            "x_etiquetas": etiquetas,
            "x_infraestructura_5g": infra,
            "x_fecha_publicacion": d.get("fecha_publicacion"),
            "x_dificultad": d.get("dificultad_explotacion"),
            "x_impacto": d.get("impacto_potencial"),
            "x_fuente": d.get("fuente") or "NVD",
        }
        objs.append(vul)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objs,
    }

    payload = json.dumps(bundle, ensure_ascii=False, default=str)
    fn = f"vulndb5g_stix_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    return Response(
        payload,
        mimetype="application/stix+json",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'}
    )

@bp_api.route("/export/csv")
def export_csv():
    col, q, sort_field, sort_dir = _build_query_from_request(request)

    try:
        limit = int(request.args.get("limit", 5000))
    except Exception:
        limit = 5000
    limit = max(1, min(limit, 20000))

    cursor = (col.find(q, {"_id": 0})
                .sort(sort_field, sort_dir)
                .limit(limit))
    results = list(cursor)

    if not results:
        return Response("", mimetype="text/csv")

    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

    output = si.getvalue()
    fn = f"vulndb5g_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'}
    )

@bp_api.route("/export/json")
def export_json():
    col, q, sort_field, sort_dir = _build_query_from_request(request)

    try:
        limit = int(request.args.get("limit", 5000))
    except Exception:
        limit = 5000
    limit = max(1, min(limit, 20000))

    cursor = (col.find(q, {"_id": 0})
                .sort(sort_field, sort_dir)
                .limit(limit))
    results = list(cursor)

    fn = f"vulndb5g_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"

    return Response(
        json.dumps(results, ensure_ascii=False, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'}
    )
