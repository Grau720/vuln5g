# utils/api_utils.py
import os
import re
from datetime import datetime
from typing import Any, Dict, Tuple
from flask import current_app, Request
from utils.query_parser import parse_advanced_query

def risk_label(score: float) -> str:
    try:
        s = float(score or 0.0)
    except Exception:
        s = 0.0
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    if s >  0.0: return "low"
    return "none"

def build_query_from_request(req: Request) -> Tuple[Any, Dict[str, Any], str, int]:
    """Construye (colección, filtro Mongo, campo orden, dir orden) a partir de query params."""
    col = current_app.mongo.db[os.getenv("MONGO_COLLECTION")]
    q: Dict[str, Any] = {"$and": []}

    year = req.args.get("year")
    min_score = req.args.get("min_score", type=float, default=0.0)
    tipo = req.args.get("tipo")
    etiquetas = req.args.getlist("etiquetas")
    infraestructura = req.args.getlist("infra")
    adv = req.args.get("q", "")

    if min_score:
        q["$and"].append({"cvssv3.score": {"$gte": float(min_score)}})
    if year:
        try:
            y = int(year)
            q["$and"].append({"fecha_publicacion_dt": {"$gte": datetime(y,1,1), "$lt": datetime(y+1,1,1)}})
        except Exception:
            q["$and"].append({"fecha_publicacion": {"$regex": f"^{re.escape(year)}"}})
    if tipo:
        q["$and"].append({"tipo": {"$regex": f"^{re.escape(tipo)}$", "$options": "i"}})
    if etiquetas:
        q["$and"].append({"etiquetas": {"$all": etiquetas}})
    if infraestructura:
        q["$and"].append({"infraestructura_5g_afectada": {"$all": infraestructura}})

    adv_mongo = parse_advanced_query(adv) if adv else {}
    if adv_mongo:
        q["$and"].append(adv_mongo)

    if not q["$and"]:
        q = {}

    sort_by = req.args.get("sort_by", "fecha_publicacion")
    sort_dir = 1 if req.args.get("sort_dir", "desc") == "asc" else -1
    sort_field = {
        "cvss": "cvssv3.score",
        "cve_id": "cve_id",
        "tipo": "tipo",
        "fecha_publicacion": "fecha_publicacion_dt",
        "nombre": "nombre",
    }.get(sort_by, "fecha_publicacion_dt")

    return col, q, sort_field, sort_dir

def build_meta(col, q) -> Dict[str, Any]:
    """Agregaciones para gráficos / filtros rápidos."""
    by_month = list(col.aggregate([
        {"$match": q},
        {"$addFields": {
            "month": {
                "$let": {
                    "vars": {"fp": {"$ifNull": ["$fecha_publicacion", ""]}},
                    "in": {"$substrCP": ["$$fp", 0, 7]}
                }
            }
        }},
        {"$match": {"month": {"$ne": ""}}},
        {"$group": {"_id": "$month", "total": {"$sum": 1}}},
        {"$project": {"month": "$_id", "total": 1, "_id": 0}},
        {"$sort": {"month": 1}}
    ]))

    by_tipo = list(col.aggregate([
        {"$match": q},
        {"$group": {"_id": "$tipo", "total": {"$sum": 1}}},
        {"$project": {"tipo": "$_id", "total": 1, "_id": 0}},
        {"$sort": {"total": -1}}
    ]))

    by_infra = list(col.aggregate([
        {"$match": q},
        {"$unwind": {"path": "$infraestructura_5g_afectada", "preserveNullAndEmptyArrays": False}},
        {"$group": {"_id": "$infraestructura_5g_afectada", "total": {"$sum": 1}}},
        {"$project": {"infra": "$_id", "total": 1, "_id": 0}},
        {"$sort": {"total": -1}}
    ]))

    cvss_hist = list(col.aggregate([
        {"$match": q},
        {"$bucket": {
            "groupBy": "$cvssv3.score",
            "boundaries": [0, 1, 4, 7, 9, 11],
            "default": "Desconocido",
            "output": {"total": {"$sum": 1}}
        }},
        {"$project": {"bucket": {"$toString": "$_id"}, "total": 1, "_id": 0}}
    ]))

    years = sorted(
        {(m.get("month") or "")[:4] for m in by_month if isinstance(m.get("month"), str) and len(m.get("month")) >= 4},
        reverse=True
    )

    options = {
        "years": years,
        "tipos": [x["tipo"] for x in by_tipo if x.get("tipo") and x["tipo"].lower() != "sin clasificar"],
        "etiquetas": sorted({e
            for d in col.find(q, {"etiquetas": 1, "_id": 0})
            for e in (d.get("etiquetas") or [])
            if isinstance(e, str) and e.strip()}),
        "infraestructura": sorted({i
            for d in col.find(q, {"infraestructura_5g_afectada": 1, "_id": 0})
            for i in (d.get("infraestructura_5g_afectada") or [])
            if isinstance(i, str) and i.strip()}),
    }

    return {
        "by_month": by_month,
        "by_tipo": by_tipo,
        "by_infra": by_infra,
        "cvss_hist": cvss_hist,
        "options": options,
    }
