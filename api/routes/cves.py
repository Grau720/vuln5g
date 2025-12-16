# api/routes/cves.py
import os
import csv
import io
import json
from flask import Blueprint, render_template, request, current_app, Response, jsonify
from datetime import datetime
from utils.query_parser import parse_advanced_query

bp = Blueprint("cves", __name__)

@bp.route("/dashboard")
def dashboard():
    collection = current_app.mongo.db[os.getenv("MONGO_COLLECTION")]

    # -------------------------------
    # 🔎 1. Leer filtros de entrada
    # -------------------------------
    year = request.args.get("year")
    min_score = request.args.get("min_score", type=float, default=0.0)
    tipo = request.args.get("tipo")
    etiquetas = request.args.getlist("etiquetas")
    infraestructura = request.args.getlist("infra")

    # -------------------------------
    # 🔍 2. Construir query Mongo
    # -------------------------------
    advanced_q = request.args.get("q", "")
    query = {"cvssv3.score": {"$gte": min_score}}

    if year:
        query["fecha_publicacion"] = {"$regex": f"^{year}"}
    if tipo:
        query["tipo"] = tipo
    if etiquetas:
        query["etiquetas"] = {"$all": etiquetas}
    if infraestructura:
        query["infraestructura_5g_afectada"] = {"$all": infraestructura}

    # ✅ usar parser avanzado común
    if advanced_q:
        parsed = parse_advanced_query(advanced_q)
        query.update(parsed)

    # -------------------------------
    # 📥 3. Obtener resultados filtrados
    # -------------------------------
    cves = list(collection.find(query).sort("fecha_publicacion", -1))

    # -------------------------------
    # 📊 4. Obtener valores únicos para filtros
    # -------------------------------
    years = sorted({y[:4] for y in collection.distinct("fecha_publicacion") if y and len(y) >= 4})
    tipos = sorted({t for t in collection.distinct("tipo") if t and t.lower() != "sin clasificar"})
    etiquetas_disponibles = sorted({e for e in collection.distinct("etiquetas") if isinstance(e, str) and e.strip()})
    infraestructura_disponible = sorted({i for i in collection.distinct("infraestructura_5g_afectada") if isinstance(i, str) and i.strip()})

    return render_template(
        "dashboard.html",
        cves=cves,
        year=year,
        min_score=min_score,
        tipo=tipo,
        etiquetas=etiquetas,
        infraestructura=infraestructura,
        query=advanced_q,
        filtros={
            "years": years,
            "tipos": tipos,
            "etiquetas": etiquetas_disponibles,
            "infraestructura": infraestructura_disponible
        }
    )

@bp.route("/debug/fields")
def debug_fields():
    collection = current_app.mongo.db[os.getenv("MONGO_COLLECTION")]

    muestra = list(collection.find({}, {
        "tipo": 1,
        "etiquetas": 1,
        "infraestructura_5g_afectada": 1,
        "fecha_publicacion": 1,
        "_id": 0
    }).limit(50))

    return {"muestra": muestra}
