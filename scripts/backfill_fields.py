# scripts/backfill_fields.py
import os
from pymongo import MongoClient
from services.ingest.normalize import (
    parse_fecha_publicacion_dt, riesgo_from_score, dificultad_from_vector
)

MONGO_URI = f"mongodb://{os.getenv('MONGO_USER','admin')}:{os.getenv('MONGO_PASS','changeme')}@" \
            f"{os.getenv('MONGO_HOST','localhost')}:{os.getenv('MONGO_PORT','27017')}/" \
            f"?authSource={os.getenv('MONGO_AUTH_DB','admin')}"
DB = os.getenv("MONGO_DB", "vulndb")
COL = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

client = MongoClient(MONGO_URI)
col = client[DB][COL]

bulk = []
batch = 0
for doc in col.find({}, {"_id":1, "fecha_publicacion":1, "cvssv3":1,
                         "riesgo":1, "dificultad_explotacion":1, "fecha_publicacion_dt":1}):
    cvss = (doc.get("cvssv3") or {})
    score = float(cvss.get("score", 0.0) or 0.0)
    vector = cvss.get("vector", "") or ""

    set_fields = {}
    if not doc.get("fecha_publicacion_dt"):
        dt = parse_fecha_publicacion_dt(doc.get("fecha_publicacion",""))
        if dt:
            set_fields["fecha_publicacion_dt"] = dt
    if not doc.get("riesgo"):
        set_fields["riesgo"] = riesgo_from_score(score)
    if not doc.get("dificultad_explotacion") and vector:
        set_fields["dificultad_explotacion"] = dificultad_from_vector(vector)

    if set_fields:
        col.update_one({"_id": doc["_id"]}, {"$set": set_fields})
        batch += 1

print(f"Backfill completado. Documentos actualizados: {batch}")
