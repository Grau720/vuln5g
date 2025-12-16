import os
import logging
from flask import Blueprint, request, jsonify, current_app
from joblib import load
from pymongo import MongoClient
from services.ia.featurizer import Featurizer  

bp_ia = Blueprint("ia_api", __name__, url_prefix="/api/v1/ia")
logger = logging.getLogger("IA-API")

# ======================================================
#  CONFIGURACIÓN DE RUTAS — Con fallback
# ======================================================
# Intentar múltiples ubicaciones posibles
POSSIBLE_PATHS = [
    "/app/services/ia/models",
    "/app/ia/models",
    "./models",
    "./ia/models"
]

def find_model_path():
    """
    Prioriza modelo calibrado.
    Si no existe, usa el modelo base como fallback.
    """
    for base_path in POSSIBLE_PATHS:
        calibrated = os.path.join(base_path, "exploit_model_calibrated.joblib")
        base = os.path.join(base_path, "exploit_model.joblib")
        feat = os.path.join(base_path, "featurizer.joblib")

        if os.path.exists(calibrated) and os.path.exists(feat):
            logger.info(f"✅ Modelo CALIBRADO encontrado en: {base_path}")
            return calibrated, feat

        if os.path.exists(base) and os.path.exists(feat):
            logger.warning(f"⚠️ Usando modelo NO calibrado en: {base_path}")
            return base, feat

    return None, None

MODEL_PATH, FEAT_PATH = find_model_path()

MODEL_CALIBRATED = False
MODEL_NAME = None
MODEL_LOADED_AT = None

# ======================================================
#  CARGA MODELO Y FEATURIZER — SOLO UNA VEZ
# ======================================================
model = None
featurizer = None
IA_READY = False

if MODEL_PATH and FEAT_PATH:
    try:
        logger.info(f"🔄 Cargando modelo desde: {MODEL_PATH}")
        model = load(MODEL_PATH)
        
        logger.info(f"🔄 Cargando featurizer desde: {FEAT_PATH}")
        featurizer = Featurizer.load(FEAT_PATH)
        
        IA_READY = True
        logger.info("✅ IA cargada correctamente.")
    except Exception as e:
        logger.error(f"❌ Error cargando IA: {e}")
        logger.exception(e)
        IA_READY = False
else:
    logger.error("❌ No se encontraron los archivos del modelo en ninguna ruta conocida")
    logger.error(f"   Rutas buscadas: {POSSIBLE_PATHS}")

# ======================================================
#  HELPER: Nivel de riesgo según score
# ======================================================
def risk_level(score: float) -> str:
    """Determina el nivel de riesgo basado en la probabilidad de explotación"""
    if score >= 0.75:
        return "CRITICAL"
    elif score >= 0.50:
        return "HIGH"
    elif score >= 0.25:
        return "MEDIUM"
    else:
        return "LOW"

# ======================================================
#  ENDPOINT → STATUS DEL MODELO
# ======================================================
@bp_ia.route("/status", methods=["GET"])
def model_status():
    """Verifica el estado del modelo de IA"""
    return jsonify({
        "model_loaded": IA_READY,
        "model_path": MODEL_PATH if MODEL_PATH else "not found",
        "featurizer_path": FEAT_PATH if FEAT_PATH else "not found",
        "searched_paths": POSSIBLE_PATHS
    }), 200 if IA_READY else 503

# ======================================================
#  ENDPOINT → Predict para un CVE individual
# ======================================================
@bp_ia.route("/predict/<cve_id>", methods=["GET"])
def predict_cve(cve_id):
    """
    Predice la probabilidad de explotación para un CVE específico
    
    Ejemplo: GET /api/v1/ia/predict/CVE-2022-49075
    
    Respuesta:
    {
        "cve_id": "CVE-2022-49075",
        "exploit_probability": 0.23,
        "risk_level": "LOW"
    }
    """
    if not IA_READY:
        return jsonify({
            "error": "IA service not available",
            "details": "Model not loaded. Check /api/v1/ia/status"
        }), 503
    
    # -----------------------------
    # 1) Obtener CVE desde MongoDB
    # -----------------------------
    try:
        col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        cve_doc = col.find_one({"cve_id": cve_id})
        
        if not cve_doc:
            return jsonify({
                "error": "CVE not found",
                "cve_id": cve_id
            }), 404
    except Exception as e:
        logger.error(f"❌ Error accediendo a MongoDB: {e}")
        return jsonify({
            "error": "Database error",
            "details": str(e)
        }), 500
    
    # -----------------------------
    # 2) Extraer features del CVE
    # -----------------------------
    try:
        raw = featurizer.extract_raw_features(cve_doc)
        X = featurizer.transform([raw])
    except Exception as e:
        logger.error(f"❌ Error procesando features para {cve_id}: {e}")
        logger.exception(e)
        return jsonify({
            "error": "Feature extraction failed",
            "cve_id": cve_id,
            "details": str(e)
        }), 500
    
    # -----------------------------
    # 3) Ejecutar predicción
    # -----------------------------
    try:
        prob = float(model.predict_proba(X)[0][1])
        pred_class = int(model.predict(X)[0])
    except Exception as e:
        logger.error(f"❌ Error ejecutando predicción: {e}")
        logger.exception(e)
        return jsonify({
            "error": "Prediction failed",
            "details": str(e)
        }), 500
    
    # -----------------------------
    # 4) Respuesta final
    # -----------------------------
    response = {
        "cve_id": cve_id,
        "exploit_probability": round(prob, 4),
        "predicted_class": pred_class,
        "risk_level": risk_level(prob),
        "metadata": {
            "cvss_score": cve_doc.get("cvssv3", {}).get("score", 0),
            "tipo": cve_doc.get("tipo", "unknown")
        }
    }
    
    logger.info(f"✅ Predicción exitosa para {cve_id}: {prob:.4f}")
    return jsonify(response), 200

# ======================================================
#  ENDPOINT → Predicción por lotes
# ======================================================
@bp_ia.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Predice múltiples CVEs en una sola llamada
    
    Body JSON:
    {
        "cve_ids": ["CVE-2024-1234", "CVE-2023-5678"]
    }
    
    Respuesta:
    {
        "predictions": [
            {
                "cve_id": "CVE-2024-1234",
                "exploit_probability": 0.85,
                "risk_level": "CRITICAL"
            },
            ...
        ],
        "summary": {
            "total": 2,
            "successful": 1,
            "failed": 1
        }
    }
    """
    if not IA_READY:
        return jsonify({
            "error": "IA service not available"
        }), 503
    
    data = request.get_json()
    if not data:
        return jsonify({
            "error": "Invalid JSON body"
        }), 400
    
    cve_ids = data.get("cve_ids", [])
    
    if not cve_ids:
        return jsonify({
            "error": "No CVE IDs provided",
            "example": {"cve_ids": ["CVE-2024-1234", "CVE-2023-5678"]}
        }), 400
    
    if len(cve_ids) > 100:
        return jsonify({
            "error": "Too many CVE IDs",
            "max_allowed": 100,
            "received": len(cve_ids)
        }), 400
    
    results = []
    successful = 0
    failed = 0
    
    col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
    
    for cve_id in cve_ids:
        try:
            cve_doc = col.find_one({"cve_id": cve_id})
            
            if not cve_doc:
                results.append({
                    "cve_id": cve_id,
                    "error": "not found"
                })
                failed += 1
                continue
            
            raw = featurizer.extract_raw_features(cve_doc)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            
            results.append({
                "cve_id": cve_id,
                "exploit_probability": round(prob, 4),
                "risk_level": risk_level(prob)
            })
            successful += 1
            
        except Exception as e:
            logger.error(f"❌ Error processing {cve_id}: {e}")
            results.append({
                "cve_id": cve_id,
                "error": str(e)
            })
            failed += 1
    
    return jsonify({
        "predictions": results,
        "summary": {
            "total": len(cve_ids),
            "successful": successful,
            "failed": failed
        }
    }), 200

# ======================================================
#  ENDPOINT → Análisis de top CVEs por riesgo
# ======================================================
@bp_ia.route("/top-risk", methods=["GET"])
def top_risk():
    """
    Devuelve los CVEs con mayor probabilidad de explotación
    
    Query params:
    - limit: número de CVEs a retornar (default: 10, max: 50)
    - min_cvss: CVSS mínimo para filtrar (default: 0)
    
    Ejemplo: GET /api/v1/ia/top-risk?limit=20&min_cvss=7.0
    """
    if not IA_READY:
        return jsonify({"error": "IA service not available"}), 503
    
    try:
        limit = min(int(request.args.get("limit", 10)), 50)
        min_cvss = float(request.args.get("min_cvss", 0))
    except ValueError:
        return jsonify({"error": "Invalid parameters"}), 400
    
    col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
    
    # Filtrar CVEs con CVSS >= min_cvss
    query = {"cvssv3.score": {"$gte": min_cvss}}
    cves = list(col.find(query).limit(500))  # Procesar máximo 500
    
    if not cves:
        return jsonify({
            "top_risks": [],
            "message": "No CVEs found matching criteria"
        }), 200
    
    # Calcular predicciones
    predictions = []
    for cve in cves:
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            
            predictions.append({
                "cve_id": cve["cve_id"],
                "exploit_probability": round(prob, 4),
                "risk_level": risk_level(prob),
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "tipo": cve.get("tipo", "unknown")
            })
        except Exception as e:
            logger.error(f"Error processing {cve.get('cve_id')}: {e}")
            continue
    
    # Ordenar por probabilidad descendente
    predictions.sort(key=lambda x: x["exploit_probability"], reverse=True)
    
    return jsonify({
        "top_risks": predictions[:limit],
        "total_analyzed": len(predictions),
        "filters": {
            "min_cvss": min_cvss,
            "limit": limit
        }
    }), 200