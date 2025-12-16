import os
import logging
from flask import Blueprint, request, jsonify, current_app
from joblib import load
from pymongo import MongoClient
from services.ia.featurizer import Featurizer  
from datetime import datetime

bp_ia = Blueprint("ia_api", __name__, url_prefix="/api/v1/ia")
logger = logging.getLogger("IA-API")

# ======================================================
#  CONFIGURACIÓN DE MODELOS — V2.1 Support
# ======================================================
POSSIBLE_PATHS = [
    "/app/services/ia/models",
    "/app/ia/models",
    "./models",
    "./ia/models"
]

MODEL_VERSIONS = {
    "v2.1": {
        "base": "exploit_model_v2.1.joblib",
        "calibrated": "exploit_model_v2.1_calibrated.joblib",
        "featurizer": "featurizer_v2.1.joblib",
        "name": "V2.1 (Attack Vector Aware)"
    },
    "v2.0": {
        "base": "exploit_model_v2.joblib",
        "calibrated": "exploit_model_v2_calibrated.joblib",
        "featurizer": "featurizer_v2.joblib",
        "name": "V2.0 (Smart Labels)"
    },
    "v1": {
        "base": "exploit_model.joblib",
        "calibrated": "exploit_model_calibrated.joblib",
        "featurizer": "featurizer.joblib",
        "name": "V1 (Heuristic)"
    }
}

def find_best_model():
    """
    Busca el mejor modelo disponible.
    Prioridad: V2.1 calibrado > V2.1 base > V2.0 calibrado > V2.0 base > V1 calibrado > V1 base
    
    Returns:
        (model_path, featurizer_path, version, is_calibrated, base_path)
    """
    search_order = [
        ("v2.1", True),
        ("v2.1", False),
        ("v2.0", True),
        ("v2.0", False),
        ("v1", True),
        ("v1", False)
    ]
    
    for base_path in POSSIBLE_PATHS:
        for version, prefer_calibrated in search_order:
            version_info = MODEL_VERSIONS[version]
            
            model_file = version_info["calibrated"] if prefer_calibrated else version_info["base"]
            feat_file = version_info["featurizer"]
            
            model_path = os.path.join(base_path, model_file)
            feat_path = os.path.join(base_path, feat_file)
            
            if os.path.exists(model_path) and os.path.exists(feat_path):
                logger.info(f"✅ Modelo encontrado: {version_info['name']} {'(Calibrado)' if prefer_calibrated else ''}")
                logger.info(f"   Ruta: {base_path}")
                return model_path, feat_path, version, prefer_calibrated, base_path
    
    return None, None, None, False, None

MODEL_PATH, FEAT_PATH, MODEL_VERSION, MODEL_CALIBRATED, MODEL_BASE_PATH = find_best_model()
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
        model = load(MODEL_PATH)
        featurizer = Featurizer.load(FEAT_PATH)

        IA_READY = True
        MODEL_NAME = MODEL_VERSIONS[MODEL_VERSION]["name"]
        if MODEL_CALIBRATED:
            MODEL_NAME += " (Calibrado)"
        MODEL_LOADED_AT = datetime.utcnow().isoformat() + "Z"

        logger.info(f"✅ IA Service ready: {MODEL_NAME}")

    except Exception as e:
        logger.exception(e)
        IA_READY = False
else:
    logger.error("❌ No se encontraron los archivos del modelo en ninguna ruta conocida")
    logger.error(f"   Rutas buscadas: {POSSIBLE_PATHS}")

# ======================================================
#  HELPER: Detectar Attack Vector
# ======================================================
def detect_attack_vector(cve_doc):
    """Extrae el Attack Vector del CVSS vector string"""
    vector = cve_doc.get("cvssv3", {}).get("vector", "")
    
    if "AV:N" in vector:
        return "NETWORK"
    elif "AV:L" in vector:
        return "LOCAL"
    elif "AV:A" in vector:
        return "ADJACENT"
    elif "AV:P" in vector:
        return "PHYSICAL"
    else:
        return "UNKNOWN"

# ======================================================
#  HELPER: Threshold usado según Attack Vector y Tipo
# ======================================================
def get_threshold_info(cve_doc, version):
    """
    Calcula el threshold usado para este CVE según su Attack Vector y tipo.
    Solo aplica para V2.1.
    """
    if version != "v2.1":
        return None
    
    # Thresholds base por Attack Vector (de smart_labeling.py)
    AV_THRESHOLDS = {
        "NETWORK": 0.50,
        "ADJACENT": 0.65,
        "LOCAL": 0.75,
        "PHYSICAL": 0.85,
        "UNKNOWN": 0.70
    }
    
    # Ajustes por tipo
    TIPO_ADJUSTMENTS = {
        "Ejecución remota": -0.10,
        "Inyección de comandos/código": -0.10,
        "Inyección SQL": -0.05,
        "Escalada de privilegios": -0.05,
        "Bypass de autenticación": -0.10,
        "Denegación de servicio": +0.15,
        "Cross-Site Scripting": +0.10,
        "Sin clasificar": +0.10,
    }
    
    av = detect_attack_vector(cve_doc)
    tipo = cve_doc.get("tipo", "Sin clasificar")
    
    base_threshold = AV_THRESHOLDS.get(av, 0.70)
    adjustment = TIPO_ADJUSTMENTS.get(tipo, 0.0)
    final_threshold = min(max(base_threshold + adjustment, 0.30), 0.95)
    
    return {
        "base_threshold": base_threshold,
        "adjustment": adjustment,
        "final_threshold": final_threshold,
        "attack_vector": av,
        "tipo": tipo
    }

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
    """
    Devuelve el estado del servicio de IA
    
    GET /api/v1/ia/status
    """
    return jsonify({
        "model_loaded": IA_READY,
        "model": {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "calibrated": MODEL_CALIBRATED,
            "loaded_at": MODEL_LOADED_AT
        },
        "paths": {
            "model": MODEL_PATH if MODEL_PATH else "not found",
            "featurizer": FEAT_PATH if FEAT_PATH else "not found",
            "base_directory": MODEL_BASE_PATH
        },
        "searched_paths": POSSIBLE_PATHS,
        "available_versions": list(MODEL_VERSIONS.keys())
    }), 200 if IA_READY else 503

# ======================================================
#  ENDPOINT → Predict para un CVE individual
# ======================================================
@bp_ia.route("/predict/<cve_id>", methods=["GET"])
def predict_cve(cve_id):
    """
    Predice la probabilidad de explotación para un CVE específico
    
    Ejemplo: GET /api/v1/ia/predict/CVE-2022-49075
    
    Query params opcionales:
    - explain: si es "true", incluye explicación detallada
    
    Respuesta:
    {
        "cve_id": "CVE-2022-49075",
        "exploit_probability": 0.23,
        "predicted_class": 0,
        "risk_level": "LOW",
        "attack_vector": "LOCAL",
        "threshold_info": {
            "final_threshold": 0.75,
            "base_threshold": 0.75,
            "adjustment": 0.0
        },
        "metadata": {
            "cvss_score": 7.8,
            "tipo": "Ejecución remota",
            "componente": "Open5GS",
            "infraestructura_5g": ["Core"]
        },
        "model": {
            "name": "V2.1 (Attack Vector Aware) (Calibrado)",
            "version": "v2.1",
            "calibrated": true
        }
    }
    """
    if not IA_READY:
        return jsonify({
            "error": "IA service not available",
            "details": "Model not loaded. Check /api/v1/ia/status"
        }), 503
    
    # Query params
    include_explain = request.args.get("explain", "false").lower() == "true"
    
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
    # 4) Construir respuesta
    # -----------------------------
    attack_vector = detect_attack_vector(cve_doc)
    threshold_info = get_threshold_info(cve_doc, MODEL_VERSION)
    
    response = {
        "cve_id": cve_id,
        "exploit_probability": round(prob, 4),
        "predicted_class": pred_class,
        "risk_level": risk_level(prob),
        "attack_vector": attack_vector,
        "metadata": {
            "cvss_score": cve_doc.get("cvssv3", {}).get("score", 0),
            "tipo": cve_doc.get("tipo", "unknown"),
            "componente": cve_doc.get("componente_afectado"),
            "infraestructura_5g": cve_doc.get("infraestructura_5g_afectada", [])
        },
        "model": {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "calibrated": MODEL_CALIBRATED
        }
    }
    
    # Añadir threshold info solo para V2.1
    if threshold_info:
        response["threshold_info"] = threshold_info
    
    # Añadir explicación si se solicita
    if include_explain:
        try:
            from services.ia.smart_labeling import explain_label
            explanation = explain_label(cve_doc)
            response["explanation"] = explanation
        except ImportError:
            response["explanation"] = "Explicación no disponible (smart_labeling.py no encontrado)"
        except Exception as e:
            logger.error(f"Error generando explicación: {e}")
            response["explanation"] = f"Error: {str(e)}"
    
    logger.info(f"✅ Predicción exitosa para {cve_id}: {prob:.4f} ({attack_vector})")
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
                "risk_level": "CRITICAL",
                "attack_vector": "NETWORK"
            },
            ...
        ],
        "summary": {
            "total": 2,
            "successful": 1,
            "failed": 1,
            "by_risk_level": {
                "CRITICAL": 1,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            },
            "by_attack_vector": {
                "NETWORK": 1,
                "LOCAL": 0
            }
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
    risk_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    av_stats = {}
    
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
            
            av = detect_attack_vector(cve_doc)
            rl = risk_level(prob)
            
            results.append({
                "cve_id": cve_id,
                "exploit_probability": round(prob, 4),
                "risk_level": rl,
                "attack_vector": av,
                "cvss_score": cve_doc.get("cvssv3", {}).get("score", 0)
            })
            
            successful += 1
            risk_stats[rl] += 1
            av_stats[av] = av_stats.get(av, 0) + 1
            
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
            "failed": failed,
            "by_risk_level": risk_stats,
            "by_attack_vector": av_stats
        },
        "model": {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "calibrated": MODEL_CALIBRATED
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
    - attack_vector: filtrar por AV (network, local, adjacent)
    
    Ejemplo: GET /api/v1/ia/top-risk?limit=20&min_cvss=7.0&attack_vector=network
    """
    if not IA_READY:
        return jsonify({"error": "IA service not available"}), 503
    
    try:
        limit = min(int(request.args.get("limit", 10)), 50)
        min_cvss = float(request.args.get("min_cvss", 0))
        filter_av = request.args.get("attack_vector", "").upper()
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
            # Filtrar por Attack Vector si se especifica
            av = detect_attack_vector(cve)
            if filter_av and av != filter_av:
                continue
            
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            
            predictions.append({
                "cve_id": cve["cve_id"],
                "exploit_probability": round(prob, 4),
                "risk_level": risk_level(prob),
                "attack_vector": av,
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "tipo": cve.get("tipo", "unknown"),
                "infraestructura_5g": cve.get("infraestructura_5g_afectada", [])
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
            "attack_vector": filter_av if filter_av else "all",
            "limit": limit
        },
        "model": {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "calibrated": MODEL_CALIBRATED
        }
    }), 200


# ======================================================
#  ENDPOINT → Explicación detallada
# ======================================================
@bp_ia.route("/explain/<cve_id>", methods=["GET"])
def explain_prediction(cve_id):
    """
    Explica en detalle por qué un CVE fue clasificado de cierta manera
    
    GET /api/v1/ia/explain/CVE-2024-1234
    
    Respuesta:
    {
        "cve_id": "CVE-2024-1234",
        "explanation": "texto detallado...",
        "components": {
            "base_cvss": 7.8,
            "tipo_weight": 1.0,
            "attack_vector": "LOCAL",
            "final_score": 0.85
        }
    }
    """
    if not IA_READY:
        return jsonify({"error": "IA service not available"}), 503
    
    # Obtener CVE
    try:
        col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        cve_doc = col.find_one({"cve_id": cve_id})
        
        if not cve_doc:
            return jsonify({"error": "CVE not found"}), 404
    except Exception as e:
        return jsonify({"error": "Database error", "details": str(e)}), 500
    
    # Generar explicación
    try:
        from services.ia.smart_labeling import explain_label, calculate_exploit_score
        
        explanation_text = explain_label(cve_doc)
        score, metadata = calculate_exploit_score(cve_doc)
        
        return jsonify({
            "cve_id": cve_id,
            "explanation": explanation_text,
            "components": metadata,
            "model": {
                "name": MODEL_NAME,
                "version": MODEL_VERSION
            }
        }), 200
        
    except ImportError:
        return jsonify({
            "error": "Explanation not available",
            "details": "smart_labeling module not found"
        }), 501
    except Exception as e:
        logger.error(f"Error generating explanation: {e}")
        return jsonify({
            "error": "Explanation generation failed",
            "details": str(e)
        }), 500


# ======================================================
#  ENDPOINT → Estadísticas agregadas
# ======================================================
@bp_ia.route("/stats", methods=["GET"])
def get_statistics():
    """
    Estadísticas agregadas del dataset completo
    
    GET /api/v1/ia/stats
    
    Respuesta:
    {
        "total_cves": 331,
        "by_risk_level": {
            "CRITICAL": 214,
            "HIGH": 9,
            "MEDIUM": 7,
            "LOW": 101
        },
        "by_attack_vector": {
            "NETWORK": 251,
            "LOCAL": 76,
            "ADJACENT": 4
        },
        "critical_by_component": {
            "Core": 150,
            "RAN": 30
        }
    }
    """
    if not IA_READY:
        return jsonify({"error": "IA service not available"}), 503
    
    try:
        col = current_app.mongo.db[os.getenv("MONGO_COLLECTION", "vulnerabilidades")]
        cves = list(col.find({"cvssv3.score": {"$exists": True}}))
        
        # Estadísticas
        risk_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        av_stats = {}
        component_critical = {}
        
        for cve in cves:
            try:
                raw = featurizer.extract_raw_features(cve)
                X = featurizer.transform([raw])
                prob = float(model.predict_proba(X)[0][1])
                
                rl = risk_level(prob)
                av = detect_attack_vector(cve)
                
                risk_stats[rl] += 1
                av_stats[av] = av_stats.get(av, 0) + 1
                
                # Componentes críticos
                if rl == "CRITICAL":
                    infra = cve.get("infraestructura_5g_afectada", [])
                    for comp in infra:
                        component_critical[comp] = component_critical.get(comp, 0) + 1
                
            except:
                continue
        
        return jsonify({
            "total_cves": len(cves),
            "by_risk_level": risk_stats,
            "by_attack_vector": av_stats,
            "critical_by_component": component_critical,
            "model": {
                "name": MODEL_NAME,
                "version": MODEL_VERSION
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating stats: {e}")
        return jsonify({"error": str(e)}), 500