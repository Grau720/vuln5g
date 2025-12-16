import os
import sys
import numpy as np
from pymongo import MongoClient
from joblib import load, dump

from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import brier_score_loss

sys.path.append('/app/ia')
from featurizer import Featurizer
from smart_labeling import smart_label_batch


"""
==============================================================
    CALIBRATE EXPLOITABILITY MODEL — v1.1
==============================================================

NUEVO: Soporta calibración de V1 y V2

Uso:
    python calibrate_exploit_model.py           # V1 (por defecto)
    python calibrate_exploit_model.py --v2      # V2
    python calibrate_exploit_model.py --smart   # V2 (alias)
==============================================================
"""

# -------------------------------
# Configuración MongoDB
# -------------------------------
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_HOST = os.getenv("MONGO_HOST", "vulndb_mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB   = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

MONGO_URI = (
    f"mongodb://{MONGO_USER}:{MONGO_PASS}@"
    f"{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}?authSource={MONGO_AUTH}"
)

# -------------------------------
# Paths
# -------------------------------
MODELS_DIR = "/app/ia/models"

# V1
MODEL_V1_PATH = os.path.join(MODELS_DIR, "exploit_model.joblib")
FEAT_V1_PATH = os.path.join(MODELS_DIR, "featurizer.joblib")
OUTPUT_V1_PATH = os.path.join(MODELS_DIR, "exploit_model_calibrated.joblib")

# V2
MODEL_V2_PATH = os.path.join(MODELS_DIR, "exploit_model_v2.joblib")
FEAT_V2_PATH = os.path.join(MODELS_DIR, "featurizer_v2.joblib")
OUTPUT_V2_PATH = os.path.join(MODELS_DIR, "exploit_model_v2_calibrated.joblib")


# -------------------------------
# Cargar datos
# -------------------------------
def load_data():
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]

    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    client.close()

    if len(cves) < 100:
        raise RuntimeError("Muy pocos CVEs para calibración (mínimo: 100)")

    return cves


# -------------------------------
# Etiquetado V1 (Original)
# -------------------------------
def build_labels_v1(cves):
    """Reproduce el etiquetado heurístico original"""
    y = []

    for cve in cves:
        cvss = cve.get("cvssv3", {})
        score = cvss.get("score", 0)
        vector = cvss.get("vector", "")

        has_exploit = any(
            "exploit" in r.lower() or "poc" in r.lower()
            for r in (cve.get("referencias_mitre") or [])
        )

        is_network = "AV:N" in vector
        is_low = "AC:L" in vector
        no_priv = "PR:N" in vector
        no_ui = "UI:N" in vector

        if has_exploit:
            y.append(1)
        elif score >= 7.0 and is_network and is_low and (no_priv or no_ui):
            y.append(1)
        elif score >= 9.0:
            y.append(1)
        else:
            y.append(0)

    return np.array(y)


# -------------------------------
# Etiquetado V2 (Smart Labeling)
# -------------------------------
def build_labels_v2(cves):
    """Usa Smart Labeling para etiquetas"""
    try:
        return np.array(smart_label_batch(cves, verbose=False))
    except ImportError:
        print("[!] ADVERTENCIA: smart_labeling.py no encontrado")
        print("    Usando método V1 como fallback")
        return build_labels_v1(cves)


# -------------------------------
# MAIN
# -------------------------------
def main():
    # Detectar versión a calibrar
    use_v2 = '--v2' in sys.argv or '--smart' in sys.argv or '--version=v2' in sys.argv
    
    if use_v2:
        print("\n==============================================")
        print("  🔧 CALIBRATING MODEL V2 (Smart Labels)")
        print("==============================================\n")
        
        MODEL_PATH = MODEL_V2_PATH
        FEAT_PATH = FEAT_V2_PATH
        OUTPUT_PATH = OUTPUT_V2_PATH
        build_labels_fn = build_labels_v2
        version_name = "V2"
    else:
        print("\n==============================================")
        print("  🔧 CALIBRATING MODEL V1 (Original)")
        print("==============================================\n")
        
        MODEL_PATH = MODEL_V1_PATH
        FEAT_PATH = FEAT_V1_PATH
        OUTPUT_PATH = OUTPUT_V1_PATH
        build_labels_fn = build_labels_v1
        version_name = "V1"

    # Verificar que existan los archivos
    if not os.path.exists(MODEL_PATH):
        print(f"❌ ERROR: Modelo {version_name} no encontrado en:")
        print(f"   {MODEL_PATH}")
        print(f"\n💡 Debes entrenar el modelo primero:")
        if use_v2:
            print("   python services/ia/retrain_with_smart_labels.py")
        else:
            print("   python services/ia/train_exploit_model.py")
        sys.exit(1)
    
    if not os.path.exists(FEAT_PATH):
        print(f"❌ ERROR: Featurizer {version_name} no encontrado en:")
        print(f"   {FEAT_PATH}")
        sys.exit(1)

    # Cargar datos
    print("[1/5] Cargando CVEs desde MongoDB...")
    cves = load_data()
    print(f"      ✅ {len(cves)} CVEs cargados")

    # Cargar modelo
    print(f"\n[2/5] Cargando modelo {version_name}...")
    model = load(MODEL_PATH)
    featurizer = Featurizer.load(FEAT_PATH)
    print("      ✅ Modelo y featurizer cargados")

    # Extraer features
    print("\n[3/5] Extrayendo features...")
    raw = [featurizer.extract_raw_features(c) for c in cves]
    X = featurizer.transform(raw)
    print(f"      ✅ Matriz: {X.shape}")

    # Generar labels
    print(f"\n[4/5] Generando labels ({version_name})...")
    y = build_labels_fn(cves)
    
    positivos = y.sum()
    negativos = len(y) - positivos
    
    print(f"      ✅ Positivos: {positivos} ({positivos/len(y)*100:.1f}%)")
    print(f"      ✅ Negativos: {negativos} ({negativos/len(y)*100:.1f}%)")

    if positivos == 0 or positivos == len(y):
        print("\n❌ ERROR: No se puede calibrar con una sola clase")
        sys.exit(1)

    # Calibración
    print("\n[5/5] Calibrando modelo (Platt scaling, 5-fold)...")
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    calibrated = CalibratedClassifierCV(
        estimator=model,
        method="sigmoid",
        cv=cv
    )

    calibrated.fit(X, y)

    # Métrica de calidad
    probs = calibrated.predict_proba(X)[:, 1]
    brier = brier_score_loss(y, probs)

    print(f"\n📊 MÉTRICAS DE CALIBRACIÓN:")
    print(f"   Brier score: {brier:.4f} (↓ mejor, 0 = perfecto)")
    
    if brier < 0.1:
        print("   ✅ Excelente calibración")
    elif brier < 0.2:
        print("   ✅ Buena calibración")
    else:
        print("   ⚠️  Calibración mejorable")

    # Guardar
    dump(calibrated, OUTPUT_PATH)

    print(f"\n💾 MODELO CALIBRADO GUARDADO:")
    print(f"   {OUTPUT_PATH}")
    
    print(f"\n✅ CALIBRACIÓN {version_name} COMPLETADA\n")
    
    # Sugerencia de uso
    if use_v2:
        print("💡 PRÓXIMO PASO:")
        print("   python ia/run_predict.py --top 20")
        print("   (usará automáticamente el modelo V2 calibrado)")


if __name__ == "__main__":
    main()