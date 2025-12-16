"""
==============================================================
    CALIBRATE EXPLOITABILITY MODEL v2.1
==============================================================

Soporta calibración de V1, V2.0 y V2.1

Uso:
    python calibrate_exploit_model.py              # V1 (por defecto)
    python calibrate_exploit_model.py --v2         # V2.0
    python calibrate_exploit_model.py --v21        # V2.1 (nuevo)

Guarda como: /app/ia/calibrate_exploit_model.py (reemplazar)
==============================================================
"""

import os
import sys
import numpy as np
from pymongo import MongoClient
from joblib import load, dump

from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import brier_score_loss, log_loss

sys.path.append('/app/ia')
from featurizer import Featurizer
from smart_labeling import smart_label_batch


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

# V2.0
MODEL_V2_PATH = os.path.join(MODELS_DIR, "exploit_model_v2.joblib")
FEAT_V2_PATH = os.path.join(MODELS_DIR, "featurizer_v2.joblib")
OUTPUT_V2_PATH = os.path.join(MODELS_DIR, "exploit_model_v2_calibrated.joblib")

# V2.1
MODEL_V21_PATH = os.path.join(MODELS_DIR, "exploit_model_v2.1.joblib")
FEAT_V21_PATH = os.path.join(MODELS_DIR, "featurizer_v2.1.joblib")
OUTPUT_V21_PATH = os.path.join(MODELS_DIR, "exploit_model_v2.1_calibrated.joblib")


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
# Etiquetado V2.x (Smart Labeling)
# -------------------------------
def build_labels_v2(cves):
    """Usa Smart Labeling actual (v2.0 o v2.1)"""
    try:
        return np.array(smart_label_batch(cves, verbose=False))
    except ImportError:
        print("[!] ADVERTENCIA: smart_labeling.py no encontrado")
        print("    Usando método V1 como fallback")
        return build_labels_v1(cves)


# -------------------------------
# Análisis de calibración
# -------------------------------
def analyze_calibration(y_true, y_proba_before, y_proba_after, version_name):
    """
    Compara las probabilidades antes y después de calibrar
    """
    print(f"\n📊 ANÁLISIS DE CALIBRACIÓN ({version_name}):")
    print("="*70)
    
    # Antes de calibrar
    brier_before = brier_score_loss(y_true, y_proba_before)
    logloss_before = log_loss(y_true, y_proba_before)
    
    # Después de calibrar
    brier_after = brier_score_loss(y_true, y_proba_after)
    logloss_after = log_loss(y_true, y_proba_after)
    
    print(f"\n📈 MÉTRICAS ANTES DE CALIBRAR:")
    print(f"   Brier Score: {brier_before:.4f}")
    print(f"   Log Loss:    {logloss_before:.4f}")
    
    print(f"\n📈 MÉTRICAS DESPUÉS DE CALIBRAR:")
    print(f"   Brier Score: {brier_after:.4f} ({(brier_after-brier_before)*100:+.2f}%)")
    print(f"   Log Loss:    {logloss_after:.4f} ({(logloss_after-logloss_before)*100:+.2f}%)")
    
    # Interpretación
    print(f"\n💡 INTERPRETACIÓN:")
    if brier_after < brier_before:
        mejora = (brier_before - brier_after) / brier_before * 100
        print(f"   ✅ Calibración mejoró el Brier Score en {mejora:.1f}%")
    else:
        print(f"   ⚠️  Calibración no mejoró significativamente")
    
    if brier_after < 0.1:
        print("   ✅ Excelente calibración (Brier < 0.1)")
    elif brier_after < 0.2:
        print("   ✅ Buena calibración (Brier < 0.2)")
    else:
        print("   ⚠️  Calibración mejorable (Brier ≥ 0.2)")
    
    # Análisis de bins de probabilidad
    print(f"\n📊 DISTRIBUCIÓN DE PROBABILIDADES (después de calibrar):")
    bins = [0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]
    bin_names = ["<10%", "10-30%", "30-50%", "50-70%", "70-90%", ">90%"]
    
    for i in range(len(bins)-1):
        mask = (y_proba_after >= bins[i]) & (y_proba_after < bins[i+1])
        n_in_bin = mask.sum()
        if n_in_bin > 0:
            actual_rate = y_true[mask].mean()
            avg_pred = y_proba_after[mask].mean()
            print(f"   {bin_names[i]:10s}: {n_in_bin:4d} CVEs | Pred: {avg_pred:.2%} | Real: {actual_rate:.2%}")


# -------------------------------
# MAIN
# -------------------------------
def main():
    # Detectar versión a calibrar
    use_v21 = '--v21' in sys.argv or '--v2.1' in sys.argv
    use_v2 = '--v2' in sys.argv or '--smart' in sys.argv or '--version=v2' in sys.argv
    
    if use_v21:
        print("\n==============================================")
        print("  🔧 CALIBRATING MODEL V2.1")
        print("  (Attack Vector Aware)")
        print("==============================================\n")
        
        MODEL_PATH = MODEL_V21_PATH
        FEAT_PATH = FEAT_V21_PATH
        OUTPUT_PATH = OUTPUT_V21_PATH
        build_labels_fn = build_labels_v2
        version_name = "V2.1"
    elif use_v2:
        print("\n==============================================")
        print("  🔧 CALIBRATING MODEL V2.0")
        print("  (Smart Labels)")
        print("==============================================\n")
        
        MODEL_PATH = MODEL_V2_PATH
        FEAT_PATH = FEAT_V2_PATH
        OUTPUT_PATH = OUTPUT_V2_PATH
        build_labels_fn = build_labels_v2
        version_name = "V2.0"
    else:
        print("\n==============================================")
        print("  🔧 CALIBRATING MODEL V1")
        print("  (Original)")
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
        if use_v21:
            print("   python /app/ia/retrain_with_smart_labels_v21.py")
        elif use_v2:
            print("   python /app/ia/retrain_with_smart_labels.py")
        else:
            print("   python /app/ia/train_exploit_model.py")
        sys.exit(1)
    
    if not os.path.exists(FEAT_PATH):
        print(f"❌ ERROR: Featurizer {version_name} no encontrado en:")
        print(f"   {FEAT_PATH}")
        sys.exit(1)

    # Cargar datos
    print("[1/6] Cargando CVEs desde MongoDB...")
    cves = load_data()
    print(f"      ✅ {len(cves)} CVEs cargados")

    # Cargar modelo
    print(f"\n[2/6] Cargando modelo {version_name}...")
    model = load(MODEL_PATH)
    featurizer = Featurizer.load(FEAT_PATH)
    print("      ✅ Modelo y featurizer cargados")

    # Extraer features
    print("\n[3/6] Extrayendo features...")
    raw = [featurizer.extract_raw_features(c) for c in cves]
    X = featurizer.transform(raw)
    print(f"      ✅ Matriz: {X.shape}")

    # Generar labels
    print(f"\n[4/6] Generando labels ({version_name})...")
    y = build_labels_fn(cves)
    
    positivos = y.sum()
    negativos = len(y) - positivos
    
    print(f"      ✅ Positivos: {positivos} ({positivos/len(y)*100:.1f}%)")
    print(f"      ✅ Negativos: {negativos} ({negativos/len(y)*100:.1f}%)")

    if positivos == 0 or positivos == len(y):
        print("\n❌ ERROR: No se puede calibrar con una sola clase")
        sys.exit(1)

    # Probabilidades antes de calibrar
    print("\n[5/6] Obteniendo probabilidades pre-calibración...")
    y_proba_before = model.predict_proba(X)[:, 1]

    # Calibración
    print("\n[6/6] Calibrando modelo (Platt scaling, 5-fold)...")
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    calibrated = CalibratedClassifierCV(
        estimator=model,
        method="sigmoid",
        cv=cv
    )

    calibrated.fit(X, y)
    
    # Probabilidades después de calibrar
    y_proba_after = calibrated.predict_proba(X)[:, 1]

    # Análisis detallado
    analyze_calibration(y, y_proba_before, y_proba_after, version_name)

    # Guardar
    dump(calibrated, OUTPUT_PATH)

    print(f"\n💾 MODELO CALIBRADO GUARDADO:")
    print(f"   {OUTPUT_PATH}")
    
    print(f"\n✅ CALIBRACIÓN {version_name} COMPLETADA\n")
    
    # Sugerencia de uso
    if use_v21:
        print("💡 PRÓXIMO PASO:")
        print("   python /app/ia/run_predict.py --version v2.1 --top 20")
        print("   (usará automáticamente el modelo V2.1 calibrado)")
    elif use_v2:
        print("💡 PRÓXIMO PASO:")
        print("   python /app/ia/run_predict.py --version v2 --top 20")


if __name__ == "__main__":
    main()