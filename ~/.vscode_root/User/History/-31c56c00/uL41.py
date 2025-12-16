import os
import sys
import numpy as np
from pymongo import MongoClient
from joblib import load, dump

from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import brier_score_loss

from featurizer import Featurizer


"""
==============================================================
    CALIBRATE EXPLOITABILITY MODEL — v1.0
==============================================================

Objetivo:
- Calibrar las probabilidades del modelo XGBoost
- Usar Cross-Validation (5-fold)
- Obtener probabilidades fiables (tipo EPSS)

Salida:
- exploit_model_calibrated.joblib
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
MODEL_PATH = "/app/ia/models/exploit_model.joblib"
FEAT_PATH  = "/app/ia/models/featurizer.joblib"
OUTPUT_PATH = "/app/ia/models/exploit_model_calibrated.joblib"


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
        raise RuntimeError("Muy pocos CVEs para calibración")

    return cves


# -------------------------------
# Reproducir etiquetas (MISMA lógica)
# -------------------------------
def build_labels(cves):
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
# MAIN
# -------------------------------
def main():
    print("\n==============================================")
    print("  🔧 CALIBRATING EXPLOITABILITY MODEL (5-FOLD)")
    print("==============================================\n")

    print("[+] Cargando datos...")
    cves = load_data()

    print("[+] Cargando modelo y featurizer...")
    model = load(MODEL_PATH)
    featurizer = Featurizer.load(FEAT_PATH)

    print("[+] Extrayendo features...")
    raw = [featurizer.extract_raw_features(c) for c in cves]
    X = featurizer.transform(raw)
    y = build_labels(cves)

    print(f"[+] Dataset: {X.shape} | Positivos: {y.sum()}")

    if y.sum() == 0 or y.sum() == len(y):
        raise RuntimeError("No se puede calibrar con una sola clase")

    # -------------------------------
    # Calibración (SIGMOID = robusto)
    # -------------------------------
    print("[+] Calibrando modelo (Platt scaling, 5-fold)...")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    calibrated = CalibratedClassifierCV(
        estimator=model,
        method="sigmoid",
        cv=cv
    )

    calibrated.fit(X, y)

    # -------------------------------
    # Métrica de calidad
    # -------------------------------
    probs = calibrated.predict_proba(X)[:, 1]
    brier = brier_score_loss(y, probs)

    print(f"[✔] Brier score (↓ mejor): {brier:.4f}")

    # -------------------------------
    # Guardar modelo calibrado
    # -------------------------------
    dump(calibrated, OUTPUT_PATH)

    print(f"\n[✔] Modelo calibrado guardado en:")
    print(f"    {OUTPUT_PATH}")
    print("\n[OK] Calibración completada.\n")


if __name__ == "__main__":
    main()
