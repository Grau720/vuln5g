import sys
import os
import pandas as pd

from pymongo import MongoClient
from joblib import dump
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from featurizer import Featurizer


"""
==============================================================
    TRAIN EXPLOITABILITY MODEL — Versión 1.2
    
    NUEVO: Soporta Smart Labeling (--smart-labels)
==============================================================
"""

# Configuración MongoDB
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

OUTPUT_DIR = "/app/ia/models"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_cves_from_mongo():
    """Carga CVEs desde MongoDB."""
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]

    cursor = col.find({"cvssv3.score": {"$exists": True}})

    cves = list(cursor)
    print(f"[+] CVEs cargadas desde Mongo: {len(cves)}")
    client.close()
    return cves


def build_labels_original(cves):
    """
    Etiquetado original (heurístico mejorado).
    Mantiene compatibilidad con versiones anteriores.
    """
    y = []

    dangerous_keywords = [
        'remote code execution', 'rce', 'unauthenticated',
        'memory corruption', 'buffer overflow', 'use after free',
        'arbitrary code', 'root privilege', 'privilege escalation',
        'sql injection', 'command injection', 'path traversal',
        'cross-site scripting', 'xss', 'csrf', 'authentication bypass'
    ]

    critical_types = [
        'ejecución remota',
        'ejecución de código',
        'escalada de privilegios',
        'inyección de comandos',
        'inyección sql'
    ]

    critical_components = [
        'kernel', 'openssh', 'apache', 'nginx', 'mysql',
        'postgresql', 'wordpress', 'drupal', 'windows'
    ]

    for cve in cves:
        cvss = cve.get("cvssv3") or {}
        cvss_score = cvss.get("score") or 0
        vector = cvss.get("vector") or ""

        referencias = cve.get("referencias_mitre") or []
        has_exploit_refs = any(
            isinstance(ref, str) and (
                'exploit' in ref.lower() or 'poc' in ref.lower()
            )
            for ref in referencias
        )

        is_network = "AV:N" in vector
        is_low_complexity = "AC:L" in vector
        no_priv = "PR:N" in vector
        no_ui = "UI:N" in vector

        tipo = (cve.get("tipo") or "").lower()
        is_critical_type = any(ct in tipo for ct in critical_types)

        desc = (
            (cve.get("descripcion_tecnica") or "") + " " +
            (cve.get("descripcion_general") or "")
        ).lower()
        has_dangerous_keywords = any(kw in desc for kw in dangerous_keywords)

        componente = (cve.get("componente_afectado") or "").lower()
        is_critical_component = any(cc in componente for cc in critical_components)

        score = 0

        if has_exploit_refs:
            score += 100

        if cvss_score >= 9.0:
            score += 50

        if cvss_score >= 7.0:
            if is_network:
                score += 20
            if is_low_complexity:
                score += 10
            if no_priv:
                score += 5
            if no_ui:
                score += 5

        if cvss_score >= 6.0 and is_network and is_low_complexity:
            score += 30

        if is_critical_type:
            score += 25

        if has_dangerous_keywords:
            score += 20

        if is_critical_component:
            score += 15

        y.append(1 if score >= 40 else 0)

    return y


def build_labels_smart(cves):
    """
    Etiquetado inteligente usando Smart Labeling.
    """
    try:
        from smart_labeling import smart_label_batch
        return smart_label_batch(cves, verbose=True)
    except ImportError:
        print("[!] ADVERTENCIA: smart_labeling.py no encontrado")
        print("    Usando método original como fallback")
        return build_labels_original(cves)


def build_raw_features(cves, featurizer):
    """Extrae features crudas de los CVEs."""
    raw_list = []
    for cve in cves:
        try:
            raw = featurizer.extract_raw_features(cve)
            raw_list.append(raw)
        except Exception as e:
            print(f"[!] Error procesando CVE {cve.get('cve_id', 'unknown')}: {e}")
            raw_list.append({
                "cvss_base_score": 0.0,
                "attackVector": "UNKNOWN",
                "attackComplexity": "UNKNOWN",
                "privilegesRequired": "UNKNOWN",
                "userInteraction": "UNKNOWN",
                "scope": "UNKNOWN",
                "confidentialityImpact": 0.0,
                "integrityImpact": 0.0,
                "availabilityImpact": 0.0,
                "cwe": "CWE-UNKNOWN",
                "text": ""
            })
    return raw_list


def train_model():
    print("\n==============================================")
    print("    EPSS-LIKE MODEL TRAINING (v1.2)")
    print("==============================================\n")
    
    # Detectar modo smart labels
    use_smart_labels = '--smart-labels' in sys.argv or '-s' in sys.argv
    
    if use_smart_labels:
        print("🧠 MODO: Smart Labeling (Context-Aware)")
    else:
        print("📋 MODO: Original Heuristic")
    
    print()

    cves = load_cves_from_mongo()
    if len(cves) < 50:
        print("[!] Muy pocos datos para entrenar. Se necesitan al menos 50 CVEs.")
        sys.exit(1)

    # Crear labels según modo
    if use_smart_labels:
        print("[+] Generando labels con Smart Labeling...")
        y = build_labels_smart(cves)
    else:
        y = build_labels_original(cves)
    
    print(f"[+] CVEs explotables (1): {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
    print(f"[+] CVEs no explotables (0): {len(y) - sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")
    
    if sum(y) == 0:
        print("[!] ADVERTENCIA: No hay CVEs etiquetados como explotables.")
        print("[!] El modelo no aprenderá correctamente.")

    # Crear y ajustar featurizer
    F = Featurizer()

    print("[+] Extrayendo features...")
    raw_feature_list = build_raw_features(cves, F)

    print("[+] Ajustando featurizer (TF-IDF, OneHot, Scaler)...")
    F.fit(raw_feature_list)

    print("[+] Transformando features...")
    X = F.transform(raw_feature_list)

    print(f"[+] Matriz de features: {X.shape}")

    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if sum(y) > 5 else None
    )

    # Entrenar XGBoost
    print("[+] Entrenando XGBoost...")
    
    n_neg = len([i for i in y_train if i == 0])
    n_pos = len([i for i in y_train if i == 1])
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1
    
    print(f"    scale_pos_weight: {scale_pos_weight:.2f}")
    
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        objective="binary:logistic",
        base_score=0.5,
        scale_pos_weight=scale_pos_weight,
        random_state=42
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    # Evaluar modelo
    print("\n[+] Evaluación del modelo:")
    y_pred = model.predict(X_test)
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['No Explotable', 'Explotable']))

    # Guardar modelos
    suffix = "_smart" if use_smart_labels else ""
    FEATURIZER_PATH = os.path.join(OUTPUT_DIR, f"featurizer{suffix}.joblib")
    MODEL_PATH = os.path.join(OUTPUT_DIR, f"exploit_model{suffix}.joblib")

    F.save(FEATURIZER_PATH)
    dump(model, MODEL_PATH)

    print(f"\n[✔] Featurizer guardado: {FEATURIZER_PATH}")
    print(f"[✔] Modelo guardado: {MODEL_PATH}")
    
    if use_smart_labels:
        print("\n💡 PRÓXIMO PASO: Calibrar el modelo")
        print("   python calibrate_exploit_model.py --smart")
    
    print("\n[OK] Entrenamiento completado.\n")


if __name__ == "__main__":
    train_model()