"""
==============================================================
    RE-TRAIN MODEL WITH SMART LABELING
    Versión 2.0 - Context-Aware Training
==============================================================

Entrena un nuevo modelo usando Smart Labeling y compara
con el modelo anterior para validar mejoras.
==============================================================
"""

import os
import sys
import numpy as np
import pandas as pd
from pymongo import MongoClient
from joblib import dump, load
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_curve, roc_auc_score,
    average_precision_score
)

sys.path.append('/app/ia')
from featurizer import Featurizer
from smart_labeling import smart_label_batch


# Configuración MongoDB
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_HOST = os.getenv("MONGO_HOST", "vulndb_mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB   = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}?authSource={MONGO_AUTH}"

# Paths
OUTPUT_DIR = "/app/ia/models"
MODEL_V1_PATH = os.path.join(OUTPUT_DIR, "exploit_model.joblib")
FEAT_V1_PATH = os.path.join(OUTPUT_DIR, "featurizer.joblib")
MODEL_V2_PATH = os.path.join(OUTPUT_DIR, "exploit_model_v2.joblib")
FEAT_V2_PATH = os.path.join(OUTPUT_DIR, "featurizer_v2.joblib")


def load_cves():
    """Carga CVEs desde MongoDB"""
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    client.close()
    
    return cves


def build_raw_features(cves, featurizer):
    """Extrae features crudas de los CVEs"""
    raw_list = []
    for cve in cves:
        try:
            raw = featurizer.extract_raw_features(cve)
            raw_list.append(raw)
        except Exception as e:
            print(f"[!] Error procesando {cve.get('cve_id', 'unknown')}: {e}")
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


def compare_models(X_test, y_test, model_v1, model_v2, featurizer_v1, featurizer_v2):
    """
    Compara el rendimiento de ambos modelos.
    """
    print("\n" + "="*70)
    print("  📊 COMPARACIÓN V1 vs V2")
    print("="*70 + "\n")
    
    # Predicciones V1
    y_pred_v1 = model_v1.predict(X_test)
    y_proba_v1 = model_v1.predict_proba(X_test)[:, 1]
    
    # Predicciones V2
    y_pred_v2 = model_v2.predict(X_test)
    y_proba_v2 = model_v2.predict_proba(X_test)[:, 1]
    
    # Métricas V1
    print("📊 MODELO V1 (Original):")
    print(classification_report(y_test, y_pred_v1, target_names=['No Explotable', 'Explotable']))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba_v1):.4f}")
    print(f"AP Score: {average_precision_score(y_test, y_proba_v1):.4f}")
    
    print("\n" + "-"*70 + "\n")
    
    # Métricas V2
    print("📊 MODELO V2 (Smart Labels):")
    print(classification_report(y_test, y_pred_v2, target_names=['No Explotable', 'Explotable']))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba_v2):.4f}")
    print(f"AP Score: {average_precision_score(y_test, y_proba_v2):.4f}")
    
    # Comparación directa
    auc_v1 = roc_auc_score(y_test, y_proba_v1)
    auc_v2 = roc_auc_score(y_test, y_proba_v2)
    
    print("\n📈 MEJORA:")
    print(f"   ROC-AUC: {auc_v1:.4f} → {auc_v2:.4f} ({(auc_v2-auc_v1)*100:+.2f}%)")
    
    if auc_v2 > auc_v1:
        print("   ✅ V2 es MEJOR que V1")
        return True
    else:
        print("   ⚠️  V2 NO superó a V1")
        return False


def main():
    print("\n" + "="*70)
    print("  🚀 RE-TRAINING WITH SMART LABELING (V2)")
    print("="*70 + "\n")
    
    # 1. Cargar datos
    print("[1/6] Cargando CVEs desde MongoDB...")
    cves = load_cves()
    print(f"      ✅ {len(cves)} CVEs cargados")
    
    if len(cves) < 50:
        print("\n❌ ERROR: Se necesitan al menos 50 CVEs para entrenar")
        sys.exit(1)
    
    # 2. Generar labels con Smart Labeling
    print("\n[2/6] Generando labels con Smart Labeling...")
    y = smart_label_batch(cves, verbose=True)
    
    if sum(y) == 0:
        print("\n❌ ERROR: No hay CVEs etiquetados como explotables")
        print("   Revisa los thresholds en smart_labeling.py")
        sys.exit(1)
    
    # 3. Extraer features
    print("[3/6] Extrayendo features...")
    F = Featurizer()
    raw_feature_list = build_raw_features(cves, F)
    
    print("      Ajustando featurizer (TF-IDF, OneHot, Scaler)...")
    F.fit(raw_feature_list)
    
    print("      Transformando features...")
    X = F.transform(raw_feature_list)
    print(f"      ✅ Matriz: {X.shape}")
    
    # 4. Split train/test
    print("\n[4/6] Split train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42,
        stratify=y if sum(y) > 5 else None
    )
    
    print(f"      Train: {X_train.shape[0]} | Test: {X_test.shape[0]}")
    print(f"      Positivos train: {sum(y_train)} ({sum(y_train)/len(y_train)*100:.1f}%)")
    print(f"      Positivos test:  {sum(y_test)} ({sum(y_test)/len(y_test)*100:.1f}%)")
    
    # 5. Entrenar XGBoost V2
    print("\n[5/6] Entrenando XGBoost V2...")
    
    n_neg = len([i for i in y_train if i == 0])
    n_pos = len([i for i in y_train if i == 1])
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1
    
    print(f"      scale_pos_weight: {scale_pos_weight:.2f}")
    
    model_v2 = XGBClassifier(
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
    
    model_v2.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )
    
    print("      ✅ Modelo V2 entrenado")
    
    # 6. Evaluar y comparar
    print("\n[6/6] Evaluando modelo V2...")
    y_pred = model_v2.predict(X_test)
    y_proba = model_v2.predict_proba(X_test)[:, 1]
    
    print("\n📊 RESULTADOS V2 (Test Set):")
    print(confusion_matrix(y_test, y_pred))
    print("\n" + classification_report(y_test, y_pred, target_names=['No Explotable', 'Explotable']))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")
    print(f"AP Score: {average_precision_score(y_test, y_proba):.4f}")
    
    # Comparar con V1 si existe
    if os.path.exists(MODEL_V1_PATH) and os.path.exists(FEAT_V1_PATH):
        print("\n🔄 Comparando con modelo V1...")
        try:
            model_v1 = load(MODEL_V1_PATH)
            featurizer_v1 = Featurizer.load(FEAT_V1_PATH)
            
            # Re-extraer features con featurizer v1 para comparación justa
            raw_v1 = build_raw_features(cves, featurizer_v1)
            X_v1 = featurizer_v1.transform(raw_v1)
            X_train_v1, X_test_v1, _, _ = train_test_split(
                X_v1, y, test_size=0.2, random_state=42,
                stratify=y if sum(y) > 5 else None
            )
            
            v2_is_better = compare_models(X_test_v1, y_test, model_v1, model_v2, featurizer_v1, F)
            
        except Exception as e:
            print(f"   ⚠️  No se pudo comparar con V1: {e}")
            v2_is_better = True
    else:
        print("\n   ℹ️  No existe modelo V1 para comparar")
        v2_is_better = True
    
    # 7. Guardar modelo V2
    print("\n💾 Guardando modelo V2...")
    F.save(FEAT_V2_PATH)
    dump(model_v2, MODEL_V2_PATH)
    
    print(f"   ✅ Featurizer V2: {FEAT_V2_PATH}")
    print(f"   ✅ Modelo V2:     {MODEL_V2_PATH}")
    
    # Recomendación
    if v2_is_better:
        print("\n✅ RECOMENDACIÓN: Usar modelo V2")
        print("   Puedes calibrarlo con:")
        print("   python calibrate_exploit_model.py --version v2")
    else:
        print("\n⚠️  ADVERTENCIA: V2 no superó a V1")
        print("   Revisa los thresholds o la configuración del modelo")
    
    print("\n" + "="*70)
    print("  ✅ RE-ENTRENAMIENTO COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()