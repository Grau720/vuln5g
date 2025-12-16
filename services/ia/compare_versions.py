"""
==============================================================
    COMPARE MODEL VERSIONS
    V1 vs V2.0 vs V2.1
==============================================================

Compara rendimiento de todas las versiones disponibles:
- V1: Etiquetado heurístico simple
- V2.0: Smart labeling con pesos fijos
- V2.1: Attack Vector aware thresholds

Guarda como: /app/ia/compare_versions.py
Uso: python /app/ia/compare_versions.py
==============================================================
"""

import os
import sys
import numpy as np
import pandas as pd
from pymongo import MongoClient
from joblib import load
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, average_precision_score,
    precision_score, recall_score, f1_score
)

sys.path.append('/app/ia')
from featurizer import Featurizer


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
MODELS_DIR = "/app/ia/models"

VERSIONS = {
    "V1": {
        "model": os.path.join(MODELS_DIR, "exploit_model.joblib"),
        "feat": os.path.join(MODELS_DIR, "featurizer.joblib"),
        "calibrated": os.path.join(MODELS_DIR, "exploit_model_calibrated.joblib"),
        "name": "V1 (Heurístico)",
        "color": "🔵"
    },
    "V2.0": {
        "model": os.path.join(MODELS_DIR, "exploit_model_v2.joblib"),
        "feat": os.path.join(MODELS_DIR, "featurizer_v2.joblib"),
        "calibrated": os.path.join(MODELS_DIR, "exploit_model_v2_calibrated.joblib"),
        "name": "V2.0 (Smart Labels)",
        "color": "🟢"
    },
    "V2.1": {
        "model": os.path.join(MODELS_DIR, "exploit_model_v2.1.joblib"),
        "feat": os.path.join(MODELS_DIR, "featurizer_v2.1.joblib"),
        "calibrated": os.path.join(MODELS_DIR, "exploit_model_v2.1_calibrated.joblib"),
        "name": "V2.1 (Attack Vector Aware)",
        "color": "🟡"
    }
}


def load_data():
    """Carga CVEs desde MongoDB"""
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    client.close()
    
    return cves


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


def build_labels_v2(cves):
    """Smart labeling (v2.1)"""
    try:
        from smart_labeling import smart_label_batch
        return np.array(smart_label_batch(cves, verbose=False))
    except:
        print("[!] ADVERTENCIA: Usando labels V1 como fallback")
        return build_labels_v1(cves)


def evaluate_model(model, featurizer, X, y_true, version_name):
    """
    Evalúa un modelo y retorna métricas
    """
    try:
        y_pred = model.predict(X)
        y_proba = model.predict_proba(X)[:, 1]
        
        metrics = {
            "version": version_name,
            "accuracy": (y_pred == y_true).mean(),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0),
            "roc_auc": roc_auc_score(y_true, y_proba),
            "ap_score": average_precision_score(y_true, y_proba),
        }
        
        return metrics, y_pred, y_proba
        
    except Exception as e:
        print(f"   ⚠️  Error evaluando {version_name}: {e}")
        return None, None, None


def analyze_by_attack_vector(cves, predictions_dict, y_true):
    """
    Analiza rendimiento por Attack Vector
    """
    print("\n" + "="*70)
    print("  🎯 ANÁLISIS POR ATTACK VECTOR")
    print("="*70 + "\n")
    
    # Clasificar CVEs por AV
    av_data = {"NETWORK": [], "LOCAL": [], "ADJACENT": [], "UNKNOWN": []}
    
    for i, cve in enumerate(cves):
        vector = cve.get("cvssv3", {}).get("vector", "")
        
        if "AV:N" in vector:
            av = "NETWORK"
        elif "AV:L" in vector:
            av = "LOCAL"
        elif "AV:A" in vector:
            av = "ADJACENT"
        else:
            av = "UNKNOWN"
        
        av_data[av].append({
            "idx": i,
            "cve_id": cve.get("cve_id"),
            "cvss": cve.get("cvssv3", {}).get("score", 0),
            "tipo": cve.get("tipo", "Desconocido"),
            "true_label": y_true[i]
        })
    
    # Calcular métricas por AV
    for av_name, av_cves in av_data.items():
        if len(av_cves) == 0:
            continue
        
        print(f"\n📊 {av_name} ({len(av_cves)} CVEs):")
        print("-" * 70)
        
        indices = [c["idx"] for c in av_cves]
        y_av_true = y_true[indices]
        
        # Tabla comparativa
        results = []
        for version, preds in predictions_dict.items():
            if preds is None:
                continue
            
            y_av_pred = preds[indices]
            
            if len(np.unique(y_av_true)) > 1:
                precision = precision_score(y_av_true, y_av_pred, zero_division=0)
                recall = recall_score(y_av_true, y_av_pred, zero_division=0)
                f1 = f1_score(y_av_true, y_av_pred, zero_division=0)
            else:
                precision = recall = f1 = 0.0
            
            results.append({
                "Version": version,
                "Precision": f"{precision:.3f}",
                "Recall": f"{recall:.3f}",
                "F1": f"{f1:.3f}",
                "TP": ((y_av_pred == 1) & (y_av_true == 1)).sum(),
                "FP": ((y_av_pred == 1) & (y_av_true == 0)).sum(),
                "FN": ((y_av_pred == 0) & (y_av_true == 1)).sum()
            })
        
        df = pd.DataFrame(results)
        print(df.to_string(index=False))


def analyze_by_tipo(cves, predictions_dict, y_true):
    """
    Analiza rendimiento por tipo de vulnerabilidad
    """
    print("\n" + "="*70)
    print("  🏷️  ANÁLISIS POR TIPO DE VULNERABILIDAD")
    print("="*70 + "\n")
    
    # Top 5 tipos más comunes
    from collections import Counter
    tipos = [cve.get("tipo", "Desconocido") for cve in cves]
    top_tipos = [t for t, _ in Counter(tipos).most_common(5)]
    
    for tipo in top_tipos:
        indices = [i for i, cve in enumerate(cves) if cve.get("tipo") == tipo]
        
        if len(indices) == 0:
            continue
        
        print(f"\n📊 {tipo} ({len(indices)} CVEs):")
        print("-" * 70)
        
        y_tipo_true = y_true[indices]
        
        results = []
        for version, preds in predictions_dict.items():
            if preds is None:
                continue
            
            y_tipo_pred = preds[indices]
            
            if len(np.unique(y_tipo_true)) > 1:
                precision = precision_score(y_tipo_true, y_tipo_pred, zero_division=0)
                recall = recall_score(y_tipo_true, y_tipo_pred, zero_division=0)
                f1 = f1_score(y_tipo_true, y_tipo_pred, zero_division=0)
            else:
                precision = recall = f1 = 0.0
            
            results.append({
                "Version": version,
                "Precision": f"{precision:.3f}",
                "Recall": f"{recall:.3f}",
                "F1": f"{f1:.3f}",
                "Explotables predichos": (y_tipo_pred == 1).sum()
            })
        
        df = pd.DataFrame(results)
        print(df.to_string(index=False))


def main():
    print("\n" + "="*70)
    print("  📊 COMPARACIÓN DE VERSIONES DE MODELO")
    print("  V1 vs V2.0 vs V2.1")
    print("="*70 + "\n")
    
    # 1. Cargar datos
    print("[1/4] Cargando CVEs desde MongoDB...")
    cves = load_data()
    print(f"      ✅ {len(cves)} CVEs cargados\n")
    
    # 2. Generar labels (usar V2.1 como referencia)
    print("[2/4] Generando labels de referencia (V2.1)...")
    y_true = build_labels_v2(cves)
    print(f"      ✅ Explotables: {y_true.sum()} ({y_true.sum()/len(y_true)*100:.1f}%)\n")
    
    # 3. Evaluar cada versión disponible
    print("[3/4] Evaluando modelos disponibles...")
    
    results = []
    predictions = {}
    available_versions = []
    
    for version_key, version_info in VERSIONS.items():
        model_path = version_info["model"]
        feat_path = version_info["feat"]
        calibrated_path = version_info["calibrated"]
        
        # Verificar si el modelo existe
        if not os.path.exists(model_path) or not os.path.exists(feat_path):
            print(f"   ⚠️  {version_info['name']}: No disponible")
            continue
        
        print(f"   {version_info['color']} Evaluando {version_info['name']}...")
        
        try:
            # Cargar modelo
            model = load(model_path)
            featurizer = Featurizer.load(feat_path)
            
            # Extraer features
            raw = [featurizer.extract_raw_features(c) for c in cves]
            X = featurizer.transform(raw)
            
            # Evaluar modelo sin calibrar
            metrics, y_pred, y_proba = evaluate_model(
                model, featurizer, X, y_true, 
                f"{version_key}"
            )
            
            if metrics:
                metrics["calibrated"] = "No"
                results.append(metrics)
                predictions[version_key] = y_pred
                available_versions.append(version_key)
            
            # Evaluar modelo calibrado si existe
            if os.path.exists(calibrated_path):
                calibrated = load(calibrated_path)
                metrics_cal, y_pred_cal, y_proba_cal = evaluate_model(
                    calibrated, featurizer, X, y_true,
                    f"{version_key} (calibrado)"
                )
                
                if metrics_cal:
                    metrics_cal["calibrated"] = "Sí"
                    results.append(metrics_cal)
            
        except Exception as e:
            print(f"      ❌ Error: {e}")
            continue
    
    print()
    
    # 4. Mostrar comparación
    print("[4/4] Generando reporte comparativo...\n")
    
    if len(results) == 0:
        print("❌ No hay modelos disponibles para comparar")
        print("\n💡 Entrena modelos primero:")
        print("   - V1: python /app/ia/train_exploit_model.py")
        print("   - V2.0: python /app/ia/retrain_with_smart_labels.py")
        print("   - V2.1: python /app/ia/retrain_with_smart_labels_v21.py")
        sys.exit(1)
    
    # Tabla general
    print("="*70)
    print("  📊 RESUMEN GENERAL")
    print("="*70 + "\n")
    
    df_results = pd.DataFrame(results)
    df_results = df_results.round(4)
    
    # Ordenar por F1 score
    df_results = df_results.sort_values("f1", ascending=False)
    
    print(df_results[["version", "calibrated", "precision", "recall", "f1", "roc_auc", "ap_score"]].to_string(index=False))
    
    # Mejor modelo
    best_idx = df_results["f1"].idxmax()
    best_model = df_results.iloc[best_idx]
    
    print(f"\n🏆 MEJOR MODELO: {best_model['version']}")
    print(f"   F1 Score: {best_model['f1']:.4f}")
    print(f"   ROC-AUC: {best_model['roc_auc']:.4f}")
    print(f"   Precisión: {best_model['precision']:.4f}")
    print(f"   Recall: {best_model['recall']:.4f}")
    
    # Análisis detallado por Attack Vector
    if len(available_versions) > 0:
        analyze_by_attack_vector(cves, predictions, y_true)
    
    # Análisis por tipo de vulnerabilidad
    if len(available_versions) > 0:
        analyze_by_tipo(cves, predictions, y_true)
    
    # Guardar reporte
    print("\n" + "="*70)
    print("  💾 GUARDANDO REPORTE")
    print("="*70 + "\n")
    
    output_file = "/app/ia/version_comparison.csv"
    df_results.to_csv(output_file, index=False)
    print(f"✅ Reporte guardado en: {output_file}")
    
    # Recomendaciones
    print("\n" + "="*70)
    print("  💡 RECOMENDACIONES")
    print("="*70 + "\n")
    
    if "V2.1" in available_versions:
        v21_metrics = df_results[df_results["version"].str.contains("V2.1")].iloc[0]
        
        if v21_metrics["f1"] > 0.7:
            print("✅ V2.1 tiene buen rendimiento general")
        
        if v21_metrics["precision"] > 0.75:
            print("✅ V2.1 tiene buena precisión (pocos falsos positivos)")
        else:
            print("⚠️  V2.1 tiene falsos positivos - considera subir thresholds")
        
        if v21_metrics["recall"] < 0.6:
            print("⚠️  V2.1 tiene recall bajo - considera bajar thresholds en NETWORK")
    
    print("\n📋 Próximos pasos:")
    print("   1. Revisar análisis por Attack Vector para ajustar thresholds")
    print("   2. Calibrar el mejor modelo si no está calibrado")
    print("   3. Validar con CVEs reales de CISA KEV")
    
    print("\n" + "="*70)
    print("  ✅ COMPARACIÓN COMPLETADA")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()