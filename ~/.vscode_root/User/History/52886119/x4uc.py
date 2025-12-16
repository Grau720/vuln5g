"""
==============================================================
    RE-TRAIN MODEL WITH SMART LABELING v2.1
    Attack Vector Aware Training
==============================================================

NUEVO en v2.1:
- Usa smart_labeling v2.1 con thresholds por Attack Vector
- Compara con V2.0 para validar mejoras
- Análisis detallado de cambios en labels

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
    average_precision_score, precision_score, recall_score
)

sys.path.append('/app/ia')
from featurizer import Featurizer
from smart_labeling import smart_label_batch, explain_label


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
MODEL_V2_PATH = os.path.join(OUTPUT_DIR, "exploit_model_v2.joblib")
FEAT_V2_PATH = os.path.join(OUTPUT_DIR, "featurizer_v2.joblib")
MODEL_V21_PATH = os.path.join(OUTPUT_DIR, "exploit_model_v2.1.joblib")
FEAT_V21_PATH = os.path.join(OUTPUT_DIR, "featurizer_v2.1.joblib")


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


def analyze_label_changes(cves, y_old, y_new):
    """
    Analiza los cambios entre V2.0 y V2.1 labels
    """
    print("\n" + "="*70)
    print("  📊 ANÁLISIS DE CAMBIOS EN LABELS (V2.0 → V2.1)")
    print("="*70 + "\n")
    
    changes = []
    for i, cve in enumerate(cves):
        if y_old[i] != y_new[i]:
            cvss = cve.get("cvssv3", {})
            vector_str = cvss.get("vector", "")
            
            # Detectar Attack Vector
            if "AV:N" in vector_str:
                av = "NETWORK"
            elif "AV:L" in vector_str:
                av = "LOCAL"
            elif "AV:A" in vector_str:
                av = "ADJACENT"
            else:
                av = "UNKNOWN"
            
            changes.append({
                "cve_id": cve.get("cve_id"),
                "cvss": cvss.get("score", 0),
                "tipo": cve.get("tipo", "Desconocido"),
                "av": av,
                "old_label": y_old[i],
                "new_label": y_new[i],
                "change": "1→0" if y_old[i] == 1 else "0→1"
            })
    
    df_changes = pd.DataFrame(changes)
    
    print(f"📈 Total de cambios: {len(changes)} ({len(changes)/len(cves)*100:.1f}%)")
    print(f"   - V2.0 explotables: {sum(y_old)} ({sum(y_old)/len(y_old)*100:.1f}%)")
    print(f"   - V2.1 explotables: {sum(y_new)} ({sum(y_new)/len(y_new)*100:.1f}%)")
    print(f"   - Diferencia: {sum(y_new) - sum(y_old):+d} CVEs")
    
    if len(changes) > 0:
        print(f"\n🔄 Por tipo de cambio:")
        print(f"   - Explotable → No explotable (1→0): {len(df_changes[df_changes['change']=='1→0'])}")
        print(f"   - No explotable → Explotable (0→1): {len(df_changes[df_changes['change']=='0→1'])}")
        
        print(f"\n🎯 Cambios por Attack Vector:")
        for av in ["NETWORK", "LOCAL", "ADJACENT", "UNKNOWN"]:
            av_changes = df_changes[df_changes['av'] == av]
            if len(av_changes) > 0:
                print(f"   {av:12s}: {len(av_changes):3d} cambios")
                to_zero = len(av_changes[av_changes['change']=='1→0'])
                to_one = len(av_changes[av_changes['change']=='0→1'])
                print(f"                    └─ 1→0: {to_zero}, 0→1: {to_one}")
        
        print(f"\n🏷️  Top 10 tipos más afectados:")
        tipo_changes = df_changes.groupby('tipo').size().sort_values(ascending=False).head(10)
        for tipo, count in tipo_changes.items():
            pct = count / len(changes) * 100
            print(f"   {tipo:40s}: {count:3d} ({pct:5.1f}%)")
        
        # Mostrar ejemplos de cambios LOCAL
        local_changes = df_changes[df_changes['av'] == 'LOCAL'].head(5)
        if len(local_changes) > 0:
            print(f"\n🔍 Ejemplos de cambios en LOCAL (threshold 0.60→0.75):")
            for _, row in local_changes.iterrows():
                print(f"   {row['cve_id']:20s} | CVSS: {row['cvss']:.1f} | {row['tipo']:30s} | {row['change']}")
        
        # Mostrar ejemplos de DoS
        dos_changes = df_changes[df_changes['tipo'] == 'Denegación de servicio'].head(5)
        if len(dos_changes) > 0:
            print(f"\n🔍 Ejemplos de cambios en DoS (penalización extra):")
            for _, row in dos_changes.iterrows():
                print(f"   {row['cve_id']:20s} | CVSS: {row['cvss']:.1f} | {row['av']:10s} | {row['change']}")
    
    return df_changes


def compare_models(X_test, y_test, model_v2, model_v21, featurizer_v2, featurizer_v21):
    """
    Compara el rendimiento de V2.0 vs V2.1
    """
    print("\n" + "="*70)
    print("  📊 COMPARACIÓN V2.0 vs V2.1")
    print("="*70 + "\n")
    
    # Predicciones V2.0
    y_pred_v2 = model_v2.predict(X_test)
    y_proba_v2 = model_v2.predict_proba(X_test)[:, 1]
    
    # Predicciones V2.1
    y_pred_v21 = model_v21.predict(X_test)
    y_proba_v21 = model_v21.predict_proba(X_test)[:, 1]
    
    # Métricas V2.0
    print("📊 MODELO V2.0 (Original Smart Labels):")
    print(classification_report(y_test, y_pred_v2, target_names=['No Explotable', 'Explotable']))
    auc_v2 = roc_auc_score(y_test, y_proba_v2)
    ap_v2 = average_precision_score(y_test, y_proba_v2)
    prec_v2 = precision_score(y_test, y_pred_v2, zero_division=0)
    rec_v2 = recall_score(y_test, y_pred_v2, zero_division=0)
    print(f"ROC-AUC: {auc_v2:.4f}")
    print(f"AP Score: {ap_v2:.4f}")
    
    print("\n" + "-"*70 + "\n")
    
    # Métricas V2.1
    print("📊 MODELO V2.1 (Attack Vector Aware):")
    print(classification_report(y_test, y_pred_v21, target_names=['No Explotable', 'Explotable']))
    auc_v21 = roc_auc_score(y_test, y_proba_v21)
    ap_v21 = average_precision_score(y_test, y_proba_v21)
    prec_v21 = precision_score(y_test, y_pred_v21, zero_division=0)
    rec_v21 = recall_score(y_test, y_pred_v21, zero_division=0)
    print(f"ROC-AUC: {auc_v21:.4f}")
    print(f"AP Score: {ap_v21:.4f}")
    
    # Comparación directa
    print("\n📈 MEJORAS:")
    print(f"   ROC-AUC:   {auc_v2:.4f} → {auc_v21:.4f} ({(auc_v21-auc_v2)*100:+.2f}%)")
    print(f"   AP Score:  {ap_v2:.4f} → {ap_v21:.4f} ({(ap_v21-ap_v2)*100:+.2f}%)")
    print(f"   Precision: {prec_v2:.4f} → {prec_v21:.4f} ({(prec_v21-prec_v2)*100:+.2f}%)")
    print(f"   Recall:    {rec_v2:.4f} → {rec_v21:.4f} ({(rec_v21-rec_v2)*100:+.2f}%)")
    
    # Determinar si es mejor
    improvements = sum([
        auc_v21 > auc_v2,
        ap_v21 > ap_v2,
        prec_v21 > prec_v2
    ])
    
    if improvements >= 2:
        print("\n   ✅ V2.1 es MEJOR que V2.0 (mejora en 2+ métricas)")
        return True
    else:
        print("\n   ⚠️  V2.1 NO superó claramente a V2.0")
        return False


def main():
    print("\n" + "="*70)
    print("  🚀 RE-TRAINING WITH SMART LABELING v2.1")
    print("  Attack Vector Aware Thresholds")
    print("="*70 + "\n")
    
    # 1. Cargar datos
    print("[1/7] Cargando CVEs desde MongoDB...")
    cves = load_cves()
    print(f"      ✅ {len(cves)} CVEs cargados")
    
    if len(cves) < 50:
        print("\n❌ ERROR: Se necesitan al menos 50 CVEs para entrenar")
        sys.exit(1)
    
    # 2. Generar labels V2.1
    print("\n[2/7] Generando labels con Smart Labeling v2.1...")
    y_new = smart_label_batch(cves, verbose=True)
    
    if sum(y_new) == 0:
        print("\n❌ ERROR: No hay CVEs etiquetados como explotables")
        print("   Revisa los thresholds en smart_labeling.py")
        sys.exit(1)
    
    # 3. Comparar con V2.0 si existe
    if os.path.exists(MODEL_V2_PATH):
        print("\n[3/7] Comparando labels V2.0 vs V2.1...")
        try:
            # Cargar V2.0 para comparar labels
            from smart_labeling_v20 import smart_label_batch as smart_label_batch_v20
            y_old = smart_label_batch_v20(cves, verbose=False)
            
            df_changes = analyze_label_changes(cves, y_old, y_new)
            
            # Guardar reporte de cambios
            changes_file = "/app/ia/label_changes_v20_to_v21.csv"
            df_changes.to_csv(changes_file, index=False)
            print(f"\n💾 Reporte de cambios guardado: {changes_file}")
            
        except ImportError:
            print("      ℹ️  No se puede comparar con V2.0 (smart_labeling_v20.py no encontrado)")
    else:
        print("\n[3/7] Saltando comparación (modelo V2.0 no existe)")
    
    # 4. Extraer features
    print("\n[4/7] Extrayendo features...")
    F = Featurizer()
    raw_feature_list = build_raw_features(cves, F)
    
    print("      Ajustando featurizer (TF-IDF, OneHot, Scaler)...")
    F.fit(raw_feature_list)
    
    print("      Transformando features...")
    X = F.transform(raw_feature_list)
    print(f"      ✅ Matriz: {X.shape}")
    
    # 5. Split train/test
    print("\n[5/7] Split train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_new, test_size=0.2, random_state=42,
        stratify=y_new if sum(y_new) > 5 else None
    )
    
    print(f"      Train: {X_train.shape[0]} | Test: {X_test.shape[0]}")
    print(f"      Positivos train: {sum(y_train)} ({sum(y_train)/len(y_train)*100:.1f}%)")
    print(f"      Positivos test:  {sum(y_test)} ({sum(y_test)/len(y_test)*100:.1f}%)")
    
    # 6. Entrenar XGBoost V2.1
    print("\n[6/7] Entrenando XGBoost V2.1...")
    
    n_neg = len([i for i in y_train if i == 0])
    n_pos = len([i for i in y_train if i == 1])
    scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1
    
    print(f"      scale_pos_weight: {scale_pos_weight:.2f}")
    
    model_v21 = XGBClassifier(
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
    
    model_v21.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )
    
    print("      ✅ Modelo V2.1 entrenado")
    
    # 7. Evaluar
    print("\n[7/7] Evaluando modelo V2.1...")
    y_pred = model_v21.predict(X_test)
    y_proba = model_v21.predict_proba(X_test)[:, 1]
    
    print("\n📊 RESULTADOS V2.1 (Test Set):")
    print(confusion_matrix(y_test, y_pred))
    print("\n" + classification_report(y_test, y_pred, target_names=['No Explotable', 'Explotable']))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")
    print(f"AP Score: {average_precision_score(y_test, y_proba):.4f}")
    
    # Comparar con V2.0 si existe
    if os.path.exists(MODEL_V2_PATH) and os.path.exists(FEAT_V2_PATH):
        print("\n🔄 Comparando con modelo V2.0...")
        try:
            model_v2 = load(MODEL_V2_PATH)
            featurizer_v2 = Featurizer.load(FEAT_V2_PATH)
            
            # Re-extraer features con featurizer v2 para comparación justa
            raw_v2 = build_raw_features(cves, featurizer_v2)
            X_v2 = featurizer_v2.transform(raw_v2)
            
            # Usar los MISMOS labels (y_new) para comparación justa
            X_train_v2, X_test_v2, _, _ = train_test_split(
                X_v2, y_new, test_size=0.2, random_state=42,
                stratify=y_new if sum(y_new) > 5 else None
            )
            
            v21_is_better = compare_models(X_test_v2, y_test, model_v2, model_v21, featurizer_v2, F)
            
        except Exception as e:
            print(f"   ⚠️  No se pudo comparar con V2.0: {e}")
            v21_is_better = True
    else:
        print("\n   ℹ️  No existe modelo V2.0 para comparar")
        v21_is_better = True
    
    # 8. Guardar modelo V2.1
    print("\n💾 Guardando modelo V2.1...")
    F.save(FEAT_V21_PATH)
    dump(model_v21, MODEL_V21_PATH)
    
    print(f"   ✅ Featurizer V2.1: {FEAT_V21_PATH}")
    print(f"   ✅ Modelo V2.1:     {MODEL_V21_PATH}")
    
    # Recomendación
    if v21_is_better:
        print("\n✅ RECOMENDACIÓN: Usar modelo V2.1")
        print("   Próximos pasos:")
        print("   1. Calibrar: python calibrate_exploit_model.py --v21")
        print("   2. Probar: python run_predict.py --version v2.1 --top 20")
    else:
        print("\n⚠️  ADVERTENCIA: V2.1 no superó claramente a V2.0")
        print("   Revisa el reporte de cambios en label_changes_v20_to_v21.csv")
    
    # Mostrar ejemplos de predicción
    print("\n📋 EJEMPLOS DE PREDICCIÓN V2.1:")
    print("="*70)
    
    # Tomar 3 ejemplos: 1 NETWORK explotable, 1 LOCAL no explotable, 1 DoS
    ejemplos = []
    
    for cve in cves:
        cvss = cve.get("cvssv3", {})
        vector = cvss.get("vector", "")
        tipo = cve.get("tipo", "")
        
        # Buscar ejemplo NETWORK explotable
        if not any(e.get("tipo") == "NETWORK" for e in ejemplos):
            if "AV:N" in vector and tipo == "Ejecución remota":
                ejemplos.append({"cve": cve, "tipo": "NETWORK"})
        
        # Buscar ejemplo LOCAL
        if not any(e.get("tipo") == "LOCAL" for e in ejemplos):
            if "AV:L" in vector:
                ejemplos.append({"cve": cve, "tipo": "LOCAL"})
        
        # Buscar ejemplo DoS
        if not any(e.get("tipo") == "DOS" for e in ejemplos):
            if tipo == "Denegación de servicio":
                ejemplos.append({"cve": cve, "tipo": "DOS"})
        
        if len(ejemplos) >= 3:
            break
    
    for ej in ejemplos:
        print(explain_label(ej["cve"]))
    
    print("\n" + "="*70)
    print("  ✅ RE-ENTRENAMIENTO V2.1 COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()