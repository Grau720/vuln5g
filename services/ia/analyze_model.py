import os
import sys
import pandas as pd
import numpy as np
from pymongo import MongoClient
from joblib import load
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Importar el featurizer
sys.path.append('/app/ia')
from featurizer import Featurizer

"""
==============================================================
    ANÁLISIS DEL MODELO DE EXPLOTABILIDAD
    Para usuarios NO expertos en IA
==============================================================

Este script te ayuda a entender:
1. ¿Qué tan bueno es el modelo?
2. ¿Qué CVEs está prediciendo bien o mal?
3. ¿Qué features son más importantes?
4. ¿Hay problemas con los datos?
"""

# Configuración
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_HOST = os.getenv("MONGO_HOST", "vulndb_mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB   = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}?authSource={MONGO_AUTH}"

MODEL_PATH = "/app/ia/models/exploit_model.joblib"
FEAT_PATH = "/app/ia/models/featurizer.joblib"


def print_section(title):
    """Imprime una sección bonita"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def load_data():
    """Carga CVEs y modelo"""
    print("🔄 Cargando datos desde MongoDB...")
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    print(f"✅ {len(cves)} CVEs cargados")
    
    print("🔄 Cargando modelo y featurizer...")
    model = load(MODEL_PATH)
    featurizer = Featurizer.load(FEAT_PATH)
    print("✅ Modelo cargado")
    
    client.close()
    return cves, model, featurizer


def analyze_dataset(cves):
    """Análisis básico del dataset"""
    print_section("1️⃣  ANÁLISIS DEL DATASET")
    
    print(f"📊 Total de CVEs: {len(cves)}\n")
    
    # Distribución de CVSS scores
    scores = [cve.get("cvssv3", {}).get("score", 0) for cve in cves]
    print("📈 Distribución de CVSS Scores:")
    print(f"   - Promedio: {np.mean(scores):.2f}")
    print(f"   - Mediana: {np.median(scores):.2f}")
    print(f"   - Mínimo: {min(scores):.2f}")
    print(f"   - Máximo: {max(scores):.2f}")
    
    # Rangos de severidad
    low = sum(1 for s in scores if s < 4.0)
    medium = sum(1 for s in scores if 4.0 <= s < 7.0)
    high = sum(1 for s in scores if 7.0 <= s < 9.0)
    critical = sum(1 for s in scores if s >= 9.0)
    
    print(f"\n📊 Por severidad:")
    print(f"   - 🟢 Baja (< 4.0): {low} ({low/len(cves)*100:.1f}%)")
    print(f"   - 🟡 Media (4.0-6.9): {medium} ({medium/len(cves)*100:.1f}%)")
    print(f"   - 🟠 Alta (7.0-8.9): {high} ({high/len(cves)*100:.1f}%)")
    print(f"   - 🔴 Crítica (≥ 9.0): {critical} ({critical/len(cves)*100:.1f}%)")
    
    # Tipos de vulnerabilidad
    print(f"\n🏷️  Top 10 tipos de vulnerabilidad:")
    tipos = [cve.get("tipo", "Desconocido") for cve in cves]
    tipo_counts = Counter(tipos).most_common(10)
    for tipo, count in tipo_counts:
        print(f"   - {tipo}: {count} ({count/len(cves)*100:.1f}%)")
    
    # Attack Vector
    print(f"\n🎯 Vectores de ataque (Attack Vector):")
    vectors = []
    for cve in cves:
        vector_str = cve.get("cvssv3", {}).get("vector", "")
        if "AV:N" in vector_str:
            vectors.append("NETWORK")
        elif "AV:A" in vector_str:
            vectors.append("ADJACENT")
        elif "AV:L" in vector_str:
            vectors.append("LOCAL")
        elif "AV:P" in vector_str:
            vectors.append("PHYSICAL")
        else:
            vectors.append("UNKNOWN")
    
    vector_counts = Counter(vectors)
    for vec, count in vector_counts.most_common():
        print(f"   - {vec}: {count} ({count/len(cves)*100:.1f}%)")
    
    # Complejidad de ataque
    print(f"\n⚙️  Complejidad de ataque (Attack Complexity):")
    complexity = []
    for cve in cves:
        vector_str = cve.get("cvssv3", {}).get("vector", "")
        if "AC:L" in vector_str:
            complexity.append("LOW")
        elif "AC:H" in vector_str:
            complexity.append("HIGH")
        else:
            complexity.append("UNKNOWN")
    
    comp_counts = Counter(complexity)
    for comp, count in comp_counts.most_common():
        print(f"   - {comp}: {count} ({count/len(cves)*100:.1f}%)")


def analyze_labels(cves):
    """Analiza cómo se están etiquetando los CVEs"""
    print_section("2️⃣  ANÁLISIS DE ETIQUETAS (Labels)")
    
    print("🏷️  Criterios de etiquetado:\n")
    print("   Un CVE se marca como EXPLOTABLE (1) si:")
    print("   ✓ Tiene referencias a exploits/PoC en referencias_mitre")
    print("   ✓ CVSS ≥ 7.0 + Attack Vector NETWORK + Attack Complexity LOW")
    print("   ✓ CVSS ≥ 9.0 (crítico)\n")
    
    explotable = 0
    no_explotable = 0
    
    # Reproducir la lógica de etiquetado
    reasons = {
        "exploit_refs": 0,
        "high_cvss_network": 0,
        "critical_score": 0
    }
    
    for cve in cves:
        cvss = cve.get("cvssv3", {})
        cvss_score = cvss.get("score", 0)
        vector = cvss.get("vector", "")
        
        has_exploit_refs = any(
            'exploit' in ref.lower() or 'poc' in ref.lower() 
            for ref in cve.get('referencias_mitre', [])
        )
        
        is_network = "AV:N" in vector
        is_low_complexity = "AC:L" in vector
        no_priv = "PR:N" in vector
        no_ui = "UI:N" in vector
        
        if has_exploit_refs:
            explotable += 1
            reasons["exploit_refs"] += 1
        elif cvss_score >= 7.0 and is_network and is_low_complexity and (no_priv or no_ui):
            explotable += 1
            reasons["high_cvss_network"] += 1
        elif cvss_score >= 9.0:
            explotable += 1
            reasons["critical_score"] += 1
        else:
            no_explotable += 1
    
    print(f"📊 Distribución de etiquetas:")
    print(f"   - ✅ Explotables (1): {explotable} ({explotable/len(cves)*100:.1f}%)")
    print(f"   - ❌ No explotables (0): {no_explotable} ({no_explotable/len(cves)*100:.1f}%)")
    
    print(f"\n🔍 Razones por las que se marcaron como explotables:")
    print(f"   - Referencias a exploits/PoC: {reasons['exploit_refs']}")
    print(f"   - CVSS alto + red + baja complejidad: {reasons['high_cvss_network']}")
    print(f"   - Score crítico (≥9.0): {reasons['critical_score']}")
    
    # ADVERTENCIA si el desbalance es muy alto
    if explotable < len(cves) * 0.05:
        print(f"\n⚠️  ADVERTENCIA: Solo el {explotable/len(cves)*100:.1f}% son explotables")
        print("   Esto puede hacer que el modelo tenga problemas para aprender.")
        print("   Considera ajustar los criterios de etiquetado.")
    
    if explotable == 0:
        print(f"\n❌ ERROR CRÍTICO: NO hay CVEs marcados como explotables")
        print("   El modelo NO PUEDE aprender sin ejemplos positivos.")


def analyze_predictions(cves, model, featurizer):
    """Analiza las predicciones del modelo"""
    print_section("3️⃣  ANÁLISIS DE PREDICCIONES")
    
    print("🔄 Generando predicciones para todos los CVEs...")
    
    predictions = []
    true_labels = []
    
    for cve in cves:
        # Etiqueta real
        cvss = cve.get("cvssv3", {})
        cvss_score = cvss.get("score", 0)
        vector = cvss.get("vector", "")
        
        has_exploit_refs = any(
            'exploit' in ref.lower() or 'poc' in ref.lower() 
            for ref in cve.get('referencias_mitre', [])
        )
        
        is_network = "AV:N" in vector
        is_low_complexity = "AC:L" in vector
        no_priv = "PR:N" in vector
        no_ui = "UI:N" in vector
        
        if has_exploit_refs:
            true_label = 1
        elif cvss_score >= 7.0 and is_network and is_low_complexity and (no_priv or no_ui):
            true_label = 1
        elif cvss_score >= 9.0:
            true_label = 1
        else:
            true_label = 0
        
        # Predicción
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            pred = int(model.predict(X)[0])
        except:
            prob = 0.0
            pred = 0
        
        predictions.append({
            "cve_id": cve.get("cve_id"),
            "true_label": true_label,
            "predicted_label": pred,
            "probability": prob,
            "cvss_score": cvss_score,
            "tipo": cve.get("tipo", "Desconocido")
        })
        
        true_labels.append(true_label)
    
    df = pd.DataFrame(predictions)
    
    # Distribución de probabilidades
    print(f"\n📊 Distribución de probabilidades de explotación:")
    print(f"   - Promedio: {df['probability'].mean():.4f}")
    print(f"   - Mediana: {df['probability'].median():.4f}")
    print(f"   - Mínimo: {df['probability'].min():.4f}")
    print(f"   - Máximo: {df['probability'].max():.4f}")
    
    # Rangos de probabilidad
    very_low = sum(1 for p in df['probability'] if p < 0.25)
    low = sum(1 for p in df['probability'] if 0.25 <= p < 0.50)
    high = sum(1 for p in df['probability'] if 0.50 <= p < 0.75)
    very_high = sum(1 for p in df['probability'] if p >= 0.75)
    
    print(f"\n📈 Por nivel de riesgo:")
    print(f"   - 🟢 LOW (< 25%): {very_low} CVEs")
    print(f"   - 🟡 MEDIUM (25-50%): {low} CVEs")
    print(f"   - 🟠 HIGH (50-75%): {high} CVEs")
    print(f"   - 🔴 CRITICAL (≥ 75%): {very_high} CVEs")
    
    # Top 10 CVEs más peligrosos según el modelo
    print(f"\n🚨 Top 10 CVEs MÁS PELIGROSOS según el modelo:")
    top_risky = df.nlargest(10, 'probability')
    for idx, row in top_risky.iterrows():
        print(f"   {row['cve_id']}: {row['probability']:.2%} | CVSS: {row['cvss_score']} | {row['tipo']}")
    
    # CVEs con mayor discrepancia (modelo vs etiqueta)
    df['discrepancy'] = abs(df['probability'] - df['true_label'])
    print(f"\n🤔 Top 10 CVEs con MAYOR DISCREPANCIA (modelo vs etiqueta real):")
    top_discrepancy = df.nlargest(10, 'discrepancy')
    for idx, row in top_discrepancy.iterrows():
        print(f"   {row['cve_id']}: Predicción={row['probability']:.2%} | Real={row['true_label']} | CVSS={row['cvss_score']}")
    
    return df


def analyze_feature_importance(model):
    """Analiza qué features son más importantes"""
    print_section("4️⃣  IMPORTANCIA DE FEATURES")
    
    print("📊 Features más importantes para el modelo:\n")
    
    try:
        # XGBoost guarda la importancia de features
        importance = model.feature_importances_
        
        # Obtener top 20
        top_indices = np.argsort(importance)[-20:][::-1]
        
        print("   Top 20 features más influyentes:")
        for i, idx in enumerate(top_indices, 1):
            print(f"   {i:2d}. Feature {idx}: {importance[idx]:.4f}")
        
        print("\n💡 Interpretación:")
        print("   - Números más altos = mayor influencia en las predicciones")
        print("   - Las primeras features suelen ser CVSS score y métricas categóricas")
        print("   - Features altas (> 500) son palabras del TF-IDF")
        
    except Exception as e:
        print(f"   ⚠️  No se pudo extraer importancia: {e}")


def generate_recommendations(df, cves):
    """Genera recomendaciones para mejorar el modelo"""
    print_section("5️⃣  RECOMENDACIONES")
    
    explotable_count = sum(df['true_label'])
    total = len(df)
    
    print("💡 Análisis y sugerencias:\n")
    
    # 1. Balanceo de clases
    if explotable_count / total < 0.1:
        print("⚠️  1. DESBALANCE DE CLASES")
        print(f"   Solo {explotable_count/total*100:.1f}% de CVEs son explotables.")
        print("   SUGERENCIAS:")
        print("   - Relajar criterios: incluir CVSS ≥ 6.0 como potencialmente explotables")
        print("   - Buscar más CVEs con referencias a exploits/PoC")
        print("   - Usar técnicas de oversampling (SMOTE)\n")
    else:
        print("✅ 1. Balanceo de clases: Aceptable\n")
    
    # 2. Calidad de features
    print("💭 2. CALIDAD DE FEATURES")
    print("   Actualmente usas:")
    print("   ✓ CVSS metrics (score, vector, complexity, etc.)")
    print("   ✓ CWE/Tipo de vulnerabilidad")
    print("   ✓ TF-IDF de descripciones")
    print("   MEJORAS POSIBLES:")
    print("   - Edad del CVE (CVEs más recientes pueden ser más explotables)")
    print("   - Número de referencias técnicas")
    print("   - Vendors/productos afectados (algunos son más populares)")
    print("   - Keywords específicas en descripciones ('remote', 'unauthenticated')\n")
    
    # 3. Datos de entrenamiento
    if total < 500:
        print("⚠️  3. CANTIDAD DE DATOS")
        print(f"   Tienes {total} CVEs. Para un modelo robusto:")
        print("   - Ideal: > 1000 CVEs")
        print("   - Mínimo aceptable: 500 CVEs")
        print("   SUGERENCIAS: Importar más CVEs de NVD\n")
    else:
        print("✅ 3. Cantidad de datos: Suficiente\n")
    
    # 4. Validación
    print("📋 4. PRÓXIMOS PASOS")
    print("   1. Revisar los CVEs con mayor discrepancia")
    print("   2. Ajustar criterios de etiquetado si es necesario")
    print("   3. Re-entrenar el modelo con mejores labels")
    print("   4. Validar con expertos en seguridad")
    print("   5. Integrar con sistemas de threat intelligence reales")


def main():
    print("\n" + "="*70)
    print("  🔍 ANÁLISIS DE MODELO DE EXPLOTABILIDAD")
    print("  Para usuarios NO expertos en IA")
    print("="*70)
    
    try:
        # Cargar datos
        cves, model, featurizer = load_data()
        
        # Análisis
        analyze_dataset(cves)
        analyze_labels(cves)
        df = analyze_predictions(cves, model, featurizer)
        analyze_feature_importance(model)
        generate_recommendations(df, cves)
        
        # Guardar reporte
        print_section("💾 GUARDANDO REPORTE")
        output_file = "/app/ia/analysis_report.csv"
        df.to_csv(output_file, index=False)
        print(f"✅ Reporte guardado en: {output_file}")
        print("   Puedes abrirlo con Excel o cualquier editor de CSV")
        
        print("\n" + "="*70)
        print("  ✅ ANÁLISIS COMPLETADO")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()