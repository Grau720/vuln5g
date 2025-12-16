import os
import sys
from pymongo import MongoClient
from joblib import load
import json

sys.path.append('/app/ia')
from featurizer import Featurizer

"""
==============================================================
    INSPECTOR DE CVE INDIVIDUAL
    Analiza un CVE específico y muestra TODO el proceso
==============================================================
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

MODEL_PATH = "/app/services/ia/models/exploit_model.joblib"
FEAT_PATH = "/app/services/ia/models/featurizer.joblib"


def print_box(title, content=""):
    """Imprime un box bonito"""
    width = 70
    print("\n┌" + "─" * (width - 2) + "┐")
    print(f"│ {title:<{width-4}} │")
    if content:
        print("├" + "─" * (width - 2) + "┤")
        for line in content.split('\n'):
            print(f"│ {line:<{width-4}} │")
    print("└" + "─" * (width - 2) + "┘")


def inspect_cve(cve_id):
    """Inspecciona un CVE en detalle"""
    
    print("\n" + "="*70)
    print(f"  🔍 INSPECCIÓN DETALLADA: {cve_id}")
    print("="*70)
    
    # Conectar a MongoDB
    print("\n🔄 Buscando CVE en la base de datos...")
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    cve = col.find_one({"cve_id": cve_id})
    
    if not cve:
        print(f"❌ CVE {cve_id} no encontrado en la base de datos")
        client.close()
        return
    
    print("✅ CVE encontrado\n")
    
    # ========================================
    # 1. INFORMACIÓN BÁSICA
    # ========================================
    print_box("📋 INFORMACIÓN BÁSICA")
    
    cvss = cve.get("cvssv3", {})
    print(f"CVE ID: {cve.get('cve_id')}")
    print(f"Tipo: {cve.get('tipo', 'Desconocido')}")
    print(f"CVSS Score: {cvss.get('score', 0)}")
    print(f"Vector CVSS: {cvss.get('vector', 'N/A')}")
    print(f"Componente: {cve.get('componente_afectado', 'N/A')}")
    print(f"Fecha publicación: {cve.get('fecha_publicacion', 'N/A')}")
    
    # ========================================
    # 2. MÉTRICAS CVSS DESGLOSADAS
    # ========================================
    print_box("📊 MÉTRICAS CVSS DESGLOSADAS")
    
    vector = cvss.get('vector', '')
    
    # Parsear vector
    metrics = {}
    for part in vector.split('/'):
        if ':' in part:
            key, value = part.split(':', 1)
            metrics[key] = value
    
    av_map = {'N': 'NETWORK', 'A': 'ADJACENT', 'L': 'LOCAL', 'P': 'PHYSICAL'}
    ac_map = {'L': 'LOW', 'H': 'HIGH'}
    pr_map = {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
    ui_map = {'N': 'NONE', 'R': 'REQUIRED'}
    s_map = {'U': 'UNCHANGED', 'C': 'CHANGED'}
    impact_map = {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
    
    print(f"Attack Vector (AV): {av_map.get(metrics.get('AV'), 'UNKNOWN')}")
    print(f"Attack Complexity (AC): {ac_map.get(metrics.get('AC'), 'UNKNOWN')}")
    print(f"Privileges Required (PR): {pr_map.get(metrics.get('PR'), 'UNKNOWN')}")
    print(f"User Interaction (UI): {ui_map.get(metrics.get('UI'), 'UNKNOWN')}")
    print(f"Scope (S): {s_map.get(metrics.get('S'), 'UNKNOWN')}")
    print(f"Confidentiality (C): {impact_map.get(metrics.get('C'), 'UNKNOWN')}")
    print(f"Integrity (I): {impact_map.get(metrics.get('I'), 'UNKNOWN')}")
    print(f"Availability (A): {impact_map.get(metrics.get('A'), 'UNKNOWN')}")
    
    # ========================================
    # 3. CRITERIOS DE EXPLOTABILIDAD
    # ========================================
    print_box("🎯 CRITERIOS DE EXPLOTABILIDAD")
    
    cvss_score = cvss.get("score", 0)
    has_exploit_refs = any(
        'exploit' in ref.lower() or 'poc' in ref.lower() 
        for ref in cve.get('referencias_mitre', [])
    )
    
    is_network = "AV:N" in vector
    is_low_complexity = "AC:L" in vector
    no_priv = "PR:N" in vector
    no_ui = "UI:N" in vector
    is_critical = cvss_score >= 9.0
    is_high = cvss_score >= 7.0
    
    print("Condiciones para ser marcado como EXPLOTABLE:")
    print(f"  {'✅' if has_exploit_refs else '❌'} Referencias a exploits/PoC: {has_exploit_refs}")
    print(f"  {'✅' if is_critical else '❌'} CVSS crítico (≥9.0): {is_critical}")
    print(f"  {'✅' if is_high else '❌'} CVSS alto (≥7.0): {is_high}")
    print(f"  {'✅' if is_network else '❌'} Attack Vector = NETWORK: {is_network}")
    print(f"  {'✅' if is_low_complexity else '❌'} Attack Complexity = LOW: {is_low_complexity}")
    print(f"  {'✅' if no_priv else '❌'} No requiere privilegios: {no_priv}")
    print(f"  {'✅' if no_ui else '❌'} No requiere interacción: {no_ui}")
    
    # Determinar etiqueta
    if has_exploit_refs:
        label = 1
        reason = "Referencias a exploits/PoC"
    elif is_high and is_network and is_low_complexity and (no_priv or no_ui):
        label = 1
        reason = "CVSS alto + red + baja complejidad"
    elif is_critical:
        label = 1
        reason = "Score crítico"
    else:
        label = 0
        reason = "No cumple criterios"
    
    print(f"\n🏷️  ETIQUETA ASIGNADA: {label} ({'EXPLOTABLE' if label == 1 else 'NO EXPLOTABLE'})")
    print(f"📝 Razón: {reason}")
    
    # ========================================
    # 4. PREDICCIÓN DEL MODELO
    # ========================================
    print_box("🤖 PREDICCIÓN DEL MODELO")
    
    try:
        print("🔄 Cargando modelo...")
        model = load(MODEL_PATH)
        featurizer = Featurizer.load(FEAT_PATH)
        
        print("🔄 Extrayendo features...")
        raw = featurizer.extract_raw_features(cve)
        
        print("\n📊 Features extraídas:")
        print(f"  - CVSS base score: {raw['cvss_base_score']}")
        print(f"  - Attack Vector: {raw['attackVector']}")
        print(f"  - Attack Complexity: {raw['attackComplexity']}")
        print(f"  - Privileges Required: {raw['privilegesRequired']}")
        print(f"  - User Interaction: {raw['userInteraction']}")
        print(f"  - Scope: {raw['scope']}")
        print(f"  - Confidentiality Impact: {raw['confidentialityImpact']}")
        print(f"  - Integrity Impact: {raw['integrityImpact']}")
        print(f"  - Availability Impact: {raw['availabilityImpact']}")
        print(f"  - CWE: {raw['cwe']}")
        print(f"  - Texto (primeros 100 chars): {raw['text'][:100]}...")
        
        print("\n🔄 Transformando features...")
        X = featurizer.transform([raw])
        print(f"  Vector final: shape {X.shape} (534 features numéricas)")
        
        print("\n🔄 Ejecutando predicción...")
        prob = float(model.predict_proba(X)[0][1])
        pred = int(model.predict(X)[0])
        
        # Nivel de riesgo
        if prob >= 0.75:
            risk = "🔴 CRITICAL"
        elif prob >= 0.50:
            risk = "🟠 HIGH"
        elif prob >= 0.25:
            risk = "🟡 MEDIUM"
        else:
            risk = "🟢 LOW"
        
        print("\n" + "="*70)
        print(f"  🎯 RESULTADO DE LA PREDICCIÓN")
        print("="*70)
        print(f"  Probabilidad de explotación: {prob:.2%}")
        print(f"  Clase predicha: {pred} ({'EXPLOTABLE' if pred == 1 else 'NO EXPLOTABLE'})")
        print(f"  Nivel de riesgo: {risk}")
        print("="*70)
        
        # Comparación con etiqueta real
        print("\n📊 COMPARACIÓN:")
        print(f"  Etiqueta real: {label} ({'EXPLOTABLE' if label == 1 else 'NO EXPLOTABLE'})")
        print(f"  Predicción: {pred} ({'EXPLOTABLE' if pred == 1 else 'NO EXPLOTABLE'})")
        
        if label == pred:
            print("  ✅ ¡El modelo acertó!")
        else:
            print("  ❌ El modelo se equivocó")
            print(f"  Discrepancia: |{prob:.4f} - {label}| = {abs(prob - label):.4f}")
        
    except Exception as e:
        print(f"❌ Error en la predicción: {e}")
        import traceback
        traceback.print_exc()
    
    # ========================================
    # 5. DESCRIPCIÓN Y REFERENCIAS
    # ========================================
    print_box("📝 DESCRIPCIÓN")
    desc = cve.get('descripcion_general', '')[:500]
    print(desc + ("..." if len(desc) >= 500 else ""))
    
    refs = cve.get('referencias_mitre', [])
    if refs:
        print_box(f"🔗 REFERENCIAS ({len(refs)})")
        for i, ref in enumerate(refs[:5], 1):
            print(f"{i}. {ref}")
        if len(refs) > 5:
            print(f"   ... y {len(refs) - 5} más")
    
    client.close()
    
    print("\n" + "="*70)
    print("  ✅ INSPECCIÓN COMPLETADA")
    print("="*70 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 inspect_cve.py <CVE-ID>")
        print("Ejemplo: python3 inspect_cve.py CVE-2022-49075")
        sys.exit(1)
    
    cve_id = sys.argv[1].upper()
    inspect_cve(cve_id)


if __name__ == "__main__":
    main()