import os
import sys
from pymongo import MongoClient
from joblib import load
from tabulate import tabulate

sys.path.append('/app/ia')
from featurizer import Featurizer

"""
==============================================================
    COMPARADOR DE CVEs
    Compara múltiples CVEs lado a lado
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

MODEL_PATH = "/app/ia/models/exploit_model.joblib"
FEAT_PATH = "/app/ia/models/featurizer.joblib"


def compare_cves(cve_ids):
    """Compara múltiples CVEs"""
    
    print("\n" + "="*100)
    print(f"  🔄 COMPARANDO {len(cve_ids)} CVEs")
    print("="*100 + "\n")
    
    # Conectar
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    # Cargar modelo
    print("🔄 Cargando modelo...")
    model = load(MODEL_PATH)
    featurizer = Featurizer.load(FEAT_PATH)
    
    # Recopilar datos
    comparison_data = []
    
    for cve_id in cve_ids:
        cve = col.find_one({"cve_id": cve_id})
        
        if not cve:
            print(f"⚠️  {cve_id} no encontrado")
            continue
        
        cvss = cve.get("cvssv3", {})
        vector = cvss.get("vector", "")
        
        # Predicción
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
        except:
            prob = 0.0
        
        # Determinar etiqueta real
        cvss_score = cvss.get("score", 0)
        has_exploit = any('exploit' in ref.lower() or 'poc' in ref.lower() 
                         for ref in cve.get('referencias_mitre', []))
        is_network = "AV:N" in vector
        is_low_complexity = "AC:L" in vector
        
        if has_exploit:
            real_label = "EXPLOTABLE"
        elif cvss_score >= 7.0 and is_network and is_low_complexity:
            real_label = "EXPLOTABLE"
        elif cvss_score >= 9.0:
            real_label = "EXPLOTABLE"
        else:
            real_label = "NO EXPLOTABLE"
        
        # Nivel de riesgo
        if prob >= 0.75:
            risk = "CRITICAL"
        elif prob >= 0.50:
            risk = "HIGH"
        elif prob >= 0.25:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        
        comparison_data.append({
            "CVE ID": cve_id,
            "Tipo": cve.get("tipo", "")[:30],
            "CVSS": cvss_score,
            "Attack Vector": "NETWORK" if is_network else "OTHER",
            "Complexity": "LOW" if is_low_complexity else "HIGH",
            "Has Exploit": "✅" if has_exploit else "❌",
            "Label Real": real_label,
            "Prob. Exploit": f"{prob:.2%}",
            "Risk Level": risk
        })
    
    # Mostrar tabla
    if comparison_data:
        print("\n" + tabulate(comparison_data, headers="keys", tablefmt="grid"))
    
    client.close()
    
    print("\n" + "="*100)
    print("  ✅ COMPARACIÓN COMPLETADA")
    print("="*100 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 compare_cves.py CVE-ID1 CVE-ID2 [CVE-ID3 ...]")
        print("Ejemplo: python3 compare_cves.py CVE-2022-49075 CVE-2024-46921 CVE-2025-33211")
        sys.exit(1)
    
    cve_ids = [cve.upper() for cve in sys.argv[1:]]
    compare_cves(cve_ids)


if __name__ == "__main__":
    main()