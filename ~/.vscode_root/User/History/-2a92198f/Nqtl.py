import os
from pymongo import MongoClient

"""
==============================================================
    REPARAR DATOS CVSS EN MONGODB
    
    Problema: Muchos CVEs tienen cvssv3 = {} o score = 0
    Solución: Buscar en otros campos y normalizar
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


def analyze_cvss_issues():
    """Analiza qué CVEs tienen problemas con CVSS"""
    print("\n🔍 Analizando problemas con CVSS...\n")
    
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    total = col.count_documents({})
    
    # CVEs sin cvssv3
    no_cvss = col.count_documents({"cvssv3": {"$exists": False}})
    
    # CVEs con cvssv3 vacío
    empty_cvss = col.count_documents({"cvssv3": {}})
    
    # CVEs con score = 0
    zero_score = col.count_documents({"cvssv3.score": 0})
    
    # CVEs sin score
    no_score = col.count_documents({"cvssv3.score": {"$exists": False}})
    
    # CVEs válidos
    valid = col.count_documents({"cvssv3.score": {"$gt": 0}})
    
    print(f"📊 Estadísticas CVSS:")
    print(f"   Total CVEs: {total}")
    print(f"   ✅ Con CVSS válido (score > 0): {valid} ({valid/total*100:.1f}%)")
    print(f"   ❌ Sin campo cvssv3: {no_cvss} ({no_cvss/total*100:.1f}%)")
    print(f"   ❌ cvssv3 vacío: {empty_cvss} ({empty_cvss/total*100:.1f}%)")
    print(f"   ❌ Score = 0: {zero_score} ({zero_score/total*100:.1f}%)")
    print(f"   ❌ Sin score: {no_score} ({no_score/total*100:.1f}%)")
    
    # Verificar campos alternativos
    print("\n🔎 Buscando campos alternativos...")
    
    # Ejemplos de CVEs problemáticos
    problematic = list(col.find(
        {"$or": [
            {"cvssv3": {"$exists": False}},
            {"cvssv3.score": {"$exists": False}},
            {"cvssv3.score": 0}
        ]},
        limit=5
    ))
    
    print(f"\n📋 Ejemplos de CVEs problemáticos:")
    for cve in problematic:
        print(f"\n   CVE: {cve.get('cve_id')}")
        print(f"   - cvssv3: {cve.get('cvssv3', 'NO EXISTE')}")
        print(f"   - cvss_v3: {cve.get('cvss_v3', 'NO EXISTE')}")
        print(f"   - riesgo: {cve.get('riesgo', 'NO EXISTE')}")
        
        # Buscar otros campos que puedan tener info CVSS
        for key in cve.keys():
            if 'cvss' in key.lower() or 'score' in key.lower():
                print(f"   - {key}: {cve.get(key)}")
    
    client.close()
    
    print("\n" + "="*70)
    print("💡 RECOMENDACIONES:")
    print("="*70)
    
    if valid < total * 0.5:
        print("\n⚠️  PROBLEMA CRÍTICO:")
        print("   Menos del 50% de CVEs tienen CVSS válido.")
        print("\n   SOLUCIONES:")
        print("   1. Verificar el script de importación de NVD")
        print("   2. Re-importar CVEs desde la fuente original")
        print("   3. Buscar campos alternativos (cvss_v3, cvss3, etc.)")
        print("   4. Filtrar solo CVEs con CVSS válido para el entrenamiento")
    else:
        print("\n✅ El problema es manejable.")
        print("   Puedes filtrar CVEs sin CVSS en el entrenamiento.")


def suggest_filter():
    """Sugiere un filtro para el entrenamiento"""
    print("\n" + "="*70)
    print("🔧 CÓDIGO PARA ENTRENAR SOLO CON CVEs VÁLIDOS")
    print("="*70)
    
    print("""
# En train_exploit_model.py, modifica load_cves_from_mongo():

def load_cves_from_mongo():
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]

    # FILTRAR SOLO CVEs CON CVSS VÁLIDO
    cursor = col.find({
        "cvssv3.score": {"$exists": True, "$gt": 0},
        "cvssv3.vector": {"$exists": True}
    })

    cves = list(cursor)
    print(f"[+] CVEs con CVSS válido: {len(cves)}")
    client.close()
    return cves
""")


def main():
    print("\n" + "="*70)
    print("  🔧 DIAGNÓSTICO DE DATOS CVSS")
    print("="*70)
    
    analyze_cvss_issues()
    suggest_filter()
    
    print("\n" + "="*70)
    print("  ✅ DIAGNÓSTICO COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()