"""
==============================================================
    RUN PREDICTIONS - Endpoint de Predicción de Explotabilidad
==============================================================

Script para ejecutar predicciones sobre CVEs individuales
o en batch desde MongoDB.

Uso:
    python run_predict.py --cve CVE-2024-1234
    python run_predict.py --top 20 --min-cvss 7.0
    python run_predict.py --batch --output predictions.json
==============================================================
"""

import os
import sys
import json
import argparse
from pymongo import MongoClient
from joblib import load

sys.path.append('/app/ia')
from featurizer import Featurizer
from smart_labeling import explain_label


# Configuración MongoDB
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_HOST = os.getenv("MONGO_HOST", "vulndb_mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB   = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}?authSource={MONGO_AUTH}"

# Paths de modelos
MODEL_CALIBRATED = "/app/ia/models/exploit_model_calibrated.joblib"
MODEL_V2_CALIBRATED = "/app/ia/models/exploit_model_v2_calibrated.joblib"
MODEL_BASE = "/app/ia/models/exploit_model.joblib"
MODEL_V2 = "/app/ia/models/exploit_model_v2.joblib"
FEATURIZER = "/app/ia/models/featurizer.joblib"
FEATURIZER_V2 = "/app/ia/models/featurizer_v2.joblib"


def find_best_model():
    """
    Encuentra el mejor modelo disponible.
    Prioridad: V2 calibrado > V2 base > V1 calibrado > V1 base
    """
    options = [
        (MODEL_V2_CALIBRATED, FEATURIZER_V2, "V2 Calibrated"),
        (MODEL_V2, FEATURIZER_V2, "V2"),
        (MODEL_CALIBRATED, FEATURIZER, "V1 Calibrated"),
        (MODEL_BASE, FEATURIZER, "V1"),
    ]
    
    for model_path, feat_path, name in options:
        if os.path.exists(model_path) and os.path.exists(feat_path):
            print(f"✅ Usando modelo: {name}")
            return load(model_path), Featurizer.load(feat_path), name
    
    raise FileNotFoundError("No se encontró ningún modelo entrenado")


def get_risk_level(probability):
    """Categoriza el nivel de riesgo según probabilidad"""
    if probability >= 0.75:
        return "CRITICAL"
    elif probability >= 0.50:
        return "HIGH"
    elif probability >= 0.25:
        return "MEDIUM"
    else:
        return "LOW"


def predict_single_cve(cve_id, model, featurizer, db):
    """
    Predice la explotabilidad de un CVE específico.
    """
    col = db[MONGO_COLLECTION]
    cve = col.find_one({"cve_id": cve_id})
    
    if not cve:
        print(f"❌ CVE {cve_id} no encontrado en la base de datos")
        return None
    
    try:
        raw = featurizer.extract_raw_features(cve)
        X = featurizer.transform([raw])
        prob = float(model.predict_proba(X)[0][1])
        pred = int(model.predict(X)[0])
        
        result = {
            "cve_id": cve_id,
            "exploit_probability": prob,
            "predicted_label": pred,
            "risk_level": get_risk_level(prob),
            "cvss_score": cve.get("cvssv3", {}).get("score", 0),
            "tipo": cve.get("tipo", "Desconocido"),
            "componente": cve.get("componente_afectado"),
            "descripcion": cve.get("descripcion_general", "")[:200]
        }
        
        return result
        
    except Exception as e:
        print(f"❌ Error procesando {cve_id}: {e}")
        return None


def predict_top_risks(model, featurizer, db, limit=10, min_cvss=0.0):
    """
    Obtiene los CVEs más peligrosos según el modelo.
    """
    col = db[MONGO_COLLECTION]
    
    # Filtrar por CVSS si se especifica
    query = {"cvssv3.score": {"$exists": True}}
    if min_cvss > 0:
        query["cvssv3.score"] = {"$gte": min_cvss}
    
    cves = list(col.find(query))
    
    if not cves:
        print(f"❌ No se encontraron CVEs con CVSS >= {min_cvss}")
        return []
    
    print(f"🔄 Analizando {len(cves)} CVEs...")
    
    results = []
    for cve in cves:
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            
            results.append({
                "cve_id": cve.get("cve_id"),
                "exploit_probability": prob,
                "risk_level": get_risk_level(prob),
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "tipo": cve.get("tipo", "Desconocido"),
                "componente": cve.get("componente_afectado")
            })
        except:
            continue
    
    # Ordenar por probabilidad descendente
    results.sort(key=lambda x: x["exploit_probability"], reverse=True)
    
    return results[:limit]


def predict_batch(model, featurizer, db, output_file=None):
    """
    Predice sobre todos los CVEs y guarda resultados.
    """
    col = db[MONGO_COLLECTION]
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    
    print(f"🔄 Procesando {len(cves)} CVEs en modo batch...")
    
    results = []
    errors = 0
    
    for i, cve in enumerate(cves, 1):
        if i % 50 == 0:
            print(f"   Progreso: {i}/{len(cves)}")
        
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            pred = int(model.predict(X)[0])
            
            results.append({
                "cve_id": cve.get("cve_id"),
                "exploit_probability": prob,
                "predicted_label": pred,
                "risk_level": get_risk_level(prob),
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "tipo": cve.get("tipo"),
            })
        except Exception as e:
            errors += 1
            continue
    
    print(f"✅ Completado: {len(results)} predicciones")
    if errors > 0:
        print(f"⚠️  {errors} errores")
    
    # Guardar si se especifica output
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"💾 Resultados guardados en: {output_file}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Predicción de explotabilidad de CVEs")
    
    parser.add_argument('--cve', type=str, help='CVE ID específico (ej: CVE-2024-1234)')
    parser.add_argument('--top', type=int, help='Top N CVEs más peligrosos')
    parser.add_argument('--min-cvss', type=float, default=0.0, help='CVSS score mínimo')
    parser.add_argument('--batch', action='store_true', help='Procesar todos los CVEs')
    parser.add_argument('--output', type=str, help='Archivo de salida (JSON)')
    parser.add_argument('--explain', action='store_true', help='Mostrar explicación detallada (solo con --cve)')
    parser.add_argument('--model', choices=['v1', 'v2', 'auto'], default='auto', help='Versión del modelo')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  🎯 EXPLOIT PREDICTION ENGINE")
    print("="*70 + "\n")
    
    # Cargar modelo
    print("🔄 Cargando modelo...")
    try:
        model, featurizer, model_name = find_best_model()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        print("\n💡 Entrena un modelo primero:")
        print("   python train_exploit_model.py")
        sys.exit(1)
    
    # Conectar a MongoDB
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    
    # Ejecutar según modo
    if args.cve:
        # Predicción individual
        print(f"\n🔍 Analizando {args.cve}...")
        result = predict_single_cve(args.cve, model, featurizer, db)
        
        if result:
            print("\n" + "="*70)
            print(f"  RESULTADO: {result['cve_id']}")
            print("="*70)
            print(f"\n📊 Probabilidad de explotación: {result['exploit_probability']:.2%}")
            print(f"🎯 Nivel de riesgo: {result['risk_level']}")
            print(f"📈 CVSS Score: {result['cvss_score']:.1f}")
            print(f"🏷️  Tipo: {result['tipo']}")
            if result['componente']:
                print(f"📦 Componente: {result['componente']}")
            print(f"\n📝 Descripción:")
            print(f"   {result['descripcion']}...")
            
            if args.explain:
                # Obtener CVE completo para explicación
                col = db[MONGO_COLLECTION]
                cve = col.find_one({"cve_id": args.cve})
                print(explain_label(cve))
    
    elif args.top:
        # Top N más peligrosos
        print(f"\n🚨 Obteniendo Top {args.top} CVEs más peligrosos...")
        if args.min_cvss > 0:
            print(f"   (con CVSS >= {args.min_cvss})")
        
        results = predict_top_risks(model, featurizer, db, args.top, args.min_cvss)
        
        if results:
            print("\n" + "="*70)
            print(f"  TOP {len(results)} CVEs MÁS PELIGROSOS")
            print("="*70 + "\n")
            
            for i, r in enumerate(results, 1):
                risk_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(r['risk_level'], "⚪")
                
                print(f"{i:2d}. {risk_icon} {r['cve_id']}")
                print(f"    Probabilidad: {r['exploit_probability']:.2%} | CVSS: {r['cvss_score']:.1f} | {r['tipo']}")
            
            if args.output:
                output = {
                    "top_risks": results,
                    "total_analyzed": len(results),
                    "filters": {
                        "min_cvss": args.min_cvss,
                        "limit": args.top
                    },
                    "model": {
                        "name": model_name,
                        "calibrated": "calibrated" in model_name.lower()
                    }
                }
                
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
                
                print(f"\n💾 Resultados guardados en: {args.output}")
    
    elif args.batch:
        # Procesamiento en batch
        results = predict_batch(model, featurizer, db, args.output)
        
        # Estadísticas
        critical = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in results if r['risk_level'] == 'LOW')
        
        print("\n📊 ESTADÍSTICAS:")
        print(f"   🔴 CRITICAL: {critical} ({critical/len(results)*100:.1f}%)")
        print(f"   🟠 HIGH:     {high} ({high/len(results)*100:.1f}%)")
        print(f"   🟡 MEDIUM:   {medium} ({medium/len(results)*100:.1f}%)")
        print(f"   🟢 LOW:      {low} ({low/len(results)*100:.1f}%)")
    
    else:
        parser.print_help()
    
    client.close()
    
    print("\n" + "="*70)
    print("  ✅ PROCESO COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()