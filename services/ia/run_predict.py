"""
==============================================================
    RUN PREDICTIONS - Endpoint de Predicción de Explotabilidad
    v2.1 - Soporte para múltiples versiones de modelo
==============================================================

Script para ejecutar predicciones sobre CVEs individuales
o en batch desde MongoDB.

Uso:
    python run_predict.py --cve CVE-2024-1234
    python run_predict.py --top 20 --min-cvss 7.0
    python run_predict.py --version v2.1 --top 20
    python run_predict.py --batch --output predictions.json
==============================================================
"""

import os
import sys
import json
import argparse
import datetime
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

# Paths de modelos - Diccionario por versión
MODELS = {
    "v1": {
        "base": "/app/ia/models/exploit_model.joblib",
        "calibrated": "/app/ia/models/exploit_model_calibrated.joblib",
        "featurizer": "/app/ia/models/featurizer.joblib",
        "name": "V1 (Heurístico)"
    },
    "v2": {
        "base": "/app/ia/models/exploit_model_v2.joblib",
        "calibrated": "/app/ia/models/exploit_model_v2_calibrated.joblib",
        "featurizer": "/app/ia/models/featurizer_v2.joblib",
        "name": "V2.0 (Smart Labels)"
    },
    "v2.1": {
        "base": "/app/ia/models/exploit_model_v2.1.joblib",
        "calibrated": "/app/ia/models/exploit_model_v2.1_calibrated.joblib",
        "featurizer": "/app/ia/models/featurizer_v2.1.joblib",
        "name": "V2.1 (Attack Vector Aware)"
    }
}


def load_model_version(version, prefer_calibrated=True):
    """
    Carga un modelo específico por versión.
    
    Args:
        version: 'v1', 'v2', 'v2.1', o 'auto'
        prefer_calibrated: Si True, prefiere versión calibrada
    
    Returns:
        (model, featurizer, model_name)
    """
    if version == "auto":
        return find_best_model()
    
    if version not in MODELS:
        raise ValueError(f"Versión '{version}' no válida. Opciones: v1, v2, v2.1, auto")
    
    model_info = MODELS[version]
    featurizer_path = model_info["featurizer"]
    
    # Verificar featurizer
    if not os.path.exists(featurizer_path):
        raise FileNotFoundError(f"Featurizer para {version} no encontrado: {featurizer_path}")
    
    # Intentar cargar calibrado primero
    if prefer_calibrated and os.path.exists(model_info["calibrated"]):
        model = load(model_info["calibrated"])
        featurizer = Featurizer.load(featurizer_path)
        name = f"{model_info['name']} (Calibrado)"
        print(f"✅ Modelo cargado: {name}")
        return model, featurizer, name
    
    # Cargar modelo base
    if os.path.exists(model_info["base"]):
        model = load(model_info["base"])
        featurizer = Featurizer.load(featurizer_path)
        name = model_info['name']
        print(f"✅ Modelo cargado: {name}")
        return model, featurizer, name
    
    raise FileNotFoundError(f"Modelo {version} no encontrado. Entrena el modelo primero.")


def find_best_model():
    """
    Encuentra el mejor modelo disponible.
    Prioridad: V2.1 calibrado > V2.1 > V2.0 calibrado > V2.0 > V1 calibrado > V1
    """
    search_order = [
        ("v2.1", True),   # V2.1 calibrado
        ("v2.1", False),  # V2.1 base
        ("v2", True),     # V2.0 calibrado
        ("v2", False),    # V2.0 base
        ("v1", True),     # V1 calibrado
        ("v1", False),    # V1 base
    ]
    
    for version, calibrated in search_order:
        model_info = MODELS[version]
        model_path = model_info["calibrated"] if calibrated else model_info["base"]
        feat_path = model_info["featurizer"]
        
        if os.path.exists(model_path) and os.path.exists(feat_path):
            model = load(model_path)
            featurizer = Featurizer.load(feat_path)
            name = f"{model_info['name']}" + (" (Calibrado)" if calibrated else "")
            print(f"✅ Usando modelo: {name}")
            return model, featurizer, name
    
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
        
        # Detectar Attack Vector
        vector = cve.get("cvssv3", {}).get("vector", "")
        if "AV:N" in vector:
            attack_vector = "NETWORK"
        elif "AV:L" in vector:
            attack_vector = "LOCAL"
        elif "AV:A" in vector:
            attack_vector = "ADJACENT"
        else:
            attack_vector = "UNKNOWN"
        
        result = {
            "cve_id": cve_id,
            "exploit_probability": prob,
            "predicted_label": pred,
            "risk_level": get_risk_level(prob),
            "cvss_score": cve.get("cvssv3", {}).get("score", 0),
            "attack_vector": attack_vector,
            "tipo": cve.get("tipo", "Desconocido"),
            "componente": cve.get("componente_afectado"),
            "infraestructura_5g": cve.get("infraestructura_5g_afectada", []),
            "descripcion": cve.get("descripcion_general", "")[:200]
        }
        
        return result
        
    except Exception as e:
        print(f"❌ Error procesando {cve_id}: {e}")
        import traceback
        traceback.print_exc()
        return None


def predict_top_risks(model, featurizer, db, limit=10, min_cvss=0.0, attack_vector=None):
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
            # Filtro por Attack Vector si se especifica
            if attack_vector:
                vector = cve.get("cvssv3", {}).get("vector", "")
                if attack_vector.upper() == "NETWORK" and "AV:N" not in vector:
                    continue
                elif attack_vector.upper() == "LOCAL" and "AV:L" not in vector:
                    continue
                elif attack_vector.upper() == "ADJACENT" and "AV:A" not in vector:
                    continue
            
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            
            # Detectar AV
            vector = cve.get("cvssv3", {}).get("vector", "")
            if "AV:N" in vector:
                av = "NETWORK"
            elif "AV:L" in vector:
                av = "LOCAL"
            elif "AV:A" in vector:
                av = "ADJACENT"
            else:
                av = "UNKNOWN"
            
            results.append({
                "cve_id": cve.get("cve_id"),
                "exploit_probability": prob,
                "risk_level": get_risk_level(prob),
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "attack_vector": av,
                "tipo": cve.get("tipo", "Desconocido"),
                "componente": cve.get("componente_afectado"),
                "infraestructura_5g": cve.get("infraestructura_5g_afectada", [])
            })
        except:
            continue
    
    # Ordenar por probabilidad descendente
    results.sort(key=lambda x: x["exploit_probability"], reverse=True)
    
    return results[:limit]


def predict_batch(model, featurizer, db, output_file=None, save_to_db=True):
    """
    Predice sobre todos los CVEs y guarda resultados en MongoDB.
    
    Args:
        save_to_db: Si True, guarda en MongoDB (default: True)
    """
    col = db[MONGO_COLLECTION]
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    
    print(f"🔄 Procesando {len(cves)} CVEs en modo batch...")
    
    results = []
    errors = 0
    saved = 0
    
    for i, cve in enumerate(cves, 1):
        if i % 50 == 0:
            print(f"   Progreso: {i}/{len(cves)} | Guardados: {saved}")
        
        try:
            raw = featurizer.extract_raw_features(cve)
            X = featurizer.transform([raw])
            prob = float(model.predict_proba(X)[0][1])
            pred = int(model.predict(X)[0])
            
            # Detectar AV
            vector = cve.get("cvssv3", {}).get("vector", "")
            if "AV:N" in vector:
                av = "NETWORK"
            elif "AV:L" in vector:
                av = "LOCAL"
            elif "AV:A" in vector:
                av = "ADJACENT"
            else:
                av = "UNKNOWN"
            
            ia_analysis = {
                "exploit_probability": prob,
                "predicted_label": pred,
                "risk_level": get_risk_level(prob),
                "attack_vector": av,
                "model_version": "v2.1_calibrated",
                "last_updated": datetime.datetime.utcnow()
            }
            
            results.append({
                "cve_id": cve.get("cve_id"),
                **ia_analysis,
                "cvss_score": cve.get("cvssv3", {}).get("score", 0),
                "tipo": cve.get("tipo"),
                "infraestructura_5g": cve.get("infraestructura_5g_afectada", [])
            })
            
            # ⭐ GUARDAR EN MONGODB (NUEVO)
            if save_to_db:
                col.update_one(
                    {"_id": cve["_id"]},
                    {"$set": {"ia_analysis": ia_analysis}}
                )
                saved += 1
                
        except Exception as e:
            errors += 1
            continue
    
    print(f"✅ Completado: {len(results)} predicciones")
    if save_to_db:
        print(f"💾 Guardados en DB: {saved} CVEs")
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
    parser.add_argument('--attack-vector', type=str, choices=['network', 'local', 'adjacent'], 
                       help='Filtrar por Attack Vector')
    parser.add_argument('--batch', action='store_true', help='Procesar todos los CVEs')
    parser.add_argument('--output', type=str, help='Archivo de salida (JSON)')
    parser.add_argument('--explain', action='store_true', help='Mostrar explicación detallada (solo con --cve)')
    parser.add_argument('--version', type=str, choices=['v1', 'v2', 'v2.1', 'auto'], 
                       default='auto', help='Versión del modelo a usar')
    parser.add_argument('--no-calibrated', action='store_true', 
                       help='Usar modelo sin calibrar')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("  🎯 EXPLOIT PREDICTION ENGINE v2.1")
    print("="*70 + "\n")
    
    # Cargar modelo
    print("🔄 Cargando modelo...")
    try:
        model, featurizer, model_name = load_model_version(
            args.version, 
            prefer_calibrated=not args.no_calibrated
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ {e}")
        print("\n💡 Modelos disponibles:")
        for ver, info in MODELS.items():
            base_exists = os.path.exists(info['base'])
            cal_exists = os.path.exists(info['calibrated'])
            status = "✅" if (base_exists or cal_exists) else "❌"
            print(f"   {status} {ver}: {info['name']}")
            if base_exists:
                print(f"      - Base: ✅")
            if cal_exists:
                print(f"      - Calibrado: ✅")
        
        print("\n💡 Para entrenar modelos:")
        print("   V1:   python /app/ia/train_exploit_model.py")
        print("   V2.0: python /app/ia/retrain_with_smart_labels.py")
        print("   V2.1: python /app/ia/retrain_with_smart_labels_v21.py")
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
            print(f"🌐 Attack Vector: {result['attack_vector']}")
            print(f"🏷️  Tipo: {result['tipo']}")
            if result['componente']:
                print(f"📦 Componente: {result['componente']}")
            if result['infraestructura_5g']:
                print(f"🔧 Infraestructura 5G: {', '.join(result['infraestructura_5g'])}")
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
            print(f"   Filtro: CVSS >= {args.min_cvss}")
        if args.attack_vector:
            print(f"   Filtro: Attack Vector = {args.attack_vector.upper()}")
        
        results = predict_top_risks(
            model, featurizer, db, 
            args.top, args.min_cvss, args.attack_vector
        )
        
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
                
                av_icon = {
                    "NETWORK": "🌐",
                    "LOCAL": "💻",
                    "ADJACENT": "📡",
                    "UNKNOWN": "❓"
                }.get(r['attack_vector'], "❓")
                
                print(f"{i:2d}. {risk_icon} {r['cve_id']}")
                print(f"    Prob: {r['exploit_probability']:.2%} | CVSS: {r['cvss_score']:.1f} | {av_icon} {r['attack_vector']} | {r['tipo']}")
                if r['infraestructura_5g']:
                    print(f"    5G: {', '.join(r['infraestructura_5g'][:3])}")
            
            if args.output:
                output = {
                    "top_risks": results,
                    "total_analyzed": len(results),
                    "filters": {
                        "min_cvss": args.min_cvss,
                        "attack_vector": args.attack_vector,
                        "limit": args.top
                    },
                    "model": {
                        "name": model_name,
                        "version": args.version,
                        "calibrated": "calibrado" in model_name.lower()
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
        
        # Estadísticas por Attack Vector
        av_stats = {}
        for r in results:
            av = r['attack_vector']
            if av not in av_stats:
                av_stats[av] = {'total': 0, 'critical': 0, 'high': 0}
            av_stats[av]['total'] += 1
            if r['risk_level'] == 'CRITICAL':
                av_stats[av]['critical'] += 1
            elif r['risk_level'] == 'HIGH':
                av_stats[av]['high'] += 1
        
        print("\n📊 POR ATTACK VECTOR:")
        for av, stats in sorted(av_stats.items(), key=lambda x: x[1]['total'], reverse=True):
            crit_pct = stats['critical'] / stats['total'] * 100 if stats['total'] > 0 else 0
            print(f"   {av:12s}: {stats['total']:3d} CVEs | {stats['critical']} CRITICAL ({crit_pct:.1f}%)")
    
    else:
        parser.print_help()
    
    client.close()
    
    print("\n" + "="*70)
    print("  ✅ PROCESO COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()