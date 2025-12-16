#!/usr/bin/env python3
"""
Script para re-enriquecer CVEs incompletos.
Busca CVEs con quality_score < 60 o campos vacíos críticos,
y re-consulta NVD para actualizar.

Uso:
    python scripts/reenrich.py --days 30  # Re-enriquecer CVEs de últimos 30 días
    python scripts/reenrich.py --cve-file missing_cves.txt  # Desde archivo
"""

import sys
import logging
import argparse
from datetime import datetime, timedelta, timezone
from pymongo import UpdateOne

from services.ingest.db import get_collection
from services.ingest.fetch import nvd_request_with_backoff
from services.ingest.normalize import normalizar_cve
from config.settings import NVD_BASE_URL

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
logger = logging.getLogger("reenrich")


def identificar_cves_incompletos(collection, dias=30):
    """
    Encuentra CVEs con problemas de calidad.
    """
    fecha_limite = datetime.now(timezone.utc) - timedelta(days=dias)
    
    query = {
        "$or": [
            # Sin versiones afectadas
            {
                "$or": [
                    {"versiones_afectadas": {"$exists": False}},
                    {"versiones_afectadas": []},
                    {"versiones_afectadas": None}
                ]
            },
            # Sin componente
            {
                "$or": [
                    {"componente_afectado": {"$exists": False}},
                    {"componente_afectado": None},
                    {"componente_afectado": ""}
                ]
            },
            # Sin CVSS
            {
                "$or": [
                    {"cvssv3.score": {"$lte": 0}},
                    {"cvssv3.score": {"$exists": False}}
                ]
            },
            # Quality score bajo
            {"_quality_audit.quality_score": {"$lt": 60}}
        ],
        # Solo CVEs recientes
        "fecha_publicacion_dt": {"$gte": fecha_limite}
    }
    
    cves = list(collection.find(query, {"cve_id": 1, "_quality_audit": 1}))
    logger.info(f"📊 Encontrados {len(cves)} CVEs candidatos para re-enriquecimiento")
    
    return [doc["cve_id"] for doc in cves]


def reenriquecer_cve(cve_id: str, collection) -> bool:
    """
    Re-consulta NVD y actualiza el CVE si hay cambios.
    """
    try:
        # Consultar NVD
        params = {"cveId": cve_id}
        resp = nvd_request_with_backoff(NVD_BASE_URL, params)
        
        if not resp or resp.status_code != 200:
            logger.warning(f"⚠️ No se pudo consultar NVD para {cve_id}")
            return False
        
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            logger.warning(f"⚠️ CVE {cve_id} no encontrado en NVD")
            return False
        
        vuln = vulnerabilities[0]
        
        # Verificar estado
        status = vuln.get("cve", {}).get("vulnStatus", "Unknown")
        if status not in ["Analyzed", "Modified"]:
            logger.debug(f"⏸ {cve_id} aún en estado '{status}', omitiendo")
            return False
        
        # Normalizar
        doc_nuevo = normalizar_cve(vuln)
        
        if not doc_nuevo:
            logger.warning(f"⚠️ Error normalizando {cve_id}")
            return False
        
        # Obtener documento existente
        doc_existente = collection.find_one({"cve_id": cve_id})
        
        if not doc_existente:
            logger.warning(f"⚠️ {cve_id} no existe en BD")
            return False
        
        # Comparar campos críticos
        cambios = []
        
        # 1. Versiones
        vers_old = doc_existente.get("versiones_afectadas", [])
        vers_new = doc_nuevo.get("versiones_afectadas", [])
        if vers_new and vers_new != vers_old:
            cambios.append("versiones")
        
        # 2. Componente
        comp_old = doc_existente.get("componente_afectado")
        comp_new = doc_nuevo.get("componente_afectado")
        if comp_new and comp_new != comp_old:
            cambios.append("componente")
        
        # 3. CVSS
        cvss_old = doc_existente.get("cvssv3", {}).get("score", 0)
        cvss_new = doc_nuevo.get("cvssv3", {}).get("score", 0)
        if cvss_new > 0 and cvss_new != cvss_old:
            cambios.append("cvss")
        
        # 4. Configurations (metadata)
        if doc_nuevo.get("_metadata", {}).get("fuente_componente") == "CPE":
            cambios.append("configurations")
        
        if not cambios:
            logger.debug(f"⏸ {cve_id} sin cambios significativos")
            return False
        
        # Actualizar
        doc_nuevo["version"] = (doc_existente.get("version", 1)) + 1
        doc_nuevo["_metadata"]["reenriquecimiento"] = {
            "fecha": datetime.now(timezone.utc).isoformat(),
            "cambios": cambios
        }
        
        result = collection.replace_one({"cve_id": cve_id}, doc_nuevo)
        
        if result.modified_count > 0:
            logger.info(f"✅ {cve_id} actualizado (cambios: {', '.join(cambios)})")
            return True
        else:
            logger.warning(f"⚠️ {cve_id} no se actualizó en BD")
            return False
        
    except Exception as e:
        logger.error(f"❌ Error re-enriqueciendo {cve_id}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Re-enriquecer CVEs incompletos")
    parser.add_argument("--days", type=int, default=30, help="Días hacia atrás (default: 30)")
    parser.add_argument("--cve-file", type=str, help="Archivo con lista de CVE IDs")
    parser.add_argument("--limit", type=int, help="Límite de CVEs a procesar")
    
    args = parser.parse_args()
    
    collection = get_collection()
    
    # Obtener lista de CVEs
    if args.cve_file:
        logger.info(f"📂 Leyendo CVEs desde {args.cve_file}")
        with open(args.cve_file, 'r') as f:
            cve_ids = [line.strip() for line in f if line.strip()]
    else:
        logger.info(f"🔍 Buscando CVEs incompletos (últimos {args.days} días)...")
        cve_ids = identificar_cves_incompletos(collection, args.days)
    
    if args.limit:
        cve_ids = cve_ids[:args.limit]
        logger.info(f"📊 Limitando a {args.limit} CVEs")
    
    if not cve_ids:
        logger.info("✅ No hay CVEs para re-enriquecer")
        return
    
    logger.info(f"🚀 Procesando {len(cve_ids)} CVEs...")
    
    actualizados = 0
    sin_cambios = 0
    errores = 0
    
    for i, cve_id in enumerate(cve_ids, 1):
        logger.info(f"[{i}/{len(cve_ids)}] Procesando {cve_id}...")
        
        try:
            if reenriquecer_cve(cve_id, collection):
                actualizados += 1
            else:
                sin_cambios += 1
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            errores += 1
        
        # Rate limiting
        import time
        time.sleep(0.7)
    
    logger.info("\n" + "="*60)
    logger.info("📊 RESUMEN DE RE-ENRIQUECIMIENTO")
    logger.info("="*60)
    logger.info(f"✅ Actualizados: {actualizados}")
    logger.info(f"⏸️  Sin cambios: {sin_cambios}")
    logger.info(f"❌ Errores: {errores}")
    logger.info("="*60)


if __name__ == "__main__":
    main()