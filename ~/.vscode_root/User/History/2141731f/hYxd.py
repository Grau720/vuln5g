import logging, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pymongo import MongoClient, ReplaceOne, ASCENDING, DESCENDING
from config.settings import (
    MONGO_HOST, MONGO_PORT, MONGO_USER, MONGO_PASS,
    MONGO_DB, MONGO_AUTH_DB, MONGO_COLLECTION
)
from services.ingest.normalize import normalizar_cve
from services.ingest.debug.debug_mapper import DebugMapper
from services.ingest.telemetry import get_metrics, get_audit_tracker, print_metrics
from api.utils.db import ensure_indexes

logger = logging.getLogger("ingest-nvd")

def get_collection():
    """
    Devuelve la colección principal según settings.
    Mantiene la firma que ya usabas en el proyecto.
    """
    mongo_uri = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={MONGO_AUTH_DB}"
    client = MongoClient(mongo_uri)
    db = client[MONGO_DB]
    return db[MONGO_COLLECTION]

def snapshot_history(col, old_doc):
    """
    Guarda un snapshot del documento anterior a una actualización
    en <collection>_history. Quita _id para no colisionar.
    """
    if not old_doc:
        return
    snap = dict(old_doc)
    snap.pop("_id", None)
    snap["ts"] = datetime.utcnow()
    # si no tenía versión, marcamos 1 para el histórico
    snap["version"] = snap.get("version", 1)
    col.database[MONGO_COLLECTION + "_history"].insert_one(snap)

def procesar_cves(cves, collection, max_workers=10, debug=False):
    """
    Ingesta concurrente CON TELEMETRÍA COMPLETA:
      - Normaliza cada CVE (normalizar_cve) con métricas integradas
      - Inserta nuevos con upsert
      - Actualiza existentes si cambia fecha_actualizacion o entran campos enriquecidos
      - Antes de actualizar → snapshot en histórico
      - Incrementa 'version' al actualizar
      - bulk_write para minimizar roundtrips
      - Genera reportes de calidad al finalizar
    """

    ensure_indexes(collection)
    debugger = DebugMapper() if debug else None
    
    # Obtener instancias de telemetría
    metrics = get_metrics()
    audit_tracker = get_audit_tracker()

    operaciones = []
    total = len(cves)
    logger.info(f"🧵 Procesando {total} CVEs con {max_workers} hilos...")

    ENRIQUECIDOS = [
        "descripcion_tecnica",
        "referencias_mitre",
        "fecha_registro_mitre",
        "recomendaciones_remediacion",
        "versiones_afectadas",
        "componente_afectado",
    ]
    
    def is_empty_value(v) -> bool:
        """True si el valor debe considerarse 'vacío' para decidir si actualizar."""
        if v is None:
            return True
        if isinstance(v, str):
            s = v.strip().lower()
            return s == "" or s == "desconocido" or s == "n/a"
        if isinstance(v, (list, tuple, set, dict)):
            return len(v) == 0
        return False

    def procesar_item(i, item):
        """Procesa un item individual con telemetría."""
        try:
            # 1) Normalizar (aquí se registran las métricas internas)
            doc = normalizar_cve(item)
            
            if not doc:
                # Ya registrado como descartado en normalizar_cve
                return {"descartado": True}
            
            cve_id = doc["cve_id"]
            
            if debugger:
                debugger.add(doc)

            # 2) Buscar si ya existe
            existente = collection.find_one({"cve_id": cve_id})

            # 3) Si NO existe → nuevo con version=1 (upsert)
            if not existente:
                doc["version"] = 1
                metrics.registrar_operacion_db("nuevo")
                return {"nuevo": ReplaceOne({"cve_id": cve_id}, doc, upsert=True)}

            # 4) Decidir si actualizar
            actualizar = False
            razon_actualizacion = None

            # 4.1) Si NVD sube lastModified/fecha_actualizacion → actualiza
            if (doc.get("fecha_actualizacion") or "") > (existente.get("fecha_actualizacion") or ""):
                actualizar = True
                razon_actualizacion = "fecha_nvd"
            
            # 4.2) Si entran campos enriquecidos que antes estaban vacíos
            if not actualizar:
                for campo in ENRIQUECIDOS:
                    if campo in doc:
                        if campo not in existente:
                            actualizar = True
                            razon_actualizacion = "campos_enriquecidos"
                            break
                        prev = existente.get(campo)
                        now = doc.get(campo)
                        if is_empty_value(prev) and not is_empty_value(now):
                            actualizar = True
                            razon_actualizacion = "campos_enriquecidos"
                            break

            # 4.3) Diff específico de versiones_afectadas
            if not actualizar:
                prev_ver = existente.get("versiones_afectadas") or []
                now_ver = doc.get("versiones_afectadas") or []
                try:
                    if prev_ver != now_ver:
                        actualizar = True
                        razon_actualizacion = "versiones_diff"
                except Exception as e:
                    # Si no son comparables, forzar update
                    actualizar = True
                    razon_actualizacion = "versiones_diff"
                    logger.warning(f"⚠️ {cve_id}: error comparando versiones ({e}), se fuerza actualización")

            # 5) Si hay que actualizar → snapshot + version++ + replace
            if actualizar:
                try:
                    snapshot_history(collection, existente)
                except Exception as e:
                    logger.warning(f"⚠️ No se pudo snapshot {cve_id}: {e}")
                    metrics.registrar_error("snapshot_failed")
                
                doc["version"] = (existente.get("version") or 1) + 1
                metrics.registrar_operacion_db("actualizado", razon_actualizacion)
                return {"actualizado": ReplaceOne({"cve_id": cve_id}, doc)}

            # 6) Sin cambios sustanciales
            metrics.registrar_operacion_db("sin_cambios")
            return None
            
        except Exception as e:
            logger.exception(f"❌ Error procesando CVE {i}: {e}")
            metrics.registrar_error("procesamiento_cve")
            return None

    # Pool de hilos
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(procesar_item, i, item): i 
            for i, item in enumerate(cves, start=1)
        }
        
        for future in as_completed(future_to_index):
            try:
                resultado = future.result()
            except Exception as e:
                logger.exception(f"❌ Error en hilo: {e}")
                metrics.registrar_error("thread_exception")
                continue

            if not resultado:
                continue

            if "nuevo" in resultado:
                operaciones.append(resultado["nuevo"])
            elif "actualizado" in resultado:
                operaciones.append(resultado["actualizado"])
            # Los descartados ya están contados en metrics

    # Escribir en lote
    if operaciones:
        try:
            result = collection.bulk_write(operaciones, ordered=False)
            logger.info(f"✅ Bulk write completado: {result.bulk_api_result}")
        except Exception as e:
            logger.exception(f"❌ bulk_write falló: {e}")
            metrics.registrar_error("bulk_write_failed")

    # ========================================================================
    # FINALIZAR TELEMETRÍA Y GENERAR REPORTES
    # ========================================================================
    
    metrics.finalizar()
    audit_tracker.finalizar_audits()
    
    # Imprimir resumen en consola
    print_metrics()
    print(audit_tracker.resumen())
    
    # Exportar reportes
    os.makedirs("reports", exist_ok=True)
    
    try:
        # 1. Reporte de métricas
        metrics.to_json("reports/ingest_metrics.json")
        logger.info("✅ Métricas exportadas a reports/ingest_metrics.json")
        
        # 2. Reporte de CVEs con problemas de calidad
        problemas = audit_tracker.get_audits_con_problemas()
        if problemas:
            import json
            with open("reports/cves_con_problemas.json", "w", encoding="utf-8") as f:
                json.dump(
                    [a.to_dict() for a in problemas[:500]],  # Limitar a 500
                    f, 
                    indent=2, 
                    ensure_ascii=False
                )
            logger.info(f"✅ {len(problemas)} CVEs con problemas exportados a reports/cves_con_problemas.json")
        
        # 3. Reporte de baja calidad (quality score < 60)
        baja_calidad = audit_tracker.get_audits_por_quality(0, 60)
        if baja_calidad:
            import csv
            with open("reports/baja_calidad.csv", "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "cve_id", "quality_score", "campos_vacios", 
                    "parsing_warnings", "enriquecimiento_status"
                ])
                for audit in baja_calidad[:1000]:  # Limitar a 1000
                    writer.writerow([
                        audit.cve_id,
                        audit.quality_score,
                        "; ".join(audit.campos_vacios),
                        "; ".join(audit.parsing_warnings[:3]),  # Primeros 3
                        str(audit.enriquecimiento_status)
                    ])
            logger.info(f"✅ {len(baja_calidad)} CVEs de baja calidad exportados a reports/baja_calidad.csv")
        
        # 4. Estadísticas de campos vacíos
        campos_stats = audit_tracker.estadisticas_campos_vacios()
        if campos_stats:
            with open("reports/campos_vacios_stats.json", "w", encoding="utf-8") as f:
                json.dump(campos_stats, f, indent=2, ensure_ascii=False)
            logger.info("✅ Estadísticas de campos vacíos exportadas a reports/campos_vacios_stats.json")
        
    except Exception as e:
        logger.error(f"❌ Error exportando reportes: {e}")

    # Debug mapper (modo legacy)
    if debugger:
        logger.info("\n" + "="*80)
        logger.info("📊 GENERANDO REPORTE DE ANÁLISIS DE MAPPING (DEBUG MODE)")
        logger.info("="*80)
        debugger.print_report()
        
        try:
            debugger.export_json("reports/mapping_analysis.json")
            debugger.export_csv_sin_clasificar("reports/sin_clasificar.csv")
            logger.info("✅ Reportes debug generados")
        except Exception as e:
            logger.error(f"❌ Error en reportes debug: {e}")

    # Resumen final
    logger.info(f"\n{'='*80}")
    logger.info(f"🎯 RESUMEN FINAL DE INGESTA")
    logger.info(f"{'='*80}")
    logger.info(f"✅ {metrics.nuevos_insertados} nuevos insertados")
    logger.info(f"🔁 {metrics.actualizados} actualizados (con versionado)")
    logger.info(f"⏸️  {metrics.sin_cambios} sin cambios")
    logger.info(f"🚫 {metrics.total_descartados} descartados")
    logger.info(f"❌ {sum(metrics.errores_por_tipo.values())} errores totales")
    logger.info(f"📈 Quality Score promedio: {audit_tracker.promedio_quality_score():.1f}/100")
    logger.info(f"{'='*80}\n")