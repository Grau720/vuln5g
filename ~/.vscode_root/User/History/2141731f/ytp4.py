# services/ingest/db.py
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
    Ingesta concurrente:
      - Normaliza cada CVE (normalizar_cve)
      - Inserta nuevos con upsert
      - Actualiza existentes si cambia fecha_actualizacion o entran campos enriquecidos
      - Antes de actualizar → snapshot en histórico
      - Incrementa 'version' al actualizar
      - bulk_write para minimizar roundtrips
    """

    ensure_indexes(collection)
    debugger = DebugMapper() if debug else None

    nuevos = 0
    actualizados = 0
    descartados = 0
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
        # 1) sanity: debe venir el bloque "cve"
        cve_obj = item.get("cve")
        if not cve_obj or not cve_obj.get("id"):
            return {"descartado": True}
        cve_id = cve_obj["id"]

        # 2) normaliza usando el ITEM COMPLETO (trae configurations)
        doc = normalizar_cve(item)
        if not doc:
            return {"descartado": True}
        
        if debugger:
            debugger.add(doc)

        # (opcional) log de lo que extrajimos
        vers = doc.get("versiones_afectadas") or []
        # logger.info(f"📄 {cve_id} → versiones_afectadas extraídas: {vers if vers else '[]'}")

        # 3) busca si ya existe
        existente = collection.find_one({"cve_id": cve_id})

        # 4) si NO existe → nuevo con version=1 (upsert)
        if not existente:
            doc["version"] = 1
            return {"nuevo": ReplaceOne({"cve_id": cve_id}, doc, upsert=True)}

        # 5) decidir si actualizar
        actualizar = False

        # 5.1) si NVD sube lastModified/fecha_actualizacion → actualiza
        if (doc.get("fecha_actualizacion") or "") > (existente.get("fecha_actualizacion") or ""):
            actualizar = True
        else:
            for campo in ENRIQUECIDOS:
                if campo in doc:
                    if campo not in existente:
                        actualizar = True
                        break
                    prev = existente.get(campo)
                    now = doc.get(campo)
                    if is_empty_value(prev) and not is_empty_value(now):
                        actualizar = True
                        break



        # 5.2) si entran campos enriquecidos que antes estaban vacíos/inexistentes
        if not actualizar:
            for campo in ENRIQUECIDOS:
                prev = existente.get(campo, None)
                now = doc.get(campo, None)
                if prev is None and now is not None:
                    actualizar = True
                    logger.debug(f"🔄 {cve_id} → campo nuevo {campo}")
                    break
                if (prev in ("", [], None)) and (now not in ("", [], None)):
                    actualizar = True
                    logger.debug(f"🔄 {cve_id} → campo {campo} ahora con datos")
                    break

        # 5.3) diff específico de versiones_afectadas (aunque estén ambas pobladas)
        if not actualizar:
            prev_ver = existente.get("versiones_afectadas") or []
            now_ver  = doc.get("versiones_afectadas") or []
            try:
                if prev_ver != now_ver:
                    actualizar = True
                    # log compacto (muestra tamaño y primera entrada)
                    prev_head = prev_ver[0] if prev_ver else None
                    now_head  = now_ver[0] if now_ver else None
                    # logger.info(
                    #     f"🔄 {cve_id}: versiones_afectadas cambiaron {len(prev_ver)}→{len(now_ver)} | "
                    #     f"prev[0]={prev_head} → now[0]={now_head}"
                    # )
            except Exception as e:
                # si por tipos no comparables, forzamos update por seguridad
                actualizar = True
                logger.warning(f"⚠️ {cve_id}: error comparando versiones_afectadas ({e}), se fuerza actualización")

        # 6) si hay que actualizar → snapshot + version++ + replace
        if actualizar:
            try:
                snapshot_history(collection, existente)
            except Exception as e:
                logger.warning(f"⚠️ No se pudo snapshot {cve_id}: {e}")
            doc["version"] = (existente.get("version") or 1) + 1
            return {"actualizado": ReplaceOne({"cve_id": cve_id}, doc)}

        # logger.info(f"✅ {nuevos} nuevos insertados")
        # logger.info(f"🔁 {actualizados} actualizados (con versionado)")
        if descartados > 0:
            logger.warning(f"🚫 {descartados} descartados")

        # 7) sin cambios sustanciales
        return None
    # Pool de hilos
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {executor.submit(procesar_item, i, item): i for i, item in enumerate(cves, start=1)}
        for future in as_completed(future_to_index):
            try:
                resultado = future.result()
            except Exception as e:
                logger.exception(f"❌ Error procesando CVE en hilo: {e}")
                continue

            if not resultado:
                continue

            if "nuevo" in resultado:
                operaciones.append(resultado["nuevo"])
                nuevos += 1
            elif "actualizado" in resultado:
                operaciones.append(resultado["actualizado"])
                actualizados += 1
            elif "descartado" in resultado:
                descartados += 1

    # Escribir en lote
    if operaciones:
        try:
            collection.bulk_write(operaciones, ordered=False)
        except Exception as e:
            logger.exception(f"❌ bulk_write falló: {e}")

    if debugger:
        logger.info("\n" + "="*80)
        logger.info("📊 GENERANDO REPORTE DE ANÁLISIS DE MAPPING")
        logger.info("="*80)
        debugger.print_report()
                
        # Exportar reportes
        import os
        os.makedirs("reports", exist_ok=True)
        debugger.export_json("reports/mapping_analysis.json")
        debugger.export_csv_sin_clasificar("reports/sin_clasificar.csv")
        logger.info("✅ Reportes generados en ./reports/")


    logger.info(f"✅ {nuevos} nuevos insertados")
    logger.info(f"🔁 {actualizados} actualizados (con versionado)")
    if descartados > 0:
        logger.warning(f"🚫 {descartados} descartados")
