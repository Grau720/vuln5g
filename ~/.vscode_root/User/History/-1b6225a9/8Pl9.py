import requests
import time
import logging
import json
import os
import datetime
from config.settings import NVD_BASE_URL, NVD_RESULTS_PER_PAGE, SLEEP_SECONDS

logger = logging.getLogger("ingest-nvd")

NVD_API_KEY = os.getenv("NVD_API_KEY")
INGEST_STATE_FILE = "/app/data/last_successful_ingest.json"

# =========================================================
# NUEVO: Filtro de estados
# =========================================================
ESTADOS_VALIDOS = {
    "Analyzed",           # CVEs completos con CPEs
    "Modified",           # CVEs actualizados (también completos)
    # "Undergoing Analysis"  # Opcional: en proceso pero puede tener datos parciales
}

ESTADOS_RECHAZADOS = {
    "Awaiting Analysis",  # Sin CPEs/CVSS oficial
    "Received",           # Recién publicado
    "Rejected",           # CVE rechazado
    "Deferred"            # Pospuesto
}

def cargar_last_run():
    if not os.path.exists(INGEST_STATE_FILE):
        logger.info("No existe archivo de estado, será la primera ejecución.")
        return None

    try:
        with open(INGEST_STATE_FILE, "r") as f:
            data = json.load(f)
            return datetime.datetime.fromisoformat(data["last_run"]).astimezone(datetime.timezone.utc)
    except Exception as e:
        logger.error(f"No se pudo leer last_run: {e}")
        return None


def guardar_last_run(dt):
    os.makedirs(os.path.dirname(INGEST_STATE_FILE), exist_ok=True)
    with open(INGEST_STATE_FILE, "w") as f:
        json.dump({
            "last_run": dt.astimezone(datetime.timezone.utc).isoformat()
        }, f)


def nvd_request_with_backoff(url, params, max_retries=4):
    headers = {"apiKey": NVD_API_KEY}
    backoff = 2
    intento = 1

    while intento <= max_retries:
        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code == 200:
            return resp

        if resp.status_code in (429, 500, 503):
            logger.warning(f"⚠️ NVD {resp.status_code}. Reintentando en {backoff}s…")
            time.sleep(backoff)
            backoff *= 2
            intento += 1
            continue

        logger.error(f"❌ Error {resp.status_code} en petición NVD")
        return resp

    logger.error("❌ Límite de reintentos alcanzado. Abortando ventana.")
    return None


def generar_ventanas_temporales(fecha_inicio, fecha_fin):
    ventanas = []
    fecha_actual = fecha_inicio

    while fecha_actual < fecha_fin:
        fecha_limite = fecha_actual + datetime.timedelta(days=120)

        if fecha_limite > fecha_fin:
            fecha_limite = fecha_fin

        ventanas.append((fecha_actual, fecha_limite))
        fecha_actual = fecha_limite + datetime.timedelta(milliseconds=1)

    return ventanas


def fetch_cves_en_ventana(keyword, ventana_start, ventana_end):
    """
    MODIFICADO: Filtra CVEs por vulnStatus antes de retornarlos.
    """
    resultados = []
    rechazados_por_estado = 0
    start_index = 0

    pubStart = ventana_start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pubEnd   = ventana_end.strftime("%Y-%m-%dT%H:%M:%S.000")

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
            "startIndex": start_index,
            "pubStartDate": pubStart,
            "pubEndDate": pubEnd,
        }

        resp = nvd_request_with_backoff(NVD_BASE_URL, params)
        if resp is None or resp.status_code != 200:
            break

        data = resp.json()
        nuevos = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        if start_index == 0:
            if total > 0:
                logger.info(f"   → {total} CVEs encontradas en NVD")
            else:
                break

        # ========================================================
        # NUEVO: FILTRAR POR vulnStatus
        # ========================================================
        for vuln in nuevos:
            cve_data = vuln.get("cve", {})
            status = cve_data.get("vulnStatus", "Unknown")
            cve_id = cve_data.get("id", "N/A")
            
            if status in ESTADOS_VALIDOS:
                resultados.append(vuln)
            else:
                rechazados_por_estado += 1
                if rechazados_por_estado <= 3:  # Log primeros 3
                    logger.debug(f"   ⏸ {cve_id} rechazado (estado: {status})")

        start_index += NVD_RESULTS_PER_PAGE
        if start_index >= total:
            break

        time.sleep(SLEEP_SECONDS)

    if rechazados_por_estado > 0:
        logger.info(f"   ⏸ {rechazados_por_estado} CVEs omitidos por estado incompleto")

    return resultados


def fetch_all_cves_for_keyword(keyword, fecha_inicio, fecha_fin):
    """
    Busca CVEs para una keyword en el rango de fechas dado.
    AHORA con filtrado por estado.
    """
    logger.info(f"\n=== 🔍 Iniciando ingesta de CVEs para '{keyword}' ===")
    logger.info(f"📅 Rango: {fecha_inicio.date()} → {fecha_fin.date()}")

    ventanas = generar_ventanas_temporales(fecha_inicio, fecha_fin)
    resultados_totales = []
    total_ventanas = len(ventanas)

    for i, (vstart, vend) in enumerate(ventanas, start=1):
        logger.info(f"⏱ Ventana {i}/{total_ventanas}: {vstart.date()} → {vend.date()}")
        resultados = fetch_cves_en_ventana(keyword, vstart, vend)

        if resultados:
            logger.info(f"   ✔ {len(resultados)} CVEs válidas añadidas")

        resultados_totales.extend(resultados)

    logger.info(f"=== ✅ Ingesta finalizada | Total CVEs válidas: {len(resultados_totales)} ===\n")

    return resultados_totales


def fetch_all_keywords(keywords_list):
    """
    Procesa TODAS las keywords con las MISMAS fechas de inicio y fin.
    MODIFICADO: Ventana de 90 días hacia atrás para capturar CVEs procesados.
    """
    logger.info("\n" + "="*60)
    logger.info("🚀 INICIO DE INGESTA MASIVA DE CVEs")
    logger.info("="*60 + "\n")
    
    last_run = cargar_last_run()
    today = datetime.datetime.now(datetime.timezone.utc)
    
    # ========================================================
    # MODIFICADO: Ventana más amplia hacia atrás
    # ========================================================
    if last_run is None:
        # Primera ejecución: últimos 6 meses (suficiente para CVEs procesados)
        logger.info("📅 Primera ejecución → últimos 6 meses de CVEs procesados")
        fecha_inicio = today - datetime.timedelta(days=180)
    else:
        # Ingesta incremental: desde último run - 7 días (buffer para CVEs que pasaron a "Analyzed")
        buffer_dias = 7
        fecha_inicio = last_run - datetime.timedelta(days=buffer_dias)
        logger.info(f"📅 Ingesta incremental con buffer de {buffer_dias} días")
        logger.info(f"   → desde {fecha_inicio.date()} hasta {today.date()}")

    logger.info(f"📊 Keywords a procesar: {len(keywords_list)}")
    logger.info(f"🎯 Estados válidos: {', '.join(ESTADOS_VALIDOS)}")
    logger.info(f"📅 Rango aplicado: {fecha_inicio.date()} → {today.date()}\n")

    resultados_por_keyword = {}
    
    for idx, keyword in enumerate(keywords_list, start=1):
        logger.info(f"[{idx}/{len(keywords_list)}] Procesando keyword: '{keyword}'")
        
        cves = fetch_all_cves_for_keyword(keyword, fecha_inicio, today)
        resultados_por_keyword[keyword] = cves
        
        if idx < len(keywords_list):
            time.sleep(1)

    guardar_last_run(today)
    logger.info(f"\n💾 Estado guardado: {today.date()}")
    
    total_cves = sum(len(cves) for cves in resultados_por_keyword.values())
    
    logger.info("\n" + "="*60)
    logger.info(f"✅ INGESTA COMPLETA FINALIZADA")
    logger.info(f"📊 Total CVEs válidas obtenidas: {total_cves}")
    logger.info(f"📅 Próxima ejecución desde: {(today - datetime.timedelta(days=7)).date()} (con buffer)")
    logger.info("="*60 + "\n")

    return resultados_por_keyword


def fetch_cves(keyword):
    """
    Función de compatibilidad para procesar una sola keyword.
    MODIFICADO: Usa ventana de 90 días hacia atrás.
    """
    last_run = cargar_last_run()
    today = datetime.datetime.now(datetime.timezone.utc)
    
    if last_run is None:
        fecha_inicio = today - datetime.timedelta(days=180)
    else:
        fecha_inicio = last_run - datetime.timedelta(days=7)
    
    resultados = fetch_all_cves_for_keyword(keyword, fecha_inicio, today)
    guardar_last_run(today)
    
    return resultados