import logging
import sys
from config.settings import NVD_KEYWORDS
from services.ingest.fetch import fetch_cves, fetch_all_keywords
from services.ingest.db import get_collection, procesar_cves
from services.ingest.telemetry import reset_metrics, reset_audit_tracker

# Configuración de logging (consola)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ingest-nvd")

def main():
    """
    Script principal de ingesta con telemetría completa.
    
    Modos disponibles:
      --debug / -d : Activa modo debug con análisis de mapping
      --verbose / -v : Aumenta el nivel de logging
    """
    
    # Parsear argumentos
    debug_mode = '--debug' in sys.argv or '-d' in sys.argv
    verbose_mode = '--verbose' in sys.argv or '-v' in sys.argv
    
    if verbose_mode:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("🔊 Modo verbose activado")
    
    if debug_mode:
        logger.info("🔍 MODO DEBUG ACTIVADO - Se generará reporte de análisis")
    
    # Resetear métricas de ejecuciones anteriores
    reset_metrics()
    reset_audit_tracker()
    
    logger.info("="*80)
    logger.info("🚀 INICIANDO PROCESO DE INGESTA DE VULNERABILIDADES 5G")
    logger.info("="*80)
    logger.info(f"📋 Keywords a buscar: {', '.join(NVD_KEYWORDS[:5])}... ({len(NVD_KEYWORDS)} total)")
    logger.info("")
    
    # ========================================================================
    # FETCH DE DATOS
    # ========================================================================
    
    logger.info("🌐 Fase 1: Descarga de CVEs desde NVD API...")
    try:
        print(NVD_KEYWORDS)
        resultados_por_keyword = fetch_all_keywords(NVD_KEYWORDS)
    except Exception as e:
        logger.error(f"❌ Error crítico durante fetch: {e}")
        logger.exception(e)
        sys.exit(1)
    
    # Consolidar todos los resultados
    total_cves = []
    for keyword, cves in resultados_por_keyword.items():
        logger.info(f"   ✓ {keyword}: {len(cves)} CVEs")
        total_cves.extend(cves)
    
    # Deduplicar por CVE ID
    cves_unicos = {}
    for cve in total_cves:
        cve_id = cve.get("cve", {}).get("id")
        if cve_id and cve_id not in cves_unicos:
            cves_unicos[cve_id] = cve
    
    total_cves = list(cves_unicos.values())
    logger.info(f"\n📊 Total CVEs únicos obtenidos: {len(total_cves)}")
    logger.info("")
    
    # ========================================================================
    # PROCESAMIENTO
    # ========================================================================
    
    logger.info("⚙️  Fase 2: Normalización y procesamiento con telemetría...")
    collection = get_collection()
    
    try:
        procesar_cves(total_cves, collection, debug=debug_mode)
    except Exception as e:
        logger.error(f"❌ Error crítico durante procesamiento: {e}")
        logger.exception(e)
        sys.exit(1)
    
    # ========================================================================
    # FINALIZACIÓN
    # ========================================================================
    
    logger.info("\n" + "="*80)
    logger.info("🎉 INGESTA FINALIZADA EXITOSAMENTE")
    logger.info("="*80)
    
    logger.info("\n📁 REPORTES GENERADOS:")
    logger.info("   ├─ reports/ingest_metrics.json         (métricas completas)")
    logger.info("   ├─ reports/cves_con_problemas.json     (CVEs con issues)")
    logger.info("   ├─ reports/baja_calidad.csv            (quality score < 60)")
    logger.info("   └─ reports/campos_vacios_stats.json    (estadísticas)")
    
    if debug_mode:
        logger.info("\n📁 REPORTES DEBUG ADICIONALES:")
        logger.info("   ├─ reports/mapping_analysis.json")
        logger.info("   └─ reports/sin_clasificar.csv")
    
    logger.info("\n💡 PRÓXIMOS PASOS:")
    logger.info("   1. Revisar reports/ingest_metrics.json para métricas generales")
    logger.info("   2. Analizar reports/baja_calidad.csv para CVEs problemáticos")
    logger.info("   3. Revisar reports/campos_vacios_stats.json para identificar gaps")
    logger.info("")

if __name__ == "__main__":
    main()