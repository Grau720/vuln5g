import logging
import sys
from config.settings import NVD_KEYWORDS
from services.ingest.fetch import fetch_cves, fetch_all_keywords
from services.ingest.db import get_collection, procesar_cves

# Configuración de logging (consola)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ingest-nvd")

def main():
    debug_mode = '--debug' in sys.argv or '-d' in sys.argv
    
    if debug_mode:
        logger.info("🔍 MODO DEBUG ACTIVADO - Se generará reporte de análisis")
    
    logger.info("🚀 Iniciando proceso de ingesta de vulnerabilidades 5G")
    
    # ✅ USAR fetch_all_keywords en lugar de bucle manual
    resultados_por_keyword = fetch_all_keywords(NVD_KEYWORDS)
    
    # Consolidar todos los resultados
    total_cves = []
    for cves in resultados_por_keyword.values():
        total_cves.extend(cves)
    
    collection = get_collection()
    logger.info("🚀 Iniciando proceso de normalización")
    procesar_cves(total_cves, collection, debug=debug_mode)
    
    logger.info(f"🎯 Ingesta finalizada. Total CVEs obtenidas: {len(total_cves)}")
    
    if debug_mode:
        logger.info("\n📁 Reportes disponibles en:")
        logger.info("   - reports/mapping_analysis.json")
        logger.info("   - reports/sin_clasificar.csv")

if __name__ == "__main__":
    main()