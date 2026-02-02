"""
Módulo de alertas - endpoints y lógica
"""

from api.alerts.parsers import (
    load_http_cache,
    get_http_data,
    parse_fast_log,
    parse_fast_log_line
)

from api.alerts.enrichment import (
    extract_vulnerability_type,
    extract_attack_vector,
    enrich_alert
)

from api.alerts.cve_suggestions import suggest_potential_cves

from api.alerts.statistics import (
    generate_statistics,
    generate_timeline
)

from api.alerts.helpers import (
    get_correlation_engine,
    get_whitelist_engine,
    get_asset_manager,
    is_alert_whitelisted,
    store_alert_in_mongodb
)

__all__ = [
    # Parsers
    'load_http_cache',
    'get_http_data',
    'parse_fast_log',
    'parse_fast_log_line',
    
    # Enrichment
    'extract_vulnerability_type',
    'extract_attack_vector',
    'enrich_alert',
    
    # CVE Suggestions
    'suggest_potential_cves',
    
    # Statistics
    'generate_statistics',
    'generate_timeline',
    
    # Helpers
    'get_correlation_engine',
    'get_whitelist_engine',
    'get_asset_manager',
    'is_alert_whitelisted',
    'store_alert_in_mongodb'
]