"""
Helpers de inicialización para el módulo de alertas
"""

import logging
from datetime import datetime
from bson import ObjectId

logger = logging.getLogger(__name__)

# Caches globales
_correlation_engine = None
_whitelist_engine = None
_asset_manager = None


def get_correlation_engine(mongo_db):
    """Obtiene o inicializa el engine de correlación"""
    global _correlation_engine
    if _correlation_engine is None:
        from correlation.correlation_engine import CorrelationEngine
        _correlation_engine = CorrelationEngine(mongo_db)
        _correlation_engine.create_indexes()
    return _correlation_engine


def get_whitelist_engine(mongo_db):
    """Obtiene o inicializa el WhitelistEngine"""
    global _whitelist_engine
    if _whitelist_engine is None:
        from api.assets.inventory import WhitelistEngine
        _whitelist_engine = WhitelistEngine(mongo_db)
    return _whitelist_engine


def get_asset_manager(mongo_db):
    """Obtiene o inicializa el AssetInventoryManager"""
    global _asset_manager
    if _asset_manager is None:
        from api.assets.inventory import AssetInventoryManager
        _asset_manager = AssetInventoryManager(mongo_db)
    return _asset_manager


def is_alert_whitelisted(alert: dict, whitelist_engine) -> tuple[bool, str | None]:
    """
    Verifica si una alerta debe ser ignorada según whitelist.
    
    Args:
        alert: Alerta a verificar
        whitelist_engine: Instancia de WhitelistEngine
    
    Returns:
        Tupla (is_whitelisted, reason)
    """
    try:
        is_whitelisted, reason, rule_id = whitelist_engine.is_whitelisted(alert)
        
        if is_whitelisted:
            logger.debug(
                f"🔇 Alerta whitelisted: {alert.get('src_ip')}→"
                f"{alert.get('dest_ip')}:{alert.get('dest_port')} - {reason}"
            )
        
        return is_whitelisted, reason
    
    except Exception as e:
        logger.warning(f"Error verificando whitelist: {e}")
        return False, None


def store_alert_in_mongodb(alert: dict, mongo_db, correlation_engine,
                           skip_whitelist: bool = False,
                           whitelist_engine=None) -> ObjectId | None:
    """
    Almacena una alerta en MongoDB y la correlaciona con un INCIDENTE.
    
    Args:
        alert: Alerta a almacenar
        mongo_db: Base de datos MongoDB
        correlation_engine: Engine de correlación
        skip_whitelist: Si True, no verifica whitelist
        whitelist_engine: Engine de whitelist (requerido si skip_whitelist=False)
    
    Returns:
        ObjectId de la alerta insertada o None si fue filtrada
    """
    try:
        # Verificar whitelist
        if not skip_whitelist:
            if whitelist_engine is None:
                raise ValueError("whitelist_engine es requerido cuando skip_whitelist=False")
            
            is_whitelisted, reason = is_alert_whitelisted(alert, whitelist_engine)
            if is_whitelisted:
                logger.info(
                    f"🔇 Alerta IGNORADA (whitelisted): {alert.get('src_ip')}→"
                    f"{alert.get('dest_ip')}:{alert.get('dest_port')} - {reason}"
                )
                return None
        
        alerts_col = mongo_db['alerts']
        
        # Metadatos de ingesta
        alert['ingested_at'] = datetime.utcnow()
        alert['source'] = 'suricata'
        
        # Correlacionar con INCIDENTE
        group_id = correlation_engine.correlate_alert(alert)
        
        if group_id:
            alert['correlation_group_id'] = group_id
        
        # Insertar
        result = alerts_col.insert_one(alert)
        
        logger.debug(f"✅ Alerta almacenada: {result.inserted_id}")
        return result.inserted_id
    
    except Exception as e:
        logger.error(f"Error almacenando alerta en MongoDB: {e}")
        return None