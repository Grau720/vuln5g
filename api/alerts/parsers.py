"""
Parsers para logs de Suricata (fast.log y eve.json)
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# Rutas de Suricata
SURICATA_EVE_LOG = Path("/app/runtime/suricata/logs/eve.json")
SURICATA_FAST_LOG = Path("/app/runtime/suricata/logs/fast.log")

# Cache global para datos HTTP
_http_cache = {}


def load_http_cache():
    """Carga datos HTTP desde eve.json en memoria para enriquecimiento"""
    global _http_cache
    _http_cache = {}
    
    if not SURICATA_EVE_LOG.exists():
        logger.warning(f"eve.json not found at {SURICATA_EVE_LOG}")
        return
    
    try:
        with open(SURICATA_EVE_LOG, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line.strip())
                    
                    if event.get('http') and event.get('event_type') in ['alert', 'http']:
                        timestamp = event.get('timestamp', '')
                        src_ip = event.get('src_ip', '')
                        dest_ip = event.get('dest_ip', '')
                        dest_port = event.get('dest_port', 0)
                        
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                ts_key = dt.replace(microsecond=0).isoformat()
                            except:
                                ts_key = timestamp[:19]
                        else:
                            continue
                        
                        key = (ts_key, src_ip, dest_ip, dest_port)
                        _http_cache[key] = event.get('http')
                
                except json.JSONDecodeError:
                    continue
    
    except Exception as e:
        logger.error(f"Error leyendo eve.json: {e}")


def get_http_data(alert: dict) -> dict | None:
    """Busca datos HTTP en el cache para esta alerta"""
    try:
        timestamp = alert.get('timestamp', '')
        src_ip = alert.get('src_ip', '')
        dest_ip = alert.get('dest_ip', '')
        dest_port = alert.get('dest_port', 0)
        
        if not timestamp:
            return None
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            ts_key = dt.replace(microsecond=0).isoformat()
        except:
            ts_key = timestamp[:19]
        
        key = (ts_key, src_ip, dest_ip, dest_port)
        
        if key in _http_cache:
            return _http_cache[key]
        
        # Búsqueda aproximada (±1 segundo)
        for cached_key, http_data in _http_cache.items():
            if (cached_key[0][:19] == ts_key[:19] and
                cached_key[1] == src_ip and
                cached_key[2] == dest_ip and
                cached_key[3] == dest_port):
                return http_data
        
        return None
    
    except Exception as e:
        logger.debug(f"Error obteniendo datos HTTP: {e}")
        return None


def parse_fast_log(limit: int = 500) -> list[dict]:
    """Parsea el archivo fast.log de Suricata"""
    if not SURICATA_FAST_LOG.exists():
        logger.warning(f"fast.log no encontrado en {SURICATA_FAST_LOG}")
        return []
    
    alerts = []
    
    try:
        with open(SURICATA_FAST_LOG, 'r') as f:
            lines = f.readlines()
            for line in reversed(lines[-limit:]):
                if not line.strip():
                    continue
                
                try:
                    alert = parse_fast_log_line(line)
                    if alert:
                        alerts.append(alert)
                except Exception as e:
                    logger.debug(f"Error parseando fast.log: {e}")
                    continue
        
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    except Exception as e:
        logger.error(f"Error leyendo fast.log: {e}")
    
    return alerts[:limit]


def parse_fast_log_line(line: str) -> dict | None:
    """Parsea una línea del fast.log"""
    try:
        # Timestamp
        timestamp_match = re.match(r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)', line)
        if not timestamp_match:
            return None
        timestamp_str = timestamp_match.group(1)
        
        try:
            dt = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
            timestamp_iso = dt.isoformat() + 'Z'
        except:
            timestamp_iso = timestamp_str
        
        # Firma/Mensaje
        msg_match = re.search(r'\[\*\*\]\s*(.*?)\s*\[\*\*\]', line)
        signature = msg_match.group(1) if msg_match else "Unknown"
        
        # SID
        sid_match = re.search(r'\[1:(\d+):\d+\]', line)
        signature_id = int(sid_match.group(1)) if sid_match else 0
        
        # Prioridad
        priority_match = re.search(r'\[Priority:\s*(\d+)\]', line)
        priority = int(priority_match.group(1)) if priority_match else 3
        
        # Protocolo
        proto_match = re.search(r'\{(\w+)\}', line)
        proto = proto_match.group(1) if proto_match else "TCP"
        
        # IPs y puertos
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        src_ip = ip_match.group(1) if ip_match else "0.0.0.0"
        src_port = int(ip_match.group(2)) if ip_match else 0
        dest_ip = ip_match.group(3) if ip_match else "0.0.0.0"
        dest_port = int(ip_match.group(4)) if ip_match else 0
        
        # Clasificación
        classification_match = re.search(r'\[Classification:\s*(.*?)\]', line)
        category = classification_match.group(1) if classification_match else "Unknown"
        
        # CVE en firma (si existe)
        cve_match = re.search(r'CVE-\d{4}-\d+', signature, re.IGNORECASE)
        cve_in_signature = cve_match.group(0).upper() if cve_match else None
        
        return {
            'timestamp': timestamp_iso,
            'alert': {
                'signature': signature,
                'signature_id': signature_id,
                'category': category,
                'severity': priority
            },
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'proto': proto,
            'event_type': 'alert',
            'cve_in_signature': cve_in_signature
        }
    
    except Exception as e:
        logger.debug(f"Error parseando línea: {e}")
        return None