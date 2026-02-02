"""
Generación de estadísticas de alertas
"""

from collections import defaultdict
from datetime import datetime, timedelta


def generate_statistics(alerts: list) -> dict:
    """Genera estadísticas de alertas"""
    stats = {
        'by_severity': defaultdict(int),
        'by_vuln_type': defaultdict(int),
        'by_category': defaultdict(int),
        'by_enrichment': defaultdict(int)
    }
    
    for alert in alerts:
        alert_data = alert.get('alert', {})
        
        severity = alert_data.get('severity', 3)
        stats['by_severity'][severity] += 1
        
        vuln_type = alert.get('vuln_type') or 'Unknown'
        stats['by_vuln_type'][vuln_type] += 1
        
        category = alert_data.get('category', 'Unknown')
        stats['by_category'][category] += 1
        
        enrichment = alert.get('enrichment_status', 'UNKNOWN')
        stats['by_enrichment'][enrichment] += 1
    
    return {
        'by_severity': dict(stats['by_severity']),
        'by_vuln_type': dict(stats['by_vuln_type']),
        'by_category': dict(stats['by_category']),
        'by_enrichment': dict(stats['by_enrichment'])
    }


def generate_timeline(alerts: list, hours: int) -> list:
    """Timeline de alertas por hora"""
    hourly = defaultdict(int)
    
    for alert in alerts:
        timestamp_str = alert.get('timestamp', '')
        if not timestamp_str:
            continue
        
        try:
            if 'T' in timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp_str)
            
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            hourly[hour_key] += 1
        except Exception:
            continue
    
    now = datetime.utcnow()
    timeline = []
    
    for i in range(hours):
        hour = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00')
        timeline.append({
            'hour': hour,
            'count': hourly.get(hour, 0)
        })
    
    return sorted(timeline, key=lambda x: x['hour'])