"""
Lógica de sugerencias de CVEs para alertas
"""

import os
import logging

logger = logging.getLogger(__name__)


def suggest_potential_cves(alert: dict, asset: dict | None, cve_collection) -> list[dict]:
    """
    SUGIERE CVEs potencialmente aplicables basándose en:
    1. Tipo de ataque detectado
    2. Asset conocido (si existe en inventario)
    3. Componente 5G (si aplica)
    
    IMPORTANTE: Estos son SUGERENCIAS, no correlaciones confirmadas.
    El analista debe validar manualmente.
    
    Args:
        alert: Datos de la alerta
        asset: Datos del asset destino (puede ser None)
        cve_collection: Colección MongoDB de CVEs
    
    Returns:
        Lista de CVEs sugeridos con nivel de confianza
    """
    from api.alerts.enrichment import extract_vulnerability_type
    
    suggestions = []
    vuln_type = alert.get('vuln_type') or extract_vulnerability_type(alert)
    
    if not vuln_type:
        return []
    
    try:
        # Construir query base
        query = {'tipo': {'$regex': vuln_type, '$options': 'i'}}
        
        # Si tenemos asset con información de componente 5G
        if asset:
            component_5g = asset.get('component_5g')
            software = asset.get('software')
            version = asset.get('version')
            
            if component_5g:
                # Buscar CVEs específicos del componente 5G
                query_5g = {
                    **query,
                    'infraestructura_5g_afectada': {'$regex': component_5g, '$options': 'i'}
                }
                cves_5g = list(cve_collection.find(query_5g).limit(5))
                
                for cve in cves_5g:
                    suggestions.append({
                        'cve_id': cve['cve_id'],
                        'nombre': cve.get('nombre', ''),
                        'cvss_score': cve.get('cvssv3', {}).get('score'),
                        'tipo': cve.get('tipo'),
                        'match_reason': f"Componente 5G ({component_5g}) + Tipo de ataque ({vuln_type})",
                        'confidence': 'MEDIUM',
                        'requires_validation': True,
                        'infraestructura_5g': cve.get('infraestructura_5g_afectada', [])
                    })
            
            if software:
                # Buscar CVEs del software específico
                query_sw = {
                    **query,
                    '$or': [
                        {'componente_afectado': {'$regex': software, '$options': 'i'}},
                        {'etiquetas': {'$regex': software, '$options': 'i'}},
                        {'descripcion_general': {'$regex': software, '$options': 'i'}}
                    ]
                }
                cves_sw = list(cve_collection.find(query_sw).limit(5))
                
                for cve in cves_sw:
                    # Evitar duplicados
                    if not any(s['cve_id'] == cve['cve_id'] for s in suggestions):
                        suggestions.append({
                            'cve_id': cve['cve_id'],
                            'nombre': cve.get('nombre', ''),
                            'cvss_score': cve.get('cvssv3', {}).get('score'),
                            'tipo': cve.get('tipo'),
                            'match_reason': f"Software ({software}) + Tipo de ataque ({vuln_type})",
                            'confidence': 'MEDIUM',
                            'requires_validation': True,
                            'version_check_needed': version is not None
                        })
        
        else:
            # Sin asset conocido: sugerencias de BAJA confianza solo por tipo
            cves_generic = list(cve_collection.find(query).sort('cvssv3.score', -1).limit(3))
            
            for cve in cves_generic:
                suggestions.append({
                    'cve_id': cve['cve_id'],
                    'nombre': cve.get('nombre', ''),
                    'cvss_score': cve.get('cvssv3', {}).get('score'),
                    'tipo': cve.get('tipo'),
                    'match_reason': f"Solo tipo de ataque ({vuln_type}) - Asset desconocido",
                    'confidence': 'LOW',
                    'requires_validation': True,
                    'warning': 'Asset no registrado en inventario - correlación poco fiable'
                })
        
        # Ordenar por CVSS score descendente
        suggestions.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
        
        return suggestions[:10]
    
    except Exception as e:
        logger.error(f"Error sugiriendo CVEs: {e}")
        return []