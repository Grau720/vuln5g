"""
CVE Matcher - Correlación de Assets con CVEs

Detecta qué CVEs afectan a cada asset del inventario basándose en:
1. Software + Versión exacta
2. Componente 5G (infraestructura_5g_afectada)
3. Puertos abiertos (puertos_asociados)
4. Protocolos (protocolo_principal)

Author: VulnDB 5G Team
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class CVEMatcher:
    """
    Correlaciona assets del inventario con CVEs de la base de datos.
    """
    
    def __init__(self, db):
        """
        Args:
            db: Instancia de MongoDB (pymongo Database)
        """
        self.db = db
        self.cves_col = db['vulnerabilidades']
        self.assets_col = db['network_assets']
    
    def match_asset_cves(
        self,
        asset: Dict,
        limit: int = 50
    ) -> List[Dict]:
        """
        Encuentra CVEs que afectan a un asset específico.
        
        Args:
            asset: Documento del asset con campos:
                - software: str (ej: "Open5GS")
                - version: str (ej: "2.7.0")
                - component_5g: str (ej: "AMF")
                - services: List[Dict] con puertos
            limit: Máximo de CVEs a retornar
        
        Returns:
            Lista de CVEs con scoring de relevancia
        """
        software = asset.get('software')
        version = asset.get('version')
        component_5g = asset.get('component_5g')
        services = asset.get('services', [])
        
        # Extraer puertos
        ports = [s.get('port') for s in services if s.get('port')]
        
        logger.info(
            f"🔍 Buscando CVEs para {asset['ip']}: "
            f"software={software} version={version} component_5g={component_5g}"
        )
        
        matches = []
        
        # ============================================================
        # MÉTODO 1: Match por Software + Versión
        # ============================================================
        if software and version and version != 'unknown':
            cves = self._match_by_software_version(software, version, limit)
            for cve in cves:
                matches.append({
                    **cve,
                    'match_method': 'software_version',
                    'confidence': 'HIGH',
                    'match_reason': f'Software {software} versión {version} vulnerable'
                })
        
        # ============================================================
        # MÉTODO 2: Match por Componente 5G
        # ============================================================
        if component_5g:
            cves = self._match_by_5g_component(component_5g, limit)
            for cve in cves:
                # Evitar duplicados
                if not any(m['cve_id'] == cve['cve_id'] for m in matches):
                    matches.append({
                        **cve,
                        'match_method': '5g_component',
                        'confidence': 'MEDIUM',
                        'match_reason': f'Componente 5G {component_5g} afectado'
                    })
        
        # ============================================================
        # MÉTODO 3: Match por Puertos
        # ============================================================
        if ports:
            cves = self._match_by_ports(ports, limit)
            for cve in cves:
                # Evitar duplicados
                if not any(m['cve_id'] == cve['cve_id'] for m in matches):
                    matches.append({
                        **cve,
                        'match_method': 'ports',
                        'confidence': 'LOW',
                        'match_reason': f'Puertos {ports} asociados'
                    })
        
        # ============================================================
        # MÉTODO 4: Match por Software (sin versión específica)
        # ============================================================
        if software and not matches:
            cves = self._match_by_software_only(software, limit)
            for cve in cves:
                matches.append({
                    **cve,
                    'match_method': 'software_generic',
                    'confidence': 'LOW',
                    'match_reason': f'Software {software} (versión no verificada)'
                })
        
        # Ordenar por score CVSS (descendente)
        matches.sort(
            key=lambda x: x.get('cvssv3', {}).get('score', 0),
            reverse=True
        )
        
        logger.info(f"✅ {len(matches)} CVEs encontrados para {asset['ip']}")
        
        return matches[:limit]
    
    def _match_by_software_version(
        self,
        software: str,
        version: str,
        limit: int
    ) -> List[Dict]:
        """
        Busca CVEs que afecten a software + versión específica.
        
        Lógica:
        1. Buscar en 'componente_afectado' (ej: "open5gs")
        2. Verificar en 'versiones_afectadas' si contiene la versión
        """
        software_lower = software.lower()
        
        # Normalizar nombres de software conocidos
        software_aliases = {
            'open5gs': ['open5gs', 'open5g'],
            'mongodb': ['mongodb', 'mongo'],
            'nginx': ['nginx'],
            'apache': ['apache', 'httpd'],
        }
        
        # Obtener aliases
        search_terms = []
        for canonical, aliases in software_aliases.items():
            if any(alias in software_lower for alias in aliases):
                search_terms.extend(aliases)
                break
        
        if not search_terms:
            search_terms = [software_lower]
        
        # Query MongoDB
        query = {
            '$or': [
                {'componente_afectado': {'$regex': term, '$options': 'i'}}
                for term in search_terms
            ]
        }
        
        cves = list(self.cves_col.find(query).limit(limit * 2))  # Buscar más para filtrar
        
        # Filtrar por versión
        matched = []
        for cve in cves:
            affected_versions = cve.get('versiones_afectadas', [])
            
            if self._version_is_affected(version, affected_versions):
                matched.append(cve)
        
        logger.debug(f"📦 Software+Version match: {len(matched)} CVEs para {software} {version}")
        
        return matched[:limit]
    
    def _match_by_5g_component(
        self,
        component: str,
        limit: int
    ) -> List[Dict]:
        """
        Busca CVEs que afecten a componente 5G específico.
        
        Args:
            component: Nombre del componente (ej: "AMF", "SMF", "UPF")
            limit: Máximo de resultados
        """
        component_upper = component.upper()
        
        query = {
            'infraestructura_5g_afectada': {
                '$regex': f'^{component_upper}$',
                '$options': 'i'
            }
        }
        
        cves = list(self.cves_col.find(query).limit(limit))
        
        logger.debug(f"📡 5G Component match: {len(cves)} CVEs para {component}")
        
        return cves
    
    def _match_by_ports(
        self,
        ports: List[int],
        limit: int
    ) -> List[Dict]:
        """
        Busca CVEs asociados a puertos específicos.
        
        Args:
            ports: Lista de puertos abiertos
            limit: Máximo de resultados
        """
        if not ports:
            return []
        
        query = {
            'puertos_asociados': {'$in': ports}
        }
        
        cves = list(self.cves_col.find(query).limit(limit))
        
        logger.debug(f"🔌 Ports match: {len(cves)} CVEs para puertos {ports}")
        
        return cves
    
    def _match_by_software_only(
        self,
        software: str,
        limit: int
    ) -> List[Dict]:
        """
        Busca CVEs por software sin verificar versión.
        
        Fallback cuando no se tiene versión específica.
        """
        software_lower = software.lower()
        
        query = {
            'componente_afectado': {'$regex': software_lower, '$options': 'i'}
        }
        
        cves = list(self.cves_col.find(query).limit(limit))
        
        logger.debug(f"📦 Software-only match: {len(cves)} CVEs para {software}")
        
        return cves
    
    def _version_is_affected(
        self,
        asset_version: str,
        affected_versions: List[str]
    ) -> bool:
        """
        Verifica si la versión del asset está en la lista de versiones afectadas.
        
        Soporta:
        - Versiones exactas: "2.7.0"
        - Rangos: "< 2.7.5"
        - Wildcard: "2.7.*"
        
        Args:
            asset_version: Versión del asset (ej: "2.7.0")
            affected_versions: Lista de versiones afectadas del CVE
        
        Returns:
            True si la versión está afectada
        """
        if not affected_versions:
            # Si no hay versiones especificadas, asumir que todas están afectadas
            return True
        
        # Normalizar versión del asset
        asset_ver = self._parse_version(asset_version)
        if not asset_ver:
            return False
        
        for affected in affected_versions:
            affected_str = str(affected).strip()
            
            # Match exacto
            if affected_str == asset_version:
                return True
            
            # Wildcard: "2.7.*" matches "2.7.0", "2.7.5", etc.
            if '*' in affected_str:
                pattern = affected_str.replace('.', r'\.').replace('*', r'.*')
                if re.match(f'^{pattern}$', asset_version):
                    return True
            
            # Rango: "< 2.7.5"
            if affected_str.startswith('<') or affected_str.startswith('>'):
                target_ver = self._parse_version(affected_str.lstrip('<>=').strip())
                if target_ver:
                    if '<=' in affected_str:
                        if asset_ver <= target_ver:
                            return True
                    elif '<' in affected_str:
                        if asset_ver < target_ver:
                            return True
                    elif '>=' in affected_str:
                        if asset_ver >= target_ver:
                            return True
                    elif '>' in affected_str:
                        if asset_ver > target_ver:
                            return True
        
        return False
    
    def _parse_version(self, version_str: str) -> Optional[tuple]:
        """
        Parsea string de versión a tupla para comparación.
        
        Args:
            version_str: "2.7.0" o "2.7.5-beta"
        
        Returns:
            (2, 7, 0) o None si no es válido
        """
        try:
            # Extraer solo números: "2.7.5-beta" -> "2.7.5"
            match = re.match(r'^(\d+)\.(\d+)\.?(\d+)?', version_str)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                patch = int(match.group(3)) if match.group(3) else 0
                return (major, minor, patch)
        except:
            pass
        
        return None
    
    def match_all_assets(self, limit_per_asset: int = 20) -> Dict[str, List[Dict]]:
        """
        Correlaciona TODOS los assets del inventario con CVEs.
        
        Args:
            limit_per_asset: Máximo de CVEs por asset
        
        Returns:
            {
                "172.22.0.10": [lista de CVEs],
                "172.22.0.11": [lista de CVEs],
                ...
            }
        """
        assets = list(self.assets_col.find({}))
        
        results = {}
        
        for asset in assets:
            ip = asset.get('ip')
            if not ip:
                continue
            
            cves = self.match_asset_cves(asset, limit=limit_per_asset)
            results[ip] = cves
        
        logger.info(f"✅ Matching completo: {len(results)} assets procesados")
        
        return results
    
    def get_critical_cves_for_asset(
        self,
        asset: Dict,
        min_score: float = 7.0
    ) -> List[Dict]:
        """
        Retorna solo CVEs críticos/altos para un asset.
        
        Args:
            asset: Documento del asset
            min_score: Score CVSS mínimo (default 7.0 = HIGH)
        
        Returns:
            Lista de CVEs filtrados por score
        """
        all_cves = self.match_asset_cves(asset, limit=100)
        
        critical = [
            cve for cve in all_cves
            if cve.get('cvssv3', {}).get('score', 0) >= min_score
        ]
        
        return critical
    
    def generate_asset_report(self, ip: str) -> Dict:
        """
        Genera reporte completo de vulnerabilidades para un asset.
        
        Args:
            ip: Dirección IP del asset
        
        Returns:
            {
                'asset': {...},
                'cves': [...],
                'summary': {
                    'total_cves': 10,
                    'critical': 2,
                    'high': 5,
                    'medium': 3,
                    'exploited_in_wild': 1
                }
            }
        """
        asset = self.assets_col.find_one({'ip': ip})
        
        if not asset:
            raise ValueError(f"Asset {ip} no encontrado")
        
        cves = self.match_asset_cves(asset, limit=100)
        
        # Calcular estadísticas
        summary = {
            'total_cves': len(cves),
            'critical': len([c for c in cves if c.get('cvssv3', {}).get('score', 0) >= 9.0]),
            'high': len([c for c in cves if 7.0 <= c.get('cvssv3', {}).get('score', 0) < 9.0]),
            'medium': len([c for c in cves if 4.0 <= c.get('cvssv3', {}).get('score', 0) < 7.0]),
            'low': len([c for c in cves if c.get('cvssv3', {}).get('score', 0) < 4.0]),
            'exploited_in_wild': len([c for c in cves if c.get('ia_analysis', {}).get('exploit_probability', 0) > 0.8])
        }
        
        return {
            'asset': asset,
            'cves': cves,
            'summary': summary,
            'generated_at': datetime.utcnow().isoformat()
        }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def match_asset_cves_simple(db, ip: str, limit: int = 50) -> List[Dict]:
    """
    Helper function: correlaciona un asset con CVEs sin instanciar clase.
    
    Args:
        db: MongoDB database instance
        ip: IP del asset
        limit: Máximo de CVEs
    
    Returns:
        Lista de CVEs
    """
    matcher = CVEMatcher(db)
    
    asset = db['network_assets'].find_one({'ip': ip})
    if not asset:
        return []
    
    return matcher.match_asset_cves(asset, limit=limit)