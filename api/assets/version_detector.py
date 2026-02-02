"""
Version Detector - Detección de versiones de software via red

Detecta versiones de software usando SOLO técnicas de red,
válidas para entornos de producción sin acceso a contenedores/VMs.

Métodos implementados:
1. HTTP Headers (Server, X-Powered-By)
2. API Endpoints comunes (/version, /health, /metrics, /api/version)
3. Banner Grabbing SSH
4. Fingerprinting por comportamiento

Author: VulnDB 5G Team
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
import aiohttp

logger = logging.getLogger(__name__)

# Timeout por método
TIMEOUT_HTTP = 3.0
TIMEOUT_SSH = 2.0

# API endpoints comunes que exponen versión
COMMON_VERSION_ENDPOINTS = [
    "/version",
    "/api/version",
    "/api/v1/version",
    "/health",
    "/api/health",
    "/metrics",
    "/status",
    "/info",
    "/.well-known/version"
]

# Patrones de extracción de versiones
VERSION_PATTERNS = {
    # Open5GS
    r'open5gs[/\s]+v?(\d+\.\d+\.\d+)': 'Open5GS',
    r'open5gs.*version[:\s]+v?(\d+\.\d+\.\d+)': 'Open5GS',
    
    # MongoDB
    r'mongodb[/\s]+(\d+\.\d+\.\d+)': 'MongoDB',
    
    # Nginx
    r'nginx[/\s]+(\d+\.\d+\.\d+)': 'Nginx',
    
    # Apache
    r'apache[/\s]+(\d+\.\d+\.\d+)': 'Apache',
    
    # Python/Flask
    r'werkzeug[/\s]+(\d+\.\d+\.\d+)': 'Werkzeug',
    r'flask[/\s]+(\d+\.\d+\.\d+)': 'Flask',
    
    # Generic version pattern
    r'version[:\s]+v?(\d+\.\d+\.\d+)': 'Unknown',
    r'v(\d+\.\d+\.\d+)': 'Unknown'
}


class VersionDetector:
    """
    Detector de versiones de software usando técnicas de red.
    """
    
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        """Context manager para reusar sesión HTTP"""
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cerrar sesión HTTP"""
        if self.session:
            await self.session.close()
    
    async def detect_version(
        self,
        ip: str,
        ports: List[int],
        hostname: Optional[str] = None
    ) -> Dict[str, Optional[str]]:
        """
        Detecta versión de software usando múltiples métodos.
        
        Args:
            ip: Dirección IP del host
            ports: Lista de puertos abiertos detectados
            hostname: Hostname del asset (opcional)
        
        Returns:
            {
                'software': 'Open5GS' | 'MongoDB' | None,
                'version': '2.7.5' | 'unknown',
                'confidence': 'HIGH' | 'MEDIUM' | 'LOW',
                'method': 'http_header' | 'api_endpoint' | 'ssh_banner' | None
            }
        """
        logger.debug(f"🔍 Detectando versión en {ip} - Puertos: {ports}")
        
        # Método 1: HTTP Headers
        result = await self._try_http_headers(ip, ports)
        if result['version'] != 'unknown':
            logger.info(f"✅ Versión detectada via HTTP headers: {result['software']} {result['version']}")
            return result
        
        # Método 2: API Endpoints
        result = await self._try_api_endpoints(ip, ports, hostname)
        if result['version'] != 'unknown':
            logger.info(f"✅ Versión detectada via API endpoint: {result['software']} {result['version']}")
            return result
        
        # Método 3: SSH Banner
        if 22 in ports:
            result = await self._try_ssh_banner(ip)
            if result['version'] != 'unknown':
                logger.info(f"✅ Versión detectada via SSH banner: {result['software']} {result['version']}")
                return result
        
        # Fallback: Software detectado por puertos pero sin versión
        software = self._infer_software_from_ports(ports, hostname)
        if software:
            logger.debug(f"⚠️ Software inferido pero sin versión: {software}")
            return {
                'software': software,
                'version': 'unknown',
                'confidence': 'LOW',
                'method': 'port_inference'
            }
        
        # Nada detectado
        logger.debug(f"❌ No se pudo detectar software/versión en {ip}")
        return {
            'software': None,
            'version': 'unknown',
            'confidence': 'LOW',
            'method': None
        }
    
    async def _try_http_headers(
        self,
        ip: str,
        ports: List[int]
    ) -> Dict[str, Optional[str]]:
        """
        Intenta detectar versión desde headers HTTP.
        
        Busca en: Server, X-Powered-By, X-Generator
        """
        # Probar puertos HTTP comunes
        http_ports = [p for p in ports if p in [80, 443, 5000, 7777, 8080, 8000, 9090, 3000]]
        
        if not http_ports:
            return {'software': None, 'version': 'unknown', 'confidence': 'LOW', 'method': None}
        
        for port in http_ports:
            try:
                protocol = 'https' if port == 443 else 'http'
                url = f"{protocol}://{ip}:{port}/"
                
                if not self.session:
                    timeout = aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url, ssl=False) as response:
                            headers = response.headers
                else:
                    async with self.session.get(url, ssl=False) as response:
                        headers = response.headers
                
                # Buscar en headers comunes
                for header_name in ['Server', 'X-Powered-By', 'X-Generator']:
                    header_value = headers.get(header_name, '').lower()
                    
                    if header_value:
                        logger.debug(f"📡 HTTP {header_name}: {header_value}")
                        
                        # Intentar extraer versión
                        software, version = self._parse_version_string(header_value)
                        if version and version != 'unknown':
                            return {
                                'software': software or 'Unknown',
                                'version': version,
                                'confidence': 'HIGH',
                                'method': 'http_header'
                            }
            
            except Exception as e:
                logger.debug(f"Error HTTP headers {ip}:{port}: {e}")
                continue
        
        return {'software': None, 'version': 'unknown', 'confidence': 'LOW', 'method': None}
    
    async def _try_api_endpoints(
        self,
        ip: str,
        ports: List[int],
        hostname: Optional[str]
    ) -> Dict[str, Optional[str]]:
        """
        Intenta detectar versión desde endpoints comunes.
        
        Prueba: /version, /api/version, /health, /metrics, etc.
        """
        http_ports = [p for p in ports if p in [80, 443, 5000, 7777, 8080, 8000, 9090, 3000]]
        
        if not http_ports:
            return {'software': None, 'version': 'unknown', 'confidence': 'LOW', 'method': None}
        
        for port in http_ports:
            protocol = 'https' if port == 443 else 'http'
            
            for endpoint in COMMON_VERSION_ENDPOINTS:
                try:
                    url = f"{protocol}://{ip}:{port}{endpoint}"
                    
                    if not self.session:
                        timeout = aiohttp.ClientTimeout(total=TIMEOUT_HTTP)
                        async with aiohttp.ClientSession(timeout=timeout) as session:
                            async with session.get(url, ssl=False) as response:
                                if response.status == 200:
                                    text = await response.text()
                                else:
                                    continue
                    else:
                        async with self.session.get(url, ssl=False) as response:
                            if response.status == 200:
                                text = await response.text()
                            else:
                                continue
                    
                    logger.debug(f"📡 API endpoint {url}: {text[:100]}")
                    
                    # Intentar parsear como JSON
                    try:
                        import json
                        data = json.loads(text)
                        
                        # Buscar campo version
                        for key in ['version', 'Version', 'VERSION', 'ver', 'release']:
                            if key in data:
                                version_str = str(data[key])
                                software, version = self._parse_version_string(version_str)
                                
                                if version and version != 'unknown':
                                    return {
                                        'software': software or 'Unknown',
                                        'version': version,
                                        'confidence': 'HIGH',
                                        'method': 'api_endpoint'
                                    }
                    
                    except json.JSONDecodeError:
                        # No es JSON, intentar parsear como texto
                        software, version = self._parse_version_string(text)
                        
                        if version and version != 'unknown':
                            return {
                                'software': software or 'Unknown',
                                'version': version,
                                'confidence': 'MEDIUM',
                                'method': 'api_endpoint'
                            }
                
                except Exception as e:
                    logger.debug(f"Error API endpoint {url}: {e}")
                    continue
        
        return {'software': None, 'version': 'unknown', 'confidence': 'LOW', 'method': None}
    
    async def _try_ssh_banner(self, ip: str) -> Dict[str, Optional[str]]:
        """
        Intenta detectar versión desde banner SSH.
        
        Banner típico: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=TIMEOUT_SSH
            )
            
            # Leer banner
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=TIMEOUT_SSH
            )
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            
            logger.debug(f"📡 SSH banner: {banner_str}")
            
            # Parsear banner
            # Ejemplo: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            if 'openssh' in banner_str.lower():
                match = re.search(r'openssh[_\s]+(\d+\.\d+)', banner_str, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    return {
                        'software': 'OpenSSH',
                        'version': version,
                        'confidence': 'HIGH',
                        'method': 'ssh_banner'
                    }
        
        except Exception as e:
            logger.debug(f"Error SSH banner {ip}: {e}")
        
        return {'software': None, 'version': 'unknown', 'confidence': 'LOW', 'method': None}
    
    def _parse_version_string(self, text: str) -> tuple:
        """
        Extrae software y versión de un string.
        
        Args:
            text: String a parsear
        
        Returns:
            (software_name, version) o (None, 'unknown')
        """
        text_lower = text.lower()
        
        for pattern, software_name in VERSION_PATTERNS.items():
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else 'unknown'
                return (software_name, version)
        
        return (None, 'unknown')
    
    def _infer_software_from_ports(
        self,
        ports: List[int],
        hostname: Optional[str]
    ) -> Optional[str]:
        """
        Infiere software basándose solo en puertos y hostname.
        
        Fallback cuando no se puede detectar versión.
        """
        # MongoDB
        if 27017 in ports:
            return 'MongoDB'
        
        # Open5GS (puertos característicos)
        if 7777 in ports and any(p in ports for p in [38412, 8805, 2152]):
            return 'Open5GS'
        
        # Nginx/Apache
        if 80 in ports or 443 in ports:
            return 'Web Server'
        
        # Por hostname (solo si es claro)
        if hostname:
            hostname_lower = hostname.lower()
            if 'mongo' in hostname_lower:
                return 'MongoDB'
            elif any(x in hostname_lower for x in ['amf', 'smf', 'upf', 'nrf']):
                return 'Open5GS'
        
        return None

    def _extract_version_from_docker_image(self, image_name: str) -> tuple:
            """
            Extrae versión de nombre de imagen Docker.
            
            Args:
                image_name: Nombre completo de la imagen (ej: "borieher/amf:v2.7.6")
            
            Returns:
                (software_name, version) o (None, 'unknown')
            
            Examples:
                "borieher/amf:v2.7.6" → ("Open5GS", "2.7.6")
                "mongo:4.4" → ("MongoDB", "4.4")
                "nginx:alpine" → ("Nginx", "unknown")
            """
            if not image_name:
                return (None, 'unknown')
            
            # Extraer tag después de ":"
            if ':' not in image_name:
                return (None, 'unknown')
            
            repo, tag = image_name.rsplit(':', 1)
            
            # Open5GS (borieher/*)
            if 'borieher/' in repo:
                # Extraer versión: v2.7.6 → 2.7.6
                version = tag.replace('v', '')
                
                if version and version != 'latest':
                    return ('Open5GS', version)
            
            # UERANSIM
            if 'towards5gs/ueransim' in repo:
                version = tag.replace('v', '')
                if version and version != 'latest':
                    return ('UERANSIM', version)
            
            # MongoDB
            if 'mongo' in repo.lower():
                version = tag if tag != 'latest' else 'unknown'
                return ('MongoDB', version)
            
            # Nginx
            if 'nginx' in repo.lower():
                version = tag if tag not in ['alpine', 'latest'] else 'unknown'
                return ('Nginx', version)
            
            # Python
            if 'python' in repo.lower():
                # python:3.11-slim → 3.11
                version = tag.split('-')[0] if '-' in tag else tag
                if version != 'latest':
                    return ('Python', version)
            
            # Suricata
            if 'suricata' in repo.lower() or 'jasonish/suricata' in repo.lower():
                version = tag if tag != 'latest' else 'unknown'
                return ('Suricata', version)
            
            # VulnDB custom images
            if 'vulndb' in repo.lower():
                # vulndb-5g-api, vulndb-5g-ingest, etc.
                software = repo.split('/')[-1].replace('vulndb-5g-', '').upper()
                return (f'VulnDB-{software}', 'custom')
            
            return (None, 'unknown')

# ============================================================================
# FUNCIÓN HELPER PARA USAR FUERA DE CONTEXT MANAGER
# ============================================================================

async def detect_version_simple(
    ip: str,
    ports: List[int],
    hostname: Optional[str] = None
) -> Dict[str, Optional[str]]:
    """
    Función helper para detectar versión sin context manager.
    
    Uso:
        version_info = await detect_version_simple('172.22.0.10', [7777, 38412])
    """
    async with VersionDetector() as detector:
        return await detector.detect_version(ip, ports, hostname)