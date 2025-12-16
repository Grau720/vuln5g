# api/scanning/plugins/smart_discovery.py
import asyncio
import logging
import time
from typing import List, Set
from ..plugin_base import Plugin, ScanContext, Finding

logger = logging.getLogger(__name__)

# Puertos comunes para probar conectividad en 5G Core
PROBE_PORTS = [
    7777,  # HTTP/2 SBI (NRF, AMF, SMF, etc.)
    3868,  # Diameter
    2152,  # GTP-U
    8805,  # PFCP
    9090,  # Metrics
    27017, # MongoDB
]

class SmartDiscovery(Plugin):
    """
    Plugin de descubrimiento inteligente que:
    1. Prueba conectividad TCP rápida en puertos comunes
    2. Identifica qué hosts están realmente activos
    3. Genera un mapa de servicios detectados
    """
    id = "smart_discovery"
    component = "CORE"
    interfaces = ["*"]
    profile = "all"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []
        
        # Timeout agresivo para discovery (más rápido que escaneos normales)
        timeout = 0.3 if ctx.profile == "fast" else (0.5 if ctx.profile == "standard" else 1.0)
        
        # Mayor concurrencia para discovery (es muy rápido)
        sem = asyncio.Semaphore(128 if ctx.profile == "exhaustive" else 64)
        
        logger.info(f"🔍 Smart Discovery iniciado - timeout={timeout}s")
        
        # Combinar todos los targets
        all_targets = []
        for category, hosts in ctx.targets.items():
            all_targets.extend(hosts)
        all_targets = sorted(set(all_targets))
        
        logger.info(f"📋 Probando conectividad en {len(all_targets)} hosts")
        
        # Mapa de host -> puertos abiertos
        active_hosts: dict[str, Set[int]] = {}
        
        async def probe_host_port(host: str, port: int):
            """Prueba un puerto específico en un host"""
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return host, port, True
            except:
                return host, port, False
        
        async def probe_host(host: str):
            """Prueba múltiples puertos en un host para detectar si está activo"""
            async with sem:
                tasks = [probe_host_port(host, port) for port in PROBE_PORTS]
                results = await asyncio.gather(*tasks)
                
                open_ports = set()
                for h, p, is_open in results:
                    if is_open:
                        open_ports.add(p)
                
                if open_ports:
                    active_hosts[host] = open_ports
                    logger.info(f"✅ Host activo: {host} - Puertos: {sorted(open_ports)}")
                else:
                    logger.debug(f"⚫ Host inactivo: {host}")
        
        # Escanear todos los hosts
        start = time.time()
        await asyncio.gather(*[probe_host(h) for h in all_targets])
        elapsed = time.time() - start
        
        logger.info(f"✨ Discovery completado en {elapsed:.2f}s")
        logger.info(f"📊 Hosts activos: {len(active_hosts)}/{len(all_targets)}")
        
        # Generar findings
        if not active_hosts:
            results.append(Finding(
                finding_id=f"disc_no_active_{int(time.time())}",
                component="CORE",
                interface="*",
                protocol="TCP",
                risk={"cvss_v3": 0.0, "label": "Info"},
                summary=f"No se detectaron hosts activos en {len(all_targets)} targets probados.",
                recommendation="Verificar conectividad de red o configuración de targets.",
                tags=["discovery", "no_active_hosts"],
                evidence={
                    "scanned_hosts": len(all_targets),
                    "active_hosts": 0,
                    "duration_sec": round(elapsed, 2)
                }
            ))
        else:
            # Finding con resumen de discovery
            results.append(Finding(
                finding_id=f"disc_summary_{int(time.time())}",
                component="CORE",
                interface="*",
                protocol="TCP",
                risk={"cvss_v3": 0.0, "label": "Info"},
                summary=f"Discovery completado: {len(active_hosts)} hosts activos de {len(all_targets)} escaneados.",
                recommendation=None,
                tags=["discovery", "summary"],
                evidence={
                    "scanned_hosts": len(all_targets),
                    "active_hosts": len(active_hosts),
                    "duration_sec": round(elapsed, 2),
                    "active_host_list": sorted(active_hosts.keys())
                }
            ))
            
            # Finding individual por cada host activo
            for host, ports in active_hosts.items():
                # Identificar tipo de servicio según puertos
                service_hints = []
                if 7777 in ports:
                    service_hints.append("SBI (NRF/AMF/SMF/UDM/etc)")
                if 3868 in ports:
                    service_hints.append("Diameter")
                if 2152 in ports:
                    service_hints.append("GTP-U (UPF)")
                if 8805 in ports:
                    service_hints.append("PFCP")
                if 27017 in ports:
                    service_hints.append("MongoDB")
                if 9090 in ports:
                    service_hints.append("Metrics")
                
                service_type = ", ".join(service_hints) if service_hints else "Unknown"
                
                results.append(Finding(
                    finding_id=f"disc_{host.replace('.', '_')}",
                    component="CORE",
                    interface="*",
                    protocol="TCP",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"Host activo detectado: {host}",
                    recommendation=None,
                    target=host,
                    tags=["discovery", "active_host"],
                    evidence={
                        "open_ports": sorted(ports),
                        "service_hints": service_hints,
                        "probable_service": service_type
                    }
                ))
        
        return results