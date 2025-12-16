# api/scanning/plugins/discovery_5g.py
import asyncio
import contextlib
import hashlib
import logging
import time
from typing import List, Dict, Tuple
from ..plugin_base import Plugin, ScanContext, Finding

# Configurar logger
logger = logging.getLogger("scanner-plugin-discovery5g")

# PFCP helper opcional (si no está, degradamos amable)
try:
    from scanning.utils.udp_pfcp import pfcp_probe, PFCP_PORT  # type: ignore
    PFCP_AVAILABLE = True
    logger.info("✅ Módulo PFCP disponible")
except Exception as e:
    PFCP_PORT = 8805
    pfcp_probe = None
    PFCP_AVAILABLE = False
    logger.warning(f"⚠️  Módulo PFCP no disponible: {e}")

TCP_PORTS: List[Tuple[int, str]] = [
    (3868,  "Diameter"),     # CORE *
    (443,   "HTTPS/SBA"),    # SBA típico
    (80,    "HTTP"),         # SBA/nodos mgmt
    (8080,  "HTTP-Alt"),
    (8443,  "HTTPS-Alt"),
    (9090,  "Mgmt/Prom"),
    (5060,  "SIP/TCP"),      # IMS
    (5061,  "SIP/TLS"),      # IMS
]

class Discovery5G(Plugin):
    id = "discovery_5g"
    component = "CORE"
    interfaces = ["*"]
    profile = "fast|standard|exhaustive"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []

        logger.info(f"🔍 Iniciando Discovery5G - Profile: {ctx.profile}")
        logger.info(f"📋 Targets CORE: {ctx.targets.get('core', [])}")

        # timeouts y concurrencia desde perfil (si existen) o valores por defecto
        tcp_timeout = float(getattr(ctx, "params", {}).get("tcp_timeout", 
            0.8 if ctx.profile == "fast" else 1.2 if ctx.profile == "standard" else 2.0))
        udp_timeout = float(getattr(ctx, "params", {}).get("udp_timeout", 
            0.8 if ctx.profile == "fast" else 1.2 if ctx.profile == "standard" else 2.0))
        concurrency = int(getattr(ctx, "params", {}).get("concurrency", 
            12 if ctx.profile == "fast" else 20 if ctx.profile == "standard" else 32))

        logger.info(f"⚙️  Configuración: tcp_timeout={tcp_timeout}s, udp_timeout={udp_timeout}s, concurrencia={concurrency}")
        logger.info(f"🔌 Puertos TCP a escanear: {[f'{p}({l})' for p, l in TCP_PORTS]}")
        logger.info(f"🔌 Puertos UDP a escanear: {PFCP_PORT}(PFCP) - Disponible: {PFCP_AVAILABLE}")

        sem = asyncio.Semaphore(concurrency)
        targets = (ctx.targets or {}).get("core", [])

        if not targets:
            logger.warning("⚠️  No hay targets CORE definidos en el contexto")
            return results

        async def tcp_check(host: str, port: int, label: str) -> Tuple[str, int, str]:
            start_time = time.time()
            logger.debug(f"  → TCP: {host}:{port} ({label})")
            
            try:
                conn = asyncio.open_connection(host=host, port=port)
                reader, writer = await asyncio.wait_for(conn, timeout=tcp_timeout)
                elapsed = time.time() - start_time
                
                logger.info(f"  ✅ OPEN: {host}:{port} ({label}) - respondió en {elapsed:.3f}s")
                
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                
                return ("open", port, label)
                
            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                logger.debug(f"  ⏱️  FILTERED/TIMEOUT: {host}:{port} ({label}) - {elapsed:.3f}s")
                return ("filtered", port, label)
                
            except ConnectionRefusedError:
                elapsed = time.time() - start_time
                logger.debug(f"  🚫 CLOSED: {host}:{port} ({label}) - refused en {elapsed:.3f}s")
                return ("closed", port, label)
                
            except Exception as e:
                elapsed = time.time() - start_time
                et = type(e).__name__.lower()
                logger.debug(f"  ❌ ERROR: {host}:{port} ({label}) - {et} en {elapsed:.3f}s")
                
                if "refused" in et:
                    return ("closed", port, label)
                return ("closed", port, et)

        async def pfcp_check(host: str) -> Tuple[str, int, str]:
            start_time = time.time()
            logger.debug(f"  → UDP: {host}:{PFCP_PORT} (PFCP)")
            
            if not pfcp_probe:
                logger.debug(f"  ⚠️  PFCP helper no disponible, saltando")
                return ("unknown", PFCP_PORT, "pfcp_helper_missing")
            
            try:
                status, detail = await asyncio.to_thread(pfcp_probe, host, PFCP_PORT, udp_timeout)
                elapsed = time.time() - start_time
                
                # status: "pfcp" | "closed" | "open|filtered" | "error"
                if status == "pfcp":
                    logger.info(f"  ✅ PFCP DETECTED: {host}:{PFCP_PORT} - {detail} en {elapsed:.3f}s")
                    return ("open", PFCP_PORT, "pfcp")
                    
                elif status == "open|filtered":
                    logger.debug(f"  ❓ FILTERED: {host}:{PFCP_PORT} - {detail} en {elapsed:.3f}s")
                    return ("filtered", PFCP_PORT, detail or "")
                    
                elif status == "closed":
                    logger.debug(f"  🚫 CLOSED: {host}:{PFCP_PORT} - {detail} en {elapsed:.3f}s")
                    return ("closed", PFCP_PORT, detail or "")
                    
                else:
                    logger.warning(f"  ⚠️  UNKNOWN: {host}:{PFCP_PORT} - {detail} en {elapsed:.3f}s")
                    return ("unknown", PFCP_PORT, detail or "")
                    
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"  ❌ EXCEPTION: {host}:{PFCP_PORT} - {type(e).__name__} en {elapsed:.3f}s")
                return ("unknown", PFCP_PORT, type(e).__name__)

        async def scan_host(host: str) -> List[Finding]:
            fins: List[Finding] = []
            host_start = time.time()
            
            logger.info(f"🎯 Escaneando host: {host}")

            async def guarded(coro):
                async with sem:
                    return await coro

            # TCP set
            tcp_tasks = [guarded(tcp_check(host, p, label)) for p, label in TCP_PORTS]
            # PFCP (UDP)
            udp_tasks = [guarded(pfcp_check(host))] if PFCP_AVAILABLE else []

            all_res = await asyncio.gather(*tcp_tasks, *udp_tasks)
            
            host_elapsed = time.time() - host_start

            # Agregar resultado resumido por host
            open_services = [(port, label) for st, port, label in all_res if st == "open"]
            filtered = [(port, label) for st, port, label in all_res if st == "filtered"]
            closed = [(port, label) for st, port, label in all_res if st == "closed"]
            
            logger.info(f"  📊 {host} completado en {host_elapsed:.2f}s:")
            logger.info(f"    ✅ Abiertos: {len(open_services)} puertos")
            logger.info(f"    🚫 Cerrados: {len(closed)} puertos")
            logger.info(f"    ❓ Filtrados: {len(filtered)} puertos")

            # Riesgo: solo informativo; descubrimiento no eleva severidad
            summary_parts = []
            if open_services:
                services_str = ', '.join([f"{p}({l})" for p, l in open_services])
                summary_parts.append(f"Servicios abiertos: {services_str}")
                logger.info(f"    🔓 Servicios detectados: {services_str}")
                
            if filtered:
                filtered_str = ', '.join([f"{p}({l})" for p, l in filtered])
                summary_parts.append(f"Filtrados/Sin respuesta: {filtered_str}")
                logger.debug(f"    🔒 Filtrados: {filtered_str}")
                
            if not summary_parts:
                summary_parts.append("Sin puertos relevantes detectados abiertos.")
                logger.info(f"    ℹ️  No se detectaron servicios abiertos")

            fins.append(Finding(
                finding_id=hashlib.sha1(f"{host}-disc".encode()).hexdigest()[:12],
                component="CORE",
                interface="*",
                protocol="Discovery",
                risk={"cvss_v3": 0.0, "label": "Info"},
                summary=f"Descubrimiento en {host}: " + " · ".join(summary_parts),
                recommendation="Usar estos indicios para priorizar chequeos (SBA/Diameter/SIP/PFCP).",
                evidence={
                    "host": host,
                    "tcp_open": [{"port": p, "service": l} for p, l in open_services],
                    "tcp_closed": [{"port": p, "service": l} for p, l in closed],
                    "filtered": [{"port": p, "service": l} for p, l in filtered],
                    "checked_tcp_ports": [p for p, _ in TCP_PORTS],
                    "checked_udp_ports": [PFCP_PORT] if PFCP_AVAILABLE else [],
                    "scan_time_seconds": f"{host_elapsed:.2f}"
                },
                tags=["discovery"]
            ))
            
            return fins

        logger.info(f"🚀 Iniciando discovery de {len(targets)} targets...")
        scan_start = time.time()
        
        host_tasks = [scan_host(h) for h in targets]
        batches = await asyncio.gather(*host_tasks)
        
        scan_elapsed = time.time() - scan_start
        
        for b in batches:
            results.extend(b)
        
        logger.info(f"✨ Discovery completado en {scan_elapsed:.2f}s")
        logger.info(f"📊 Resultados: {len(results)} findings generados")
        
        # Estadísticas agregadas
        total_open = sum(len(f.evidence.get('tcp_open', [])) for f in results if f.evidence)
        total_filtered = sum(len(f.evidence.get('filtered', [])) for f in results if f.evidence)
        
        logger.info(f"📈 Estadísticas globales:")
        logger.info(f"    🔓 Total servicios abiertos: {total_open}")
        logger.info(f"    🔒 Total filtrados: {total_filtered}")
        logger.info(f"    🎯 Hosts escaneados: {len(targets)}")
        logger.info(f"    ⚡ Velocidad: {len(targets)/scan_elapsed:.2f} hosts/s")
        
        return results