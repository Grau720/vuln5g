# api/scanning/plugins/diameter_check.py
import asyncio
import hashlib
import logging
import time
from typing import List
from ..plugin_base import Plugin, ScanContext, Finding

# Configurar logger
logger = logging.getLogger("scanner-plugin-diametercheck")

DIAMETER_TCP_PORTS = [3868]

class DiameterCheck(Plugin):
    id = "diameter_check"
    component = "CORE"
    interfaces = ["S6a", "S9", "S13", "Ro", "Rx", "Gx"]
    profile = "standard|exhaustive"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []
        
        logger.info(f"🔍 Iniciando DiameterCheck - Profile: {ctx.profile}")
        logger.info(f"📋 Targets CORE: {ctx.targets.get('core', [])}")

        timeout = 0.6 if ctx.profile == "fast" else (1.2 if ctx.profile == "standard" else 2.5)
        sem = asyncio.Semaphore(64 if ctx.profile == "exhaustive" else 32)
        
        logger.info(f"⚙️  Configuración: timeout={timeout}s, concurrencia={sem._value}")

        async def check_tcp(host: str, port: int):
            start_time = time.time()
            logger.debug(f"→ Intentando conectar a {host}:{port}")
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    timeout=timeout
                )
                elapsed = time.time() - start_time
                logger.info(f"✅ OPEN: {host}:{port} (respondió en {elapsed:.3f}s)")
                
                try:
                    writer.close()
                    if hasattr(writer, "wait_closed"):
                        await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error cerrando conexión a {host}:{port}: {e}")
                
                return "open"
                
            except ConnectionRefusedError:
                elapsed = time.time() - start_time
                logger.info(f"🚫 CLOSED: {host}:{port} (ConnectionRefused en {elapsed:.3f}s)")
                return "closed"
                
            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                logger.warning(f"⏱️  FILTERED/TIMEOUT: {host}:{port} (sin respuesta después de {elapsed:.3f}s)")
                return "filtered"
                
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"❌ ERROR: {host}:{port} - {type(e).__name__}: {e} (después de {elapsed:.3f}s)")
                return f"err:{type(e).__name__}"

        targets = ctx.targets.get("core", [])
        
        if not targets:
            logger.warning("⚠️  No hay targets CORE definidos en el contexto")
            return results

        async def guarded_host_port(h: str, p: int):
            async with sem:
                state = await check_tcp(h, p)
                
                if state == "open":
                    finding = Finding(
                        finding_id=hashlib.sha1(f"{h}-diameter-{p}-open".encode()).hexdigest()[:12],
                        component="CORE", 
                        interface="*", 
                        protocol="Diameter",
                        risk={"cvss_v3": 7.5, "label": "High"},
                        summary=f"Diameter ({p}/tcp) alcanzable en {h}. Revisar TLS, peers/realm y ACLs.",
                        recommendation="Forzar TLS, limitar peers por realm/origin-host, hardening de CER/CEA, listas de control y logging."
                    )
                    logger.info(f"📝 Finding generado: {finding.finding_id} - High risk")
                    return finding
                    
                elif state == "closed":
                    finding = Finding(
                        finding_id=hashlib.sha1(f"{h}-diameter-{p}-closed".encode()).hexdigest()[:12],
                        component="CORE", 
                        interface="*", 
                        protocol="Diameter",
                        risk={"cvss_v3": 0.0, "label": "Info"},
                        summary=f"Diameter ({p}/tcp) cerrado en {h} (ConnectionRefused).",
                        recommendation=None
                    )
                    logger.debug(f"📝 Finding generado: {finding.finding_id} - Info")
                    return finding
                    
                elif state == "filtered":
                    finding = Finding(
                        finding_id=hashlib.sha1(f"{h}-diameter-{p}-filtered".encode()).hexdigest()[:12],
                        component="CORE", 
                        interface="*", 
                        protocol="Diameter",
                        risk={"cvss_v3": 2.5, "label": "Low"},
                        summary=f"Diameter ({p}/tcp) potencialmente abierto o filtrado en {h}: no hay respuesta (timeout).",
                        recommendation="Verificar políticas de filtrado/firewall y si el servicio debería estar expuesto."
                    )
                    logger.info(f"📝 Finding generado: {finding.finding_id} - Low risk (filtered)")
                    return finding
                    
                else:
                    finding = Finding(
                        finding_id=hashlib.sha1(f"{h}-diameter-{p}-err".encode()).hexdigest()[:12],
                        component="CORE", 
                        interface="*", 
                        protocol="Diameter",
                        risk={"cvss_v3": 0.0, "label": "Info"},
                        summary=f"No se pudo comprobar Diameter ({p}/tcp) en {h}: {state}",
                        recommendation=None
                    )
                    logger.warning(f"📝 Finding generado: {finding.finding_id} - Error state")
                    return finding

        tasks = []
        total_checks = 0
        
        for h in targets:
            for p in DIAMETER_TCP_PORTS:
                tasks.append(guarded_host_port(h, p))
                total_checks += 1

        logger.info(f"🎯 Iniciando {total_checks} comprobaciones...")
        
        if not tasks:
            logger.warning("⚠️  No se generaron tareas de escaneo")
            return results

        scan_start = time.time()
        batch = await asyncio.gather(*tasks)
        scan_elapsed = time.time() - scan_start
        
        results.extend(batch)
        
        logger.info(f"✨ Escaneo completado en {scan_elapsed:.2f}s")
        logger.info(f"📊 Resultados: {len(results)} findings generados")
        
        # Resumen por tipo
        risk_summary = {}
        for r in results:
            label = r.risk.get('label', 'Unknown')
            risk_summary[label] = risk_summary.get(label, 0) + 1
        
        logger.info(f"📈 Resumen por riesgo: {dict(risk_summary)}")
        
        return results