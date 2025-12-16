# api/scanning/plugins/pfcp_check.py
import asyncio
import hashlib
import logging
import time
from typing import List
from ..plugin_base import Plugin, ScanContext, Finding
from scanning.utils.udp_pfcp import pfcp_probe, PFCP_PORT

# Configurar logger
logger = logging.getLogger("scanner-plugin-pfcpcheck")


class PfcpCheck(Plugin):
    id = "pfcp_check"
    component = "CORE"
    interfaces = ["N4"]
    profile = "standard|exhaustive"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []
        
        logger.info(f"🔍 Iniciando PfcpCheck - Profile: {ctx.profile}")
        logger.info(f"📋 Targets CORE: {ctx.targets.get('core', [])}")

        # parámetros del perfil inyectados por el engine
        p = getattr(ctx, "params", {}) or {}
        sem_size = int(p.get("concurrency", 16))
        udp_timeout = float(p.get("udp_timeout", 0.8))
        retries = int(p.get("retries", 1))

        logger.info(f"⚙️  Configuración: concurrencia={sem_size}, udp_timeout={udp_timeout}s, retries={retries}")
        logger.info(f"🔌 Puerto PFCP: {PFCP_PORT}/udp")

        sem = asyncio.Semaphore(sem_size)
        targets = (ctx.targets or {}).get("core", [])

        if not targets:
            logger.warning("⚠️  No hay targets CORE definidos en el contexto")
            return results

        async def probe_one(host: str) -> List[Finding]:
            fins: List[Finding] = []
            start_time = time.time()
            
            logger.debug(f"→ Probando PFCP en {host}:{PFCP_PORT}")
            
            try:
                # pfcp_probe es síncrono → ejecuta en thread
                probe_start = time.time()
                status, detail = await asyncio.to_thread(pfcp_probe, host, PFCP_PORT)
                probe_elapsed = time.time() - probe_start
                
                logger.debug(f"  ⏱️  pfcp_probe completado en {probe_elapsed:.3f}s - Status: {status}")

                if status == "pfcp":
                    logger.info(f"✅ PFCP CONFIRMED: {host}:{PFCP_PORT} - {detail}")
                    fins.append(Finding(
                        finding_id=hashlib.sha1(f"{host}-pfcp-ok".encode()).hexdigest()[:12],
                        component="CORE",
                        interface="N4",
                        protocol="PFCP",
                        risk={"cvss_v3": 7.5, "label": "High"},
                        summary=f"PFCP ({PFCP_PORT}/udp) confirmado en {host}. Validar hardening y ACLs.",
                        recommendation="Aislar N4; peers autorizados; IPsec; rate-limits.",
                        target=host,
                        transport="udp",
                        port=PFCP_PORT,
                        service="pfcp",
                        evidence={
                            "timeout_s": udp_timeout,
                            "retries": retries,
                            "detail": detail,
                            "probe_time": f"{probe_elapsed:.3f}s"
                        },
                        tags=["exposed", "control-plane"],
                    ))
                    
                elif status == "closed":
                    logger.info(f"🚫 CLOSED: {host}:{PFCP_PORT} - {detail}")
                    fins.append(Finding(
                        finding_id=hashlib.sha1(f"{host}-pfcp-closed".encode()).hexdigest()[:12],
                        component="CORE",
                        interface="N4",
                        protocol="PFCP",
                        risk={"cvss_v3": 0.0, "label": "Info"},
                        summary=f"PFCP ({PFCP_PORT}/udp) cerrado en {host} ({detail}).",
                        recommendation="Sin acción si es intencionado.",
                        target=host,
                        transport="udp",
                        port=PFCP_PORT,
                        service="pfcp",
                        evidence={
                            "timeout_s": udp_timeout,
                            "retries": retries,
                            "detail": detail,
                            "probe_time": f"{probe_elapsed:.3f}s"
                        },
                        tags=["closed"],
                    ))
                    
                elif status == "open|filtered":
                    logger.warning(f"❓ OPEN|FILTERED: {host}:{PFCP_PORT} - {detail}")
                    fins.append(Finding(
                        finding_id=hashlib.sha1(f"{host}-pfcp-amb".encode()).hexdigest()[:12],
                        component="CORE",
                        interface="N4",
                        protocol="PFCP",
                        risk={"cvss_v3": 3.1, "label": "Low"},
                        summary=f"PFCP ({PFCP_PORT}/udp) potencialmente abierto o filtrado en {host}: {detail}.",
                        recommendation="Corroborar desde segmento autorizado y revisar ACLs/Firewall.",
                        target=host,
                        transport="udp",
                        port=PFCP_PORT,
                        service="pfcp",
                        evidence={
                            "timeout_s": udp_timeout,
                            "retries": retries,
                            "detail": detail,
                            "probe_time": f"{probe_elapsed:.3f}s"
                        },
                        tags=["ambiguous"],
                    ))
                    
                else:
                    logger.warning(f"⚠️  UNKNOWN STATUS: {host}:{PFCP_PORT} - {status}: {detail}")
                    fins.append(Finding(
                        finding_id=hashlib.sha1(f"{host}-pfcp-err".encode()).hexdigest()[:12],
                        component="CORE",
                        interface="N4",
                        protocol="PFCP",
                        risk={"cvss_v3": 0.0, "label": "Info"},
                        summary=f"No se pudo verificar PFCP en {host}: {detail}",
                        recommendation="Comprobar reachability o reintentar.",
                        target=host,
                        transport="udp",
                        port=PFCP_PORT,
                        service="pfcp",
                        evidence={
                            "timeout_s": udp_timeout,
                            "retries": retries,
                            "detail": detail,
                            "probe_time": f"{probe_elapsed:.3f}s"
                        },
                        tags=["no-response"],
                    ))
                    
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"❌ EXCEPTION: {host}:{PFCP_PORT} - {type(e).__name__}: {e} (después de {elapsed:.3f}s)")
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{host}-pfcp-exc".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="N4",
                    protocol="PFCP",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"No se pudo verificar PFCP en {host}: {type(e).__name__}",
                    recommendation="Revisar conectividad/ACLs.",
                    target=host,
                    transport="udp",
                    port=PFCP_PORT,
                    service="pfcp",
                    evidence={
                        "error": str(e)[:400],
                        "timeout_s": udp_timeout,
                        "retries": retries
                    },
                    tags=["exception"],
                ))
                
            return fins

        async def guarded(h: str):
            async with sem:
                return await probe_one(h)

        logger.info(f"🎯 Iniciando comprobación PFCP en {len(targets)} targets...")
        scan_start = time.time()
        
        batches = await asyncio.gather(*(guarded(h) for h in targets))
        
        scan_elapsed = time.time() - scan_start
        
        for fins in batches:
            results.extend(fins)
        
        logger.info(f"✨ Escaneo PFCP completado en {scan_elapsed:.2f}s")
        logger.info(f"📊 Resultados: {len(results)} findings generados")
        
        # Resumen por tipo
        risk_summary = {}
        status_summary = {}
        
        for r in results:
            label = r.risk.get('label', 'Unknown')
            risk_summary[label] = risk_summary.get(label, 0) + 1
            
            # Clasificar por tags
            if 'exposed' in r.tags:
                status_summary['PFCP Confirmado'] = status_summary.get('PFCP Confirmado', 0) + 1
            elif 'closed' in r.tags:
                status_summary['Cerrado'] = status_summary.get('Cerrado', 0) + 1
            elif 'ambiguous' in r.tags:
                status_summary['Ambiguo/Filtrado'] = status_summary.get('Ambiguo/Filtrado', 0) + 1
        
        logger.info(f"📈 Resumen por riesgo: {dict(risk_summary)}")
        logger.info(f"📈 Resumen por estado: {dict(status_summary)}")
        logger.info(f"⚡ Velocidad: {len(targets)/scan_elapsed:.2f} hosts/s")
        
        return results