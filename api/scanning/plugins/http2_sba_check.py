# api/scanning/plugins/http2_sba_check.py
import asyncio
import hashlib
import logging
import socket
import ssl
import time
from typing import List
from ..plugin_base import Plugin, ScanContext, Finding

# Configurar logger
logger = logging.getLogger("scanner-plugin-http2sba")

class Http2SbaCheck(Plugin):
    id = "http2_sba_check"
    component = "CORE"
    interfaces = ["Nnrf", "Nnssf", "Npcf", "Nsmf"]
    profile = "all"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []
        
        logger.info(f"🔍 Iniciando Http2SbaCheck - Profile: {ctx.profile}")
        logger.info(f"📋 Targets CORE: {ctx.targets.get('core', [])}")
        
        # Configurar puerto SBA (por defecto 7777 para Open5GS, 443 para deployments con TLS)
        sba_port = int(getattr(ctx, "params", {}).get("sba_port", 7777))
        use_tls = bool(getattr(ctx, "params", {}).get("sba_use_tls", False))
        
        timeout = 1 if ctx.profile == "fast" else (2 if ctx.profile == "standard" else 4)
        sem = asyncio.Semaphore(32 if ctx.profile == "exhaustive" else 16 if ctx.profile == "standard" else 8)
        
        logger.info(f"⚙️  Configuración: timeout={timeout}s, concurrencia={sem._value}, puerto={sba_port}, TLS={use_tls}")

        async def probe(host: str) -> List[Finding]:
            fins: List[Finding] = []
            start_time = time.time()
            logger.debug(f"→ Comprobando HTTP/2 ALPN en {host}:{sba_port}")
            
            try:
                def check():
                    check_start = time.time()
                    logger.debug(f"  → Intentando conexión TCP a {host}:{sba_port}")
                    
                    s = socket.create_connection((host, sba_port), timeout=timeout)
                    tcp_elapsed = time.time() - check_start
                    logger.debug(f"  ✅ TCP conectado en {tcp_elapsed:.3f}s")
                    
                    try:
                        if use_tls:
                            tls_start = time.time()
                            context = ssl.create_default_context()
                            context.set_alpn_protocols(["h2", "http/1.1"])
                            logger.debug(f"  → Iniciando handshake TLS con ALPN: h2, http/1.1")
                            
                            with context.wrap_socket(s, server_hostname=host) as ss:
                                tls_elapsed = time.time() - tls_start
                                alpn = ss.selected_alpn_protocol()
                                
                                logger.info(f"  ✅ TLS establecido en {tls_elapsed:.3f}s - ALPN negociado: {alpn or 'None'}")
                                
                                # Información adicional del certificado
                                cert = ss.getpeercert()
                                if cert:
                                    subject = dict(x[0] for x in cert.get('subject', ()))
                                    cn = subject.get('commonName', 'N/A')
                                    logger.debug(f"  📜 Certificado CN: {cn}")
                                
                                weak = alpn != "h2"
                                
                                if weak:
                                    logger.warning(f"⚠️  {host} NO soporta HTTP/2 - ALPN: {alpn or 'no negociado'}")
                                    fins.append(Finding(
                                        finding_id=hashlib.sha1(f"{host}-h2".encode()).hexdigest()[:12],
                                        component="CORE",
                                        interface="SBA",
                                        protocol="HTTP/2",
                                        risk={"cvss_v3": 6.5, "label": "Medium"},
                                        summary=f"{host}:{sba_port} no negocia ALPN h2 (HTTP/2). Protocolo negociado: {alpn or 'ninguno'}.",
                                        recommendation="Habilitar ALPN h2 y deshabilitar HTTP/1.1 si procede para SBA 5G.",
                                        evidence={
                                            "alpn_negotiated": alpn,
                                            "tls_handshake_time": f"{tls_elapsed:.3f}s",
                                            "port": sba_port
                                        }
                                    ))
                                else:
                                    logger.info(f"✅ {host} soporta HTTP/2 correctamente")
                                    fins.append(Finding(
                                        finding_id=hashlib.sha1(f"{host}-h2-ok".encode()).hexdigest()[:12],
                                        component="CORE",
                                        interface="SBA",
                                        protocol="HTTP/2",
                                        risk={"cvss_v3": 0.0, "label": "Info"},
                                        summary=f"{host}:{sba_port} soporta HTTP/2 correctamente (ALPN: h2).",
                                        recommendation=None,
                                        evidence={
                                            "alpn_negotiated": "h2",
                                            "tls_handshake_time": f"{tls_elapsed:.3f}s",
                                            "port": sba_port
                                        }
                                    ))
                        else:
                            # HTTP sin TLS - verificar si responde HTTP
                            logger.debug(f"  → Modo HTTP sin TLS, enviando GET request simple")
                            
                            # Enviar HTTP request básico
                            http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
                            s.sendall(http_req)
                            
                            # Intentar leer respuesta
                            s.settimeout(1.0)
                            response = s.recv(1024)
                            
                            if response:
                                response_str = response.decode('utf-8', errors='ignore')
                                logger.debug(f"  📥 Respuesta HTTP recibida: {response_str[:100]}")
                                
                                # Verificar si es HTTP/2 (aunque sin TLS es raro)
                                if b'HTTP/2' in response or b'PRI * HTTP/2.0' in response:
                                    logger.info(f"✅ {host}:{sba_port} responde HTTP/2 (sin TLS)")
                                    fins.append(Finding(
                                        finding_id=hashlib.sha1(f"{host}-h2-notls".encode()).hexdigest()[:12],
                                        component="CORE",
                                        interface="SBA",
                                        protocol="HTTP/2",
                                        risk={"cvss_v3": 7.0, "label": "High"},
                                        summary=f"{host}:{sba_port} usa HTTP/2 sin TLS (h2c). Riesgo de seguridad.",
                                        recommendation="Habilitar TLS para proteger comunicaciones SBA.",
                                        evidence={
                                            "protocol": "HTTP/2 cleartext",
                                            "port": sba_port,
                                            "response_preview": response_str[:200]
                                        }
                                    ))
                                elif b'HTTP/1' in response:
                                    logger.warning(f"⚠️  {host}:{sba_port} responde HTTP/1.x sin TLS")
                                    fins.append(Finding(
                                        finding_id=hashlib.sha1(f"{host}-http1".encode()).hexdigest()[:12],
                                        component="CORE",
                                        interface="SBA",
                                        protocol="HTTP/1.x",
                                        risk={"cvss_v3": 8.0, "label": "High"},
                                        summary=f"{host}:{sba_port} usa HTTP/1.x sin TLS ni HTTP/2.",
                                        recommendation="Actualizar a HTTP/2 con TLS para cumplir estándares 5G SBA.",
                                        evidence={
                                            "protocol": "HTTP/1.x cleartext",
                                            "port": sba_port,
                                            "response_preview": response_str[:200]
                                        }
                                    ))
                                else:
                                    logger.info(f"ℹ️  {host}:{sba_port} respondió, pero protocolo desconocido")
                                    fins.append(Finding(
                                        finding_id=hashlib.sha1(f"{host}-unknown".encode()).hexdigest()[:12],
                                        component="CORE",
                                        interface="SBA",
                                        protocol="Unknown",
                                        risk={"cvss_v3": 0.0, "label": "Info"},
                                        summary=f"{host}:{sba_port} responde pero no se pudo identificar el protocolo.",
                                        recommendation="Verificar manualmente el servicio.",
                                        evidence={
                                            "port": sba_port,
                                            "response_preview": response_str[:200]
                                        }
                                    ))
                            else:
                                logger.warning(f"⚠️  {host}:{sba_port} aceptó conexión TCP pero no respondió HTTP")
                                fins.append(Finding(
                                    finding_id=hashlib.sha1(f"{host}-noresponse".encode()).hexdigest()[:12],
                                    component="CORE",
                                    interface="SBA",
                                    protocol="Unknown",
                                    risk={"cvss_v3": 0.0, "label": "Info"},
                                    summary=f"{host}:{sba_port} acepta conexiones TCP pero no responde HTTP.",
                                    recommendation="Verificar si el servicio está correctamente configurado.",
                                    evidence={"port": sba_port}
                                ))
                    finally:
                        s.close()
                        logger.debug(f"  🔒 Conexión cerrada")
                
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, check)
                
            except socket.timeout:
                elapsed = time.time() - start_time
                logger.warning(f"⏱️  TIMEOUT: {host}:{sba_port} (sin respuesta después de {elapsed:.3f}s)")
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{host}-timeout".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="SBA",
                    protocol="HTTP/2",
                    risk={"cvss_v3": 2.5, "label": "Low"},
                    summary=f"No se pudo conectar a {host}:{sba_port} - Timeout después de {timeout}s.",
                    recommendation="Verificar conectividad, firewall o si el servicio está activo.",
                    evidence={"port": sba_port}
                ))
                
            except ConnectionRefusedError:
                elapsed = time.time() - start_time
                logger.info(f"🚫 REFUSED: {host}:{sba_port} (ConnectionRefused en {elapsed:.3f}s)")
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{host}-refused".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="SBA",
                    protocol="HTTP/2",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"Puerto {sba_port} cerrado en {host} (ConnectionRefused).",
                    recommendation=None,
                    evidence={"port": sba_port}
                ))
                
            except ssl.SSLError as e:
                elapsed = time.time() - start_time
                logger.error(f"🔐 SSL ERROR: {host}:{sba_port} - {e} (después de {elapsed:.3f}s)")
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{host}-ssl".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="SBA",
                    protocol="HTTP/2",
                    risk={"cvss_v3": 5.0, "label": "Medium"},
                    summary=f"Error SSL/TLS al conectar con {host}:{sba_port} - {type(e).__name__}",
                    recommendation="Revisar configuración TLS del servidor (certificados, cipher suites).",
                    evidence={"error": str(e)[:200], "port": sba_port}
                ))
                
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"❌ ERROR: {host}:{sba_port} - {type(e).__name__}: {e} (después de {elapsed:.3f}s)")
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{host}-conn".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="SBA",
                    protocol="HTTP/2",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"No se pudo comprobar {host}:{sba_port}: {type(e).__name__}",
                    recommendation="Verificar conectividad de red y configuración del host.",
                    evidence={"error": str(e)[:200], "port": sba_port}
                ))
            
            return fins

        targets = ctx.targets.get("core", [])
        
        if not targets:
            logger.warning("⚠️  No hay targets CORE definidos en el contexto")
            return results

        async def guarded(h: str):
            async with sem:
                return await probe(h)

        logger.info(f"🎯 Iniciando comprobación HTTP/2 en {len(targets)} targets...")
        scan_start = time.time()
        
        batches = await asyncio.gather(*[guarded(h) for h in targets])
        
        scan_elapsed = time.time() - scan_start
        
        for b in batches:
            results.extend(b)
        
        logger.info(f"✨ Escaneo HTTP/2 completado en {scan_elapsed:.2f}s")
        logger.info(f"📊 Resultados: {len(results)} findings generados")
        
        # Resumen por tipo
        risk_summary = {}
        for r in results:
            label = r.risk.get('label', 'Unknown')
            risk_summary[label] = risk_summary.get(label, 0) + 1
        
        logger.info(f"📈 Resumen por riesgo: {dict(risk_summary)}")
        
        return results