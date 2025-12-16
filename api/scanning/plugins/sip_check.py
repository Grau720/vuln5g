# api/scanning/plugins/sip_check.py
import asyncio
import hashlib
import logging
import random
import socket
import ssl
import time
from typing import List
from ..plugin_base import Plugin, ScanContext, Finding

# Configurar logger
logger = logging.getLogger("scanner-plugin-sipcheck")

SIP_UDP_PORT = 5060
SIP_TCP_PORT = 5060
SIP_TLS_PORT = 5061


def _rand_token(n=8):
    return "".join(random.choice("abcdef0123456789") for _ in range(n))


class SipCheck(Plugin):
    id = "sip_check"
    component = "CORE"
    interfaces = ["IMS", "VoLTE", "SIP"]
    profile = "standard|exhaustive"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        results: List[Finding] = []
        
        logger.info(f"🔍 Iniciando SipCheck - Profile: {ctx.profile}")
        logger.info(f"📋 Targets CORE: {ctx.targets.get('core', [])}")
        
        timeout = 0.6 if ctx.profile == "fast" else (1.2 if ctx.profile == "standard" else 2.5)
        sem = asyncio.Semaphore(64 if ctx.profile == "exhaustive" else 32)
        
        logger.info(f"⚙️  Configuración: timeout={timeout}s, concurrencia={sem._value}")
        logger.info(f"🔌 Puertos SIP: UDP/{SIP_UDP_PORT}, TCP/{SIP_TCP_PORT}, TLS/{SIP_TLS_PORT}")

        async def sip_udp_options(host: str, port: int = SIP_UDP_PORT):
            """
            Envía un OPTIONS mínimo por UDP. Si hay cualquier respuesta → reachable.
            """
            start_time = time.time()
            call_id = _rand_token(12)
            branch = _rand_token(10)
            from_tag = _rand_token(8)
            
            logger.debug(f"  → SIP/UDP: Enviando OPTIONS a {host}:{port}")
            logger.debug(f"    Call-ID: {call_id}, Branch: z9hG4bK{branch}")
            
            msg = (
                f"OPTIONS sip:{host} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP 0.0.0.0;branch=z9hG4bK{branch}\r\n"
                f"From: <sip:scanner@local>;tag={from_tag}\r\n"
                f"To: <sip:{host}>\r\n"
                f"Call-ID: {call_id}@local\r\n"
                f"CSeq: 1 OPTIONS\r\n"
                f"Max-Forwards: 70\r\n"
                f"Content-Length: 0\r\n\r\n"
            ).encode()

            loop = asyncio.get_running_loop()
            
            def _send_recv():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                try:
                    send_time = time.time()
                    sock.sendto(msg, (host, port))
                    logger.debug(f"    📤 Datagrama enviado ({len(msg)} bytes)")
                    
                    data, addr = sock.recvfrom(2048)
                    recv_time = time.time()
                    rtt = recv_time - send_time
                    
                    logger.debug(f"    📥 Respuesta recibida ({len(data)} bytes) desde {addr} - RTT: {rtt:.3f}s")
                    logger.debug(f"    Primeros bytes: {data[:100]}")
                    
                    # Intentar parsear código de respuesta SIP
                    try:
                        response_line = data.decode('utf-8', errors='ignore').split('\r\n')[0]
                        logger.debug(f"    📋 Response line: {response_line}")
                        return True, data[:32], response_line
                    except:
                        return True, data[:32], "unknown"
                        
                except socket.timeout:
                    elapsed = time.time() - start_time
                    logger.debug(f"    ⏱️  Sin respuesta después de {elapsed:.3f}s")
                    return None, None, None  # open|filtered (sin respuesta)
                    
                except ConnectionRefusedError:
                    elapsed = time.time() - start_time
                    logger.debug(f"    🚫 ConnectionRefused en {elapsed:.3f}s")
                    return False, None, None  # cerrado
                    
                except Exception as e:
                    elapsed = time.time() - start_time
                    logger.debug(f"    ❌ Error: {type(e).__name__} en {elapsed:.3f}s")
                    return f"err:{type(e).__name__}", None, None
                finally:
                    sock.close()

            ok, resp_data, resp_line = await loop.run_in_executor(None, _send_recv)
            elapsed = time.time() - start_time
            
            if ok is True:
                logger.info(f"  ✅ SIP/UDP OPEN: {host}:{port} - Respondió en {elapsed:.3f}s")
            elif ok is False:
                logger.info(f"  🚫 SIP/UDP CLOSED: {host}:{port} - {elapsed:.3f}s")
            elif ok is None:
                logger.warning(f"  ❓ SIP/UDP FILTERED: {host}:{port} - Timeout {elapsed:.3f}s")
            else:
                logger.error(f"  ❌ SIP/UDP ERROR: {host}:{port} - {ok}")
                
            return ok, resp_line

        async def check_tcp(host: str, port: int, use_tls: bool = False):
            start_time = time.time()
            proto = "TLS" if use_tls else "TCP"
            logger.debug(f"  → SIP/{proto}: Conectando a {host}:{port}")
            
            try:
                if use_tls:
                    # TLS sin validar cert para no fallar por CN/SAN
                    ctx_ssl = ssl._create_unverified_context()
                    logger.debug(f"    🔐 Iniciando handshake TLS...")
                    
                    tls_start = time.time()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ctx_ssl, server_hostname=host),
                        timeout=timeout
                    )
                    tls_elapsed = time.time() - tls_start
                    
                    # Obtener info del certificado
                    try:
                        ssl_obj = writer.get_extra_info('ssl_object')
                        if ssl_obj:
                            cipher = ssl_obj.cipher()
                            version = ssl_obj.version()
                            logger.debug(f"    ✅ TLS establecido: {version}, Cipher: {cipher[0] if cipher else 'unknown'}")
                            logger.debug(f"    ⏱️  TLS handshake: {tls_elapsed:.3f}s")
                    except:
                        pass
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout
                    )
                
                elapsed = time.time() - start_time
                logger.info(f"  ✅ SIP/{proto} OPEN: {host}:{port} - Conectado en {elapsed:.3f}s")
                
                try:
                    writer.close()
                    if hasattr(writer, "wait_closed"):
                        await writer.wait_closed()
                except Exception:
                    pass
                    
                return "open"
                
            except ConnectionRefusedError:
                elapsed = time.time() - start_time
                logger.info(f"  🚫 SIP/{proto} CLOSED: {host}:{port} - Refused en {elapsed:.3f}s")
                return "closed"
                
            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                logger.warning(f"  ⏱️  SIP/{proto} FILTERED: {host}:{port} - Timeout en {elapsed:.3f}s")
                return "filtered"
                
            except ssl.SSLError as e:
                elapsed = time.time() - start_time
                logger.error(f"  🔐 SIP/{proto} SSL ERROR: {host}:{port} - {e} (en {elapsed:.3f}s)")
                return f"ssl_err:{type(e).__name__}"
                
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"  ❌ SIP/{proto} ERROR: {host}:{port} - {type(e).__name__} (en {elapsed:.3f}s)")
                return f"err:{type(e).__name__}"

        async def run_host(h: str):
            fins: List[Finding] = []
            host_start = time.time()
            
            logger.info(f"🎯 Comprobando SIP en host: {h}")

            # UDP/5060 con OPTIONS
            udp_state, resp_line = await sip_udp_options(h, SIP_UDP_PORT)
            
            if udp_state is True:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-udp-open".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/UDP",
                    risk={"cvss_v3": 6.0, "label": "Medium"},
                    summary=f"SIP (UDP/{SIP_UDP_PORT}) responde a OPTIONS en {h}. Revisar exposición y autenticación.",
                    recommendation="Limitar alcance a peers/IMS autorizados, activar autenticación y rate-limit; preferir TLS (5061) si aplica.",
                    evidence={"response_line": resp_line or "unknown"}
                ))
            elif udp_state is False:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-udp-closed".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/UDP",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"SIP (UDP/{SIP_UDP_PORT}) cerrado en {h} (ConnectionRefused).",
                    recommendation=None
                ))
            elif udp_state is None:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-udp-filtered".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/UDP",
                    risk={"cvss_v3": 2.5, "label": "Low"},
                    summary=f"SIP (UDP/{SIP_UDP_PORT}) potencialmente abierto o filtrado en {h}: no hay respuesta (timeout).",
                    recommendation="Verificar políticas de filtrado y si el servicio debería estar expuesto."
                ))
            else:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-udp-err".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/UDP",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"No se pudo comprobar SIP/UDP en {h}: {udp_state}",
                    recommendation=None
                ))

            # TCP/5060 (cleartext)
            st_tcp = await check_tcp(h, SIP_TCP_PORT, use_tls=False)
            
            if st_tcp == "open":
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tcp-open".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TCP",
                    risk={"cvss_v3": 5.5, "label": "Medium"},
                    summary=f"SIP (TCP/{SIP_TCP_PORT}) alcanzable en {h}.",
                    recommendation="Limitar alcance y considerar TLS (5061) si es exposición externa."
                ))
            elif st_tcp in ("closed", "filtered"):
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tcp-{st_tcp}".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TCP",
                    risk={"cvss_v3": 0.0 if st_tcp == "closed" else 2.0, "label": "Info" if st_tcp == "closed" else "Low"},
                    summary=f"SIP (TCP/{SIP_TCP_PORT}) {('cerrado' if st_tcp=='closed' else 'potencialmente abierto o filtrado (timeout)')} en {h}.",
                    recommendation=None if st_tcp == "closed" else "Revisar políticas de filtrado."
                ))
            else:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tcp-err".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TCP",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"No se pudo comprobar SIP/TCP en {h}: {st_tcp}",
                    recommendation=None
                ))

            # TCP/5061 (TLS)
            st_tls = await check_tcp(h, SIP_TLS_PORT, use_tls=True)
            
            if st_tls == "open":
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tls-open".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TLS",
                    risk={"cvss_v3": 4.5, "label": "Medium"},
                    summary=f"SIP (TLS/{SIP_TLS_PORT}) alcanzable en {h}.",
                    recommendation="Verificar certificados (CN/SAN), versiones TLS seguras y autenticación mutua si aplica."
                ))
            elif st_tls in ("closed", "filtered"):
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tls-{st_tls}".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TLS",
                    risk={"cvss_v3": 0.0 if st_tls == "closed" else 2.0, "label": "Info" if st_tls == "closed" else "Low"},
                    summary=f"SIP (TLS/{SIP_TLS_PORT}) {('cerrado' if st_tls=='closed' else 'potencialmente abierto o filtrado (timeout)')} en {h}.",
                    recommendation=None if st_tls == "closed" else "Revisar políticas de filtrado."
                ))
            elif "ssl_err" in st_tls:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tls-sslerr".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TLS",
                    risk={"cvss_v3": 5.0, "label": "Medium"},
                    summary=f"Error SSL/TLS al conectar SIP en {h}:{SIP_TLS_PORT} - {st_tls}",
                    recommendation="Revisar configuración TLS (certificados, cipher suites, versiones).",
                    evidence={"error": st_tls}
                ))
            else:
                fins.append(Finding(
                    finding_id=hashlib.sha1(f"{h}-sip-tls-err".encode()).hexdigest()[:12],
                    component="CORE",
                    interface="IMS",
                    protocol="SIP/TLS",
                    risk={"cvss_v3": 0.0, "label": "Info"},
                    summary=f"No se pudo comprobar SIP/TLS en {h}: {st_tls}",
                    recommendation=None
                ))

            host_elapsed = time.time() - host_start
            logger.info(f"  ✅ Host {h} completado en {host_elapsed:.2f}s - {len(fins)} findings")
            
            return fins

        targets = ctx.targets.get("core", [])
        
        if not targets:
            logger.warning("⚠️  No hay targets CORE definidos en el contexto")
            return results

        async def guarded(h: str):
            async with sem:
                return await run_host(h)

        logger.info(f"🎯 Iniciando comprobación SIP en {len(targets)} targets...")
        scan_start = time.time()
        
        batches = await asyncio.gather(*[guarded(h) for h in targets])
        
        scan_elapsed = time.time() - scan_start
        
        for b in batches:
            results.extend(b)
        
        logger.info(f"✨ Escaneo SIP completado en {scan_elapsed:.2f}s")
        logger.info(f"📊 Resultados: {len(results)} findings generados")
        
        # Resumen por protocolo
        protocol_summary = {}
        risk_summary = {}
        
        for r in results:
            proto = r.protocol
            protocol_summary[proto] = protocol_summary.get(proto, 0) + 1
            
            label = r.risk.get('label', 'Unknown')
            risk_summary[label] = risk_summary.get(label, 0) + 1
        
        logger.info(f"📈 Resumen por protocolo: {dict(protocol_summary)}")
        logger.info(f"📈 Resumen por riesgo: {dict(risk_summary)}")
        logger.info(f"⚡ Velocidad: {len(targets)/scan_elapsed:.2f} hosts/s")
        
        return results