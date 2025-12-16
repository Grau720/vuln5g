# scanning/utils/udp_pfcp.py
import socket, os, struct, random

PFCP_PORT = 8805
RECV_TIMEOUT = float(os.getenv("PFCP_RECV_TIMEOUT", "1.0"))  # segundos
RETRIES = int(os.getenv("PFCP_RETRIES", "2"))

def _build_pfcp_probe(seq: int = None) -> bytes:
    """
    Construye un Heartbeat Request (tipo 4) con un IE mínimo (Recovery Time Stamp).
    Esto aumenta la probabilidad de que un UPF/SMF responda.
    Estructura header PFCP v1 sin SEID:
      0: version(1 nibble=1) + spare/flags (S=0)  -> 0x20
      1: message type (4=Heartbeat Request)
      2-3: length (payload len)
      4-6: sequence number (24 bits)
      7:  spare
    Cuerpo: IE Recovery Time Stamp (IE type 96, len 4, valor 0).
    """
    if seq is None:
      seq = random.randint(1, 0xFFFFFF)

    # IE: Recovery Time Stamp (type=96, length=4, value=0)
    ie = struct.pack("!HHI", 96, 4, 0)
    length = len(ie)

    hdr = bytearray(8)
    hdr[0] = 0x20            # v1, S=0
    hdr[1] = 0x04            # Heartbeat Request
    hdr[2] = (length >> 8) & 0xFF
    hdr[3] = length & 0xFF
    hdr[4] = (seq >> 16) & 0xFF
    hdr[5] = (seq >> 8) & 0xFF
    hdr[6] = seq & 0xFF
    hdr[7] = 0x00            # spare
    return bytes(hdr) + ie

def _is_pfcp_response(data: bytes) -> bool:
    if len(data) < 8:
        return False
    # versión v1 (0x2x) y tipo plausible (1..255), longitud coherente
    ver = data[0] >> 4
    msg_type = data[1]
    if ver != 1:
        return False
    # Length campo 2-3
    plen = (data[2] << 8) | data[3]
    return len(data) >= 8 + plen and msg_type in range(1, 256)

def pfcp_probe(host: str, port: int = PFCP_PORT):
    """
    Devuelve (status, detail) donde status ∈ {"pfcp", "closed", "open|filtered", "error"}.
    """
    addr = (host, int(port))
    probe = _build_pfcp_probe()
    for _ in range(max(1, RETRIES)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(RECV_TIMEOUT)
            # Enviamos un paquete PFCP válido
            sock.sendto(probe, addr)
            try:
                data, _ = sock.recvfrom(2048)
                if _is_pfcp_response(data):
                    return ("pfcp", "Valid PFCP response")
                # Si responde algo no PFCP, es raro: reporta open|filtered
                return ("open|filtered", "Non-PFCP UDP response")
            except ConnectionRefusedError:
                # ICMP port unreachable → cerrado
                return ("closed", "ICMP Port Unreachable")
            except socket.timeout:
                # No respuesta en este intento
                pass
            finally:
                sock.close()
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return ("error", f"{type(e).__name__}: {e}")
    # Sin respuesta tras reintentos
    return ("open|filtered", "No UDP response (timeout)")
