_PROTO_KWS = [
    "http/2", "http2", "http", "https", "ngap", "diameter", "sctp", "gtp", "gtp-u", "gtp-c",
    "pfcp", "tls", "ssh", "snmp", "udp", "tcp", "icmp", "quic", "coap", "mqtt"
]

def extract_protocols(text: str):
    if not text:
        return []
    t = text.lower()
    found = set()
    for kw in _PROTO_KWS:
        if kw in t:
            norm = "http/2" if kw in ("http2", "http/2") else kw
            found.add(norm.upper())
    return sorted(found)

def inferir_protocolo_principal(protocolos: list[str]) -> str | None:
    if not protocolos:
        return None
    preferencia = ["PFCP", "NGAP", "GTP-U", "GTP-C", "DIAMETER", "HTTP/2", "SCTP"]
    for p in preferencia:
        if p in protocolos:
            return p
    return protocolos[0]
