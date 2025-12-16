MAP_PROTO_TO_SERVICE = {
    "PFCP": "UPF",
    "GTP-U": "UPF",
    "GTP-C": "UPF",
    "DIAMETER": "AUSF",
    "NGAP": "AMF",
    "HTTP/2": "SBA",
    "SCTP": "AMF",
}

MAP_PROTO_TO_PORTS = {
    "PFCP": [8805],
    "GTP-U": [2152],
    "GTP-C": [2123],
    "DIAMETER": [3868],
    "NGAP": [38412],
    "HTTP/2": [7777],
}

def inferir_servicio_posible(protocolo: str | None) -> str | None:
    if not protocolo:
        return None
    return MAP_PROTO_TO_SERVICE.get(protocolo)

def inferir_puertos(protocolo: str | None) -> list[int]:
    if not protocolo:
        return []
    return MAP_PROTO_TO_PORTS.get(protocolo, [])
