def _generic_workarounds(descripcion: str, etiquetas: list[str], protos: list[str]) -> list[str]:
    t = (descripcion or "").lower()
    et = set((etiquetas or []))
    pr = set((protos or []))
    tips = []

    if "http/2" in t or "http2" in t or "HTTP/2" in pr:
        tips.append("Deshabilitar temporalmente HTTP/2 o aplicar mitigaciones del servidor.")
    if "http" in t or "HTTP" in pr:
        tips.append("Aplicar validación estricta de cabeceras y normalización de rutas.")

    if "DoS" in et:
        tips.append("Aplicar rate limiting y WAF/CDN delante del servicio.")

    if any(x in et for x in ("RCE", "Code-Injection", "Command-Injection")):
        tips.append("Restringir exposición externa y reforzar autenticación mientras se parchea.")

    if "Path-Traversal" in et:
        tips.append("Normalizar rutas y bloquear secuencias '../' en servidor/proxy.")

    if any(x in et for x in ("SCTP", "NGAP", "GTP", "PFCP")):
        tips.append("Filtrar y monitorizar señalización 5G (SCTP, NGAP, GTP, PFCP).")

    if not tips:
        tips.append("Aplicar controles compensatorios (WAF, segmentación) hasta parchear.")

    out, seen = [], set()
    for tip in tips:
        if tip not in seen:
            out.append(tip)
            seen.add(tip)

    return out
