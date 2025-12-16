
def _norm(t: str) -> str:
    return (t or "").lower().strip()
    
def analizar_no_clasificados(cves_no_clasificadas: list[str]) -> dict:
    """
    Analiza CVEs no clasificados para encontrar patrones comunes.
    """
    palabras = []
    for cve in cves_no_clasificadas:
        tokens = _norm(cve).split()
        palabras.extend([t for t in tokens if len(t) > 4])
    return Counter(palabras).most_common(50)

