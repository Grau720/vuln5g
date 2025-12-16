def riesgo_from_score(score: float) -> str:
    if score is None:
        return "desconocido"
    if score >= 9.0:
        return "crítico"
    if score >= 7.0:
        return "alto"
    if score >= 4.0:
        return "medio"
    return "bajo"
