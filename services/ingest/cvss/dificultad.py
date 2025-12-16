def dificultad_from_vector(vector: str) -> str:
    if not vector or not isinstance(vector, str):
        return "Desconocida"
    v = vector.upper()
    score = 0
    if "AC:H" in v:
        score += 2
    if "PR:H" in v:
        score += 2
    elif "PR:L" in v:
        score += 1
    if "UI:R" in v:
        score += 1
    if "AV:N" in v:
        score -= 1
    if score <= 0:
        return "Baja"
    if score <= 2:
        return "Media"
    return "Alta"
