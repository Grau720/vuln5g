# utils/query_parser.py
"""
Parser unificado de consultas avanzadas para VulnDB 5G.

Sintaxis soportada (con comillas, paréntesis y operadores):
    tipo:RCE AND (etiquetas:NGAP OR etiquetas:"core network")
    riesgo:alto OR riesgo:critico
    nombre:"vulnerabilidad http"
    proto:NGAP AND NOT infraestructura:Core
    score>=7.5 AND year:2024

Campos y alias útiles:
    id,cve,cve_id
    nombre,title                -> busca en 'nombre' y 'descripcion_general'
    desc,descripcion,descripción-> 'descripcion_general' y 'descripcion_tecnica'
    tipo
    etiqueta,etiquetas,tag,tags -> 'etiquetas'
    infra,infraestructura       -> 'infraestructura_5g_afectada'
    proto,protocolo,protocolos  -> 'protocolos_implicados'
    interfaz,iface,interfaces   -> 'interfaces_implicadas'
    score,cvss                  -> comparadores: >=, <=, >, <, =, :
    riesgo,severity             -> bajo/medio/alto/critico
    year                        -> prefijo YYYY de 'fecha_publicacion'
"""

import re
from typing import Any, Dict, List

# =========================
#  Mapas de alias y rangos
# =========================

RIESGO_NIVELES = {
    "bajo":   (0.1, 3.9),
    "medio":  (4.0, 6.9),
    "media":  (4.0, 6.9),  # tolerancia
    "alto":   (7.0, 8.9),
    "high":   (7.0, 8.9),
    "critico": (9.0, 10.0),
    "crítico": (9.0, 10.0),
}

# Alias ligeros; se respetan, pero algunas claves se tratan de forma especial abajo
CAMPO_ALIAS = {
    "infraestructura": "infraestructura_5g_afectada",
    # OJO: mantenemos compatibilidad con versiones previas,
    # pero "nombre" tiene tratamiento especial (ver _field_cond)
    "nombre": "descripcion_general",
}

# =========================
#  Helpers
# =========================

def _rx(val: str) -> Dict[str, Any]:
    """Regex case-insensitive seguro."""
    return {"$regex": re.escape(val or ""), "$options": "i"}

_COMPS = [">=", "<=", ">", "<", "=", ":"]

def _score_cmp(op: str, n: float) -> Dict[str, Any]:
    ops = {">=": "$gte", "<=": "$lte", ">": "$gt", "<": "$lt", "=": "$eq", ":": "$eq"}
    return {"cvssv3.score": {ops[op]: n}}

def _riesgo_range(nombre: str):
    return RIESGO_NIVELES.get((nombre or "").lower())

def _field_cond(field: str, op: str, raw_val: str) -> Dict[str, Any]:
    """Traduce un 'campo op valor' a condición MongoDB."""
    f = (field or "").strip()
    f_low = f.lower()
    v = (raw_val or "").strip().strip('"').strip("'")

    # Aplicar alias genéricos
    f_norm = CAMPO_ALIAS.get(f_low, f_low)

    # Casos explícitos / multi-campo
    if f_low in ("id", "cve", "cve_id"):
        return {"cve_id": _rx(v)}

    if f_low in ("nombre", "title"):
        # Buscamos tanto en 'nombre' como en 'descripcion_general'
        return {"$or": [{"nombre": _rx(v)}, {"descripcion_general": _rx(v)}]}

    if f_low in ("desc", "descripcion", "descripción"):
        return {"$or": [{"descripcion_general": _rx(v)}, {"descripcion_tecnica": _rx(v)}]}

    if f_norm == "tipo":
        return {"tipo": _rx(v)}

    if f_low in ("etiqueta", "etiquetas", "tag", "tags"):
        # Para queries libres, permite coincidencia parcial (regex)
        # Si quieres semántica "contiene todas", usa filtros externos ($all)
        return {"etiquetas": _rx(v)}

    if f_low in ("infra", "infraestructura"):
        return {"infraestructura_5g_afectada": _rx(v)}

    if f_low in ("proto", "protocolo", "protocolos"):
        return {"protocolos_implicados": _rx(v)}

    if f_low in ("interfaz", "iface", "interfaces"):
        return {"interfaces_implicadas": _rx(v)}

    if f_low in ("score", "cvss"):
        try:
            n = float(v)
        except Exception:
            n = 0.0
        return _score_cmp(op, n)

    if f_low in ("riesgo", "severity"):
        r = _riesgo_range(v)
        return {"cvssv3.score": {"$gte": r[0], "$lte": r[1]}} if r else {}

    if f_low == "year":
        return {"fecha_publicacion": {"$regex": f"^{re.escape(v)}"}}

    # Campo desconocido => texto libre en varios campos clave
    return {"$or": [
        {"nombre": _rx(v)},
        {"descripcion_general": _rx(v)},
        {"descripcion_tecnica": _rx(v)},
        {"cve_id": _rx(v)},
    ]}

# =========================
#  Tokenizer con comillas y paréntesis
# =========================

def _tokenize(q: str) -> List[Dict[str, Any]]:
    s = (q or "").strip()
    i, n = 0, len(s)
    tokens: List[Dict[str, Any]] = []
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1; continue
        if c in "()":
            tokens.append({"t": c}); i += 1; continue
        # Operadores booleanos con separación adecuada
        if s[i:i+3].upper() == "AND" and (i+3 == n or s[i+3].isspace() or s[i+3] in ")("):
            tokens.append({"t": "AND"}); i += 3; continue
        if s[i:i+2].upper() == "OR" and (i+2 == n or s[i+2].isspace() or s[i+2] in ")("):
            tokens.append({"t": "OR"}); i += 2; continue
        if s[i:i+3].upper() == "NOT" and (i+3 == n or s[i+3].isspace() or s[i+3] in ")("):
            tokens.append({"t": "NOT"}); i += 3; continue
        # Frase entre comillas
        if c in ("'", '"'):
            qch = c; i += 1; buf = []
            while i < n and s[i] != qch:
                buf.append(s[i]); i += 1
            tokens.append({"t": "TERM", "v": "".join(buf)})
            if i < n and s[i] == qch: i += 1
            continue

        # Chunk hasta espacio o paréntesis
        j = i
        while j < n and not s[j].isspace() and s[j] not in "()":
            j += 1
        chunk = s[i:j]

        # ¿Hay comparador dentro del chunk?
        comp_pos = None; comp = None
        for cmp_ in _COMPS:
            p = chunk.find(cmp_)
            if p != -1:
                comp_pos = p; comp = cmp_; break
        if comp_pos is not None:
            field = chunk[:comp_pos]
            val = chunk[comp_pos+len(comp):]
            tokens.append({"t": "COND", "field": field, "op": comp, "val": val})
        else:
            tokens.append({"t": "TERM", "v": chunk})
        i = j
    return tokens

# =========================
#  Shunting-yard -> Postfix
# =========================

_PRECED = {"NOT": 3, "AND": 2, "OR": 1}

def _to_postfix(tokens: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    st: List[str] = []
    for tk in tokens:
        t = tk["t"]
        if t in ("TERM", "COND"):
            out.append(tk)
        elif t in ("AND", "OR", "NOT"):
            while st and st[-1] in _PRECED and _PRECED[st[-1]] >= _PRECED[t]:
                out.append({"t": st.pop()})
            st.append(t)
        elif t == "(":
            st.append("(")
        elif t == ")":
            while st and st[-1] != "(":
                out.append({"t": st.pop()})
            if st and st[-1] == "(":
                st.pop()
    while st:
        op = st.pop()
        if op != "(":
            out.append({"t": op})
    return out

# =========================
#  Conversión a Mongo
# =========================

def _cond_to_mongo(tk: Dict[str, Any]) -> Dict[str, Any]:
    if tk["t"] == "TERM":
        v = tk["v"]
        return {"$or": [
            {"nombre": _rx(v)},
            {"descripcion_general": _rx(v)},
            {"descripcion_tecnica": _rx(v)},
            {"cve_id": _rx(v)},
        ]}
    if tk["t"] == "COND":
        return _field_cond(tk["field"], tk["op"], tk["val"])
    return {}

def _combine(op: str, a: Dict[str, Any], b: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if op == "NOT":
        return {"$nor": [a]}
    if op == "AND":
        arr = []
        for x in (a, b):
            if isinstance(x, dict) and x is not None and "$and" in x:
                arr.extend(x["$and"])
            elif x is not None:
                arr.append(x)
        return {"$and": arr}
    if op == "OR":
        arr = []
        for x in (a, b):
            if isinstance(x, dict) and x is not None and "$or" in x:
                arr.extend(x["$or"])
            elif x is not None:
                arr.append(x)
        return {"$or": arr}
    return {}

# =========================
#  Punto de entrada público
# =========================

def parse_advanced_query(q: str) -> dict:
    """
    Convierte la query avanzada en un diccionario MongoDB listo para $match.

    - Operadores: AND / OR / NOT, con precedencia (NOT > AND > OR)
    - Paréntesis para agrupar
    - Frases entre comillas
    - Comparadores para 'score'/'cvss': >=, <=, >, <, =, :
    - Mapeos de 'riesgo' a rangos CVSS
    - year:YYYY filtra por prefijo de 'fecha_publicacion'
    """
    q = (q or "").strip()
    if not q:
        return {}

    toks = _tokenize(q)
    pf = _to_postfix(toks)
    st: List[Dict[str, Any]] = []

    for tk in pf:
        t = tk["t"]
        if t in ("TERM", "COND"):
            st.append(_cond_to_mongo(tk))
        elif t == "NOT":
            a = st.pop() if st else {}
            st.append(_combine("NOT", a))
        elif t in ("AND", "OR"):
            b = st.pop() if st else {}
            a = st.pop() if st else {}
            st.append(_combine(t, a, b))

    return st[-1] if st else {}
