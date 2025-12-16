import re

_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_SIMPLEVER_RE = re.compile(r"(\d+)(?:\.(\d+))?")

def _compare_versions(v1: str, v2: str) -> int:
    """
    Compara dos versiones semánticamente.
    Retorna: -1 si v1 < v2, 0 si v1 == v2, 1 si v1 > v2
    """
    try:
        # Intentar con packaging (más robusto)
        pv1 = pkg_version.parse(v1)
        pv2 = pkg_version.parse(v2)
        
        if pv1 < pv2:
            return -1
        elif pv1 > pv2:
            return 1
        else:
            return 0
            
    except Exception:
        # Fallback: comparación simple de tuplas numéricas
        try:
            parts1 = [int(x) for x in re.findall(r'\d+', v1)]
            parts2 = [int(x) for x in re.findall(r'\d+', v2)]
            
            # Rellenar con ceros para comparar
            max_len = max(len(parts1), len(parts2))
            parts1 += [0] * (max_len - len(parts1))
            parts2 += [0] * (max_len - len(parts2))
            
            if parts1 < parts2:
                return -1
            elif parts1 > parts2:
                return 1
            else:
                return 0
                
        except Exception:
            # Fallback final: comparación alfabética
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0

def _normalize_version(v: str) -> tuple:
    """
    Normaliza una versión a tupla para sorting.
    "2.10.3" → (2, 10, 3)
    """
    try:
        return tuple(int(x) for x in re.findall(r'\d+', v))
    except Exception:
        return (0,)

def _version_sort_key(version: str):
    """
    Key para ordenar versiones semánticamente.
    "2.10.3" debe ir después de "2.9.1" (no alfabéticamente).
    """
    if not version or not version[0].isdigit():
        # Rangos o versiones no estándar van al final
        return (999, 999, 999, version)
    
    # Intentar parsear como X.Y.Z
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
    if match:
        return tuple(map(int, match.groups())) + (version,)
    
    # Intentar parsear como X.Y
    match = re.match(r'(\d+)\.(\d+)', version)
    if match:
        return tuple(map(int, match.groups())) + (0, version)
    
    # Solo X
    if version.isdigit():
        return (int(version), 0, 0, version)
    
    # Fallback: alfabético
    return (999, 999, 999, version)

def _bump_patch(v: str) -> str | None:
    m = _SEMVER_RE.fullmatch(v)
    if m:
        x, y, z = map(int, m.groups())
        return f"{x}.{y}.{z+1}"
    m2 = _SIMPLEVER_RE.fullmatch(v)
    if m2:
        x = int(m2.group(1))
        y = m2.group(2)
        if y is not None:
            return f"{x}.{int(y)+1}"
        return str(x)
    return None
