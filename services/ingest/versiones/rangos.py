from typing import List, Tuple, Optional
import re
import logging

logger = logging.getLogger("ingest-nvd")

def _consolidar_rangos(versiones: list[str]) -> list[str]:
    """
    Fusiona rangos overlapping para reducir redundancia.
    Ejemplo: ">= 2.0 y < 2.5" + ">= 2.0 y < 2.6" → ">= 2.0 y < 2.6"
    
    Maneja:
    - Versiones exactas: "2.4.1"
    - Rangos simples: "< 2.5", ">= 1.0"
    - Rangos compuestos: ">= 2.0 y < 2.5"
    """
    if not versiones:
        return []
    
    exactas = []
    rangos_parseados = []
    rangos_sin_parsear = []
    
    # Separar versiones exactas de rangos
    for v in versiones:
        v = v.strip()
        if not v:
            continue
            
        if any(op in v for op in ['<', '>', '=']):
            parsed = _parse_version_range(v)
            if parsed:
                rangos_parseados.append(parsed)
            else:
                rangos_sin_parsear.append(v)  # Fallback para rangos complejos
        else:
            exactas.append(v)
    
    # Fusionar rangos overlapping
    rangos_fusionados = _merge_overlapping_ranges(rangos_parseados)
    
    # Convertir de vuelta a strings
    rangos_str = [_range_to_string(r) for r in rangos_fusionados]
    
    # Combinar todo
    resultado = exactas + rangos_str + rangos_sin_parsear
    
    # Eliminar duplicados preservando orden
    seen = set()
    resultado_final = []
    for item in resultado:
        if item not in seen:
            seen.add(item)
            resultado_final.append(item)
    
    return resultado_final

def _parse_version_range(range_str: str) -> Optional[dict]:
    """
    Parsea un rango de versiones a formato estructurado.
    
    Ejemplos:
    - "< 2.5" → {'min': None, 'min_incl': False, 'max': '2.5', 'max_incl': False}
    - ">= 1.0 y < 2.0" → {'min': '1.0', 'min_incl': True, 'max': '2.0', 'max_incl': False}
    - "<= 3.0.1" → {'min': None, 'min_incl': False, 'max': '3.0.1', 'max_incl': True}
    """
    try:
        result = {
            'min': None,
            'min_incl': False,
            'max': None,
            'max_incl': False
        }
        
        # Separar por "y" o "and"
        parts = re.split(r'\s+(?:y|and)\s+', range_str.lower())
        
        for part in parts:
            part = part.strip()
            
            # >= X
            match = re.match(r'>=\s*([0-9][\w\.\-]*)', part)
            if match:
                result['min'] = match.group(1)
                result['min_incl'] = True
                continue
            
            # > X
            match = re.match(r'>\s*([0-9][\w\.\-]*)', part)
            if match:
                result['min'] = match.group(1)
                result['min_incl'] = False
                continue
            
            # <= X
            match = re.match(r'<=\s*([0-9][\w\.\-]*)', part)
            if match:
                result['max'] = match.group(1)
                result['max_incl'] = True
                continue
            
            # < X
            match = re.match(r'<\s*([0-9][\w\.\-]*)', part)
            if match:
                result['max'] = match.group(1)
                result['max_incl'] = False
                continue
        
        # Validar que al menos tenga un límite
        if result['min'] is None and result['max'] is None:
            return None
        
        return result
        
    except Exception as e:
        logger.debug(f"No se pudo parsear rango '{range_str}': {e}")
        return None

def _merge_overlapping_ranges(ranges: List[dict]) -> List[dict]:
    """
    Fusiona rangos que se solapan o son adyacentes.
    
    Ejemplo:
    [">= 2.0 y < 2.5", ">= 2.0 y < 2.6"] → [">= 2.0 y < 2.6"]
    """
    if not ranges:
        return []
    
    # Separar rangos con límite inferior de los que solo tienen superior
    ranges_with_min = []
    ranges_without_min = []
    
    for r in ranges:
        if r['min'] is not None:
            ranges_with_min.append(r)
        else:
            ranges_without_min.append(r)
    
    # Ordenar rangos con límite inferior por su valor mínimo
    try:
        ranges_with_min.sort(key=lambda r: (
            _normalize_version(r['min']),
            not r['min_incl']  # False (exclusive) antes que True (inclusive)
        ))
    except Exception:
        # Si falla el sorting, retornar sin fusionar
        return ranges
    
    # Fusionar rangos consecutivos
    merged = []
    current = None
    
    for r in ranges_with_min:
        if current is None:
            current = r.copy()
        else:
            # Verificar si los rangos se solapan
            if _ranges_overlap(current, r):
                # Fusionar: tomar el mínimo más bajo y el máximo más alto
                current = _merge_two_ranges(current, r)
            else:
                merged.append(current)
                current = r.copy()
    
    if current:
        merged.append(current)
    
    # Añadir rangos sin límite inferior (no se pueden fusionar fácilmente)
    merged.extend(ranges_without_min)
    
    return merged

def _ranges_overlap(r1: dict, r2: dict) -> bool:
    """
    Verifica si dos rangos se solapan o son adyacentes.
    """
    try:
        # Si r1 no tiene máximo, siempre se solapa con r2
        if r1['max'] is None:
            return True
        
        # Si r2 no tiene mínimo, verificar si su máximo cubre el mínimo de r1
        if r2['min'] is None:
            if r2['max'] is None:
                return True
            # r2 va hasta su máximo, r1 empieza desde su mínimo
            cmp = _compare_versions(r2['max'], r1['min'])
            return cmp >= 0
        
        # Ambos tienen mínimo definido
        # r2.min debe ser <= r1.max para que se solapen
        cmp = _compare_versions(r2['min'], r1['max'])
        
        if cmp < 0:
            return True  # r2 empieza antes de que termine r1
        elif cmp == 0:
            # Si r2 empieza exactamente donde termina r1, 
            # se solapan solo si al menos uno es inclusive
            return r1['max_incl'] or r2['min_incl']
        else:
            return False  # r2 empieza después de que termine r1
            
    except Exception:
        # En caso de error, asumir que NO se solapan (conservador)
        return False

def _merge_two_ranges(r1: dict, r2: dict) -> dict:
    """
    Fusiona dos rangos overlapping en uno solo.
    """
    merged = {
        'min': None,
        'min_incl': False,
        'max': None,
        'max_incl': False
    }
    
    try:
        # Tomar el mínimo más bajo
        if r1['min'] is None:
            merged['min'] = r2['min']
            merged['min_incl'] = r2['min_incl']
        elif r2['min'] is None:
            merged['min'] = r1['min']
            merged['min_incl'] = r1['min_incl']
        else:
            cmp = _compare_versions(r1['min'], r2['min'])
            if cmp < 0:
                merged['min'] = r1['min']
                merged['min_incl'] = r1['min_incl']
            elif cmp > 0:
                merged['min'] = r2['min']
                merged['min_incl'] = r2['min_incl']
            else:
                # Misma versión: usar inclusive si alguno lo es
                merged['min'] = r1['min']
                merged['min_incl'] = r1['min_incl'] or r2['min_incl']
        
        # Tomar el máximo más alto
        if r1['max'] is None or r2['max'] is None:
            merged['max'] = None
            merged['max_incl'] = False
        else:
            cmp = _compare_versions(r1['max'], r2['max'])
            if cmp > 0:
                merged['max'] = r1['max']
                merged['max_incl'] = r1['max_incl']
            elif cmp < 0:
                merged['max'] = r2['max']
                merged['max_incl'] = r2['max_incl']
            else:
                # Misma versión: usar inclusive si alguno lo es
                merged['max'] = r1['max']
                merged['max_incl'] = r1['max_incl'] or r2['max_incl']
        
        return merged
        
    except Exception:
        # Si falla, retornar r1 sin cambios
        return r1

def _range_to_string(range_dict: dict) -> str:
    """
    Convierte un rango estructurado de vuelta a string.
    """
    parts = []
    
    if range_dict['min'] is not None:
        op = ">=" if range_dict['min_incl'] else ">"
        parts.append(f"{op} {range_dict['min']}")
    
    if range_dict['max'] is not None:
        op = "<=" if range_dict['max_incl'] else "<"
        parts.append(f"{op} {range_dict['max']}")
    
    if len(parts) == 0:
        return "* (todas)"
    elif len(parts) == 1:
        return parts[0]
    else:
        return " y ".join(parts)
