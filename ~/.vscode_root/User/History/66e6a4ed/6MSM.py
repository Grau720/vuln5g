"""
==============================================================
    SMART LABELING SYSTEM FOR EXPLOIT PREDICTION
    Versión 2.0 - Context-Aware Labeling
==============================================================

Mejoras sobre el etiquetado heurístico simple:
- Pesos por tipo de vulnerabilidad (RCE > DoS)
- Multiplicadores por infraestructura 5G crítica
- Keywords de alta peligrosidad
- Edad del CVE (más recientes = más riesgo)
- Validación de "Sin clasificar"
- Sistema de scoring transparente

Objetivo: Reducir falsos positivos y mejorar precision
==============================================================
"""

import re
from datetime import datetime
from typing import Dict, Tuple, List
from dateutil import parser as date_parser


# ============================================================
# PESOS POR TIPO DE VULNERABILIDAD
# ============================================================

TIPO_WEIGHTS = {
    # Alta criticidad (0.8-1.0)
    "Ejecución remota": 1.0,
    "Inyección de comandos/código": 0.95,
    "Inyección SQL": 0.90,
    "Escalada de privilegios": 0.85,
    "Bypass de autenticación": 0.85,
    
    # Media-Alta criticidad (0.5-0.8)
    "Desbordamiento de memoria": 0.70,
    "Divulgación de información": 0.65,
    "Control de acceso incorrecto": 0.60,
    "SSRF": 0.60,
    "XXE": 0.60,
    "Criptografía débil": 0.55,
    
    # Media criticidad (0.4-0.5)
    # DoS reducido drásticamente
    "Denegación de servicio": 0.45,  # ← ANTES era 1.0 implícito
    "Traversal de ruta": 0.50,
    "Validación insuficiente": 0.45,
    "Configuración incorrecta": 0.40,
    
    # Baja criticidad en contexto 5G (0.2-0.4)
    "Cross-Site Scripting": 0.30,
    "Cross-Site Request Forgery": 0.30,
    
    # Sin clasificar: penalización severa
    "Sin clasificar": 0.15,
}


# ============================================================
# MULTIPLICADORES POR INFRAESTRUCTURA 5G
# ============================================================

INFRA_MULTIPLIERS = {
    # Core Network - Crítico (1.4-1.6)
    "AMF": 1.6,      # Access and Mobility Management
    "SMF": 1.6,      # Session Management
    "UPF": 1.5,      # User Plane Function
    "AUSF": 1.5,     # Authentication Server
    "UDM": 1.4,      # Unified Data Management
    
    # Policy & Exposure (1.2-1.4)
    "PCF": 1.3,      # Policy Control
    "NEF": 1.3,      # Network Exposure
    "NRF": 1.2,      # NF Repository
    "NSSF": 1.2,     # Network Slice Selection
    
    # RAN - Radio Access (1.2-1.4)
    "gNB": 1.4,      # Next Generation NodeB
    "CU": 1.3,       # Central Unit
    "DU": 1.2,       # Distributed Unit
    
    # Edge Computing (1.1-1.2)
    "MEC": 1.2,      # Multi-access Edge Computing
    "UPF_Edge": 1.2,
    
    # Otros componentes (1.0-1.1)
    "AF": 1.1,       # Application Function
    "CHF": 1.1,      # Charging Function
    "Default": 1.0,
}


# ============================================================
# KEYWORDS DE ALTA PELIGROSIDAD
# ============================================================

HIGH_DANGER_KEYWORDS = {
    # Autenticación/Autorización (crítico)
    "unauthenticated": 1.4,
    "pre-auth": 1.4,
    "pre-authentication": 1.4,
    "without authentication": 1.4,
    "bypass authentication": 1.3,
    "no authentication": 1.3,
    
    # Ejecución remota (crítico)
    "remote attacker": 1.3,
    "arbitrary code": 1.3,
    "code execution": 1.3,
    "remote code execution": 1.4,
    "rce": 1.4,
    
    # Memory corruption (alto)
    "memory corruption": 1.2,
    "use after free": 1.2,
    "use-after-free": 1.2,
    "buffer overflow": 1.15,
    "heap overflow": 1.15,
    "stack overflow": 1.15,
    
    # Explotación activa (muy crítico)
    "zero-day": 1.5,
    "in the wild": 1.5,
    "actively exploited": 1.5,
    "exploit available": 1.3,
    
    # Privilegios (alto)
    "root privilege": 1.2,
    "superuser": 1.2,
    "admin access": 1.2,
}


# ============================================================
# THRESHOLDS DINÁMICOS POR TIPO
# ============================================================

TIPO_THRESHOLDS = {
    "Ejecución remota": 0.50,            # Más permisivo
    "Inyección de comandos/código": 0.50,
    "Inyección SQL": 0.55,
    "Escalada de privilegios": 0.55,
    "Bypass de autenticación": 0.50,
    "Denegación de servicio": 0.70,      # MUY restrictivo
    "Desbordamiento de memoria": 0.60,
    "Cross-Site Scripting": 0.75,        # Muy restrictivo
    "Sin clasificar": 0.65,              # Muy  restrictivo
    "Default": 0.60,
}


# ============================================================
# FUNCIÓN PRINCIPAL DE SCORING
# ============================================================

def calculate_exploit_score(cve: Dict) -> Tuple[float, Dict]:
    """
    Calcula un score de explotabilidad 0.0-1.0 basado en múltiples factores.
    
    Args:
        cve: Documento CVE desde MongoDB
        
    Returns:
        (score, metadata) donde metadata explica el cálculo paso a paso
    """
    
    metadata = {
        "base_cvss": 0.0,
        "tipo": "Sin clasificar",
        "tipo_weight": 0.0,
        "infra_multiplier": 1.0,
        "keyword_bonus": 0.0,
        "age_factor": 1.0,
        "exploit_refs_bonus": 0.0,
        "cvss_conditions": [],
        "final_adjustments": [],
        "raw_score": 0.0,
        "final_score": 0.0,
    }
    
    # ========================================
    # 1. BASE: CVSS Score (normalizado 0-1)
    # ========================================
    
    cvss = cve.get("cvssv3", {})
    score = float(cvss.get("score", 0.0))
    vector = cvss.get("vector", "")
    
    base_score = min(score / 10.0, 1.0)  # Normalizar a 0-1
    metadata["base_cvss"] = score
    
    # ========================================
    # 2. TIPO DE VULNERABILIDAD
    # ========================================
    
    tipo = cve.get("tipo", "Sin clasificar")
    tipo_weight = TIPO_WEIGHTS.get(tipo, 0.5)
    metadata["tipo"] = tipo
    metadata["tipo_weight"] = tipo_weight
    
    if tipo == "Sin clasificar":
        metadata["final_adjustments"].append("⚠️ Sin clasificar: penalización 85%")
    
    # ========================================
    # 3. CONDICIONES CVSS (vectores)
    # ========================================
    
    is_network = "AV:N" in vector
    is_adjacent = "AV:A" in vector
    is_low_complexity = "AC:L" in vector
    no_priv = "PR:N" in vector
    low_priv = "PR:L" in vector
    no_ui = "UI:N" in vector
    
    cvss_multiplier = 1.0
    
    if is_network:
        cvss_multiplier += 0.3
        metadata["cvss_conditions"].append("Network accessible (+30%)")
    elif is_adjacent:
        cvss_multiplier += 0.1
        metadata["cvss_conditions"].append("Adjacent network (+10%)")
    
    if is_low_complexity:
        cvss_multiplier += 0.2
        metadata["cvss_conditions"].append("Low complexity (+20%)")
    
    if no_priv:
        cvss_multiplier += 0.25
        metadata["cvss_conditions"].append("No privileges required (+25%)")
    elif low_priv:
        cvss_multiplier += 0.1
        metadata["cvss_conditions"].append("Low privileges (+10%)")
    
    if no_ui:
        cvss_multiplier += 0.15
        metadata["cvss_conditions"].append("No user interaction (+15%)")
    
    # ========================================
    # 4. INFRAESTRUCTURA 5G AFECTADA
    # ========================================
    
    infra_list = cve.get("infraestructura_5g_afectada", [])
    infra_multiplier = 1.0
    
    if infra_list:
        multipliers = [INFRA_MULTIPLIERS.get(i, 1.0) for i in infra_list]
        infra_multiplier = max(multipliers)
        metadata["infra_multiplier"] = infra_multiplier
        
        critical_infra = [i for i in infra_list if INFRA_MULTIPLIERS.get(i, 1.0) >= 1.4]
        if critical_infra:
            metadata["final_adjustments"].append(
                f"🔴 Infraestructura crítica ({critical_infra[0]}): +{(infra_multiplier-1)*100:.0f}%"
            )
    
    # ========================================
    # 5. KEYWORDS DE PELIGROSIDAD
    # ========================================
    
    descripcion = (
        cve.get("descripcion_general", "") + " " + 
        cve.get("descripcion_tecnica", "")
    ).lower()
    
    keyword_bonus = 0.0
    keywords_encontradas = []
    
    for keyword, multiplier in HIGH_DANGER_KEYWORDS.items():
        if keyword in descripcion:
            bonus = (multiplier - 1.0) * 0.5  # Suavizar el bonus
            keyword_bonus = max(keyword_bonus, bonus)
            keywords_encontradas.append(keyword)
    
    metadata["keyword_bonus"] = keyword_bonus
    if keywords_encontradas:
        top_keywords = sorted(keywords_encontradas, 
                             key=lambda k: HIGH_DANGER_KEYWORDS[k], 
                             reverse=True)[:3]
        metadata["final_adjustments"].append(
            f"🚨 Keywords críticas: {', '.join(top_keywords)} (+{keyword_bonus*100:.0f}%)"
        )
    
    # ========================================
    # 6. REFERENCIAS A EXPLOITS/PoC
    # ========================================
    
    referencias = cve.get("referencias_mitre", [])
    has_exploit = any(
        isinstance(ref, str) and ("exploit" in ref.lower() or "poc" in ref.lower())
        for ref in referencias
    )
    
    exploit_bonus = 0.0
    if has_exploit:
        exploit_bonus = 0.3  # +30% si hay exploit público
        metadata["exploit_refs_bonus"] = exploit_bonus
        metadata["final_adjustments"].append("💥 Exploit público disponible (+30%)")
    
    # ========================================
    # 7. EDAD DEL CVE
    # ========================================
    
    age_factor = 1.0
    fecha_pub = cve.get("fecha_publicacion")
    
    if fecha_pub:
        try:
            fecha_dt = date_parser.parse(fecha_pub)
            dias = (datetime.now() - fecha_dt).days
            
            if dias < 30:
                age_factor = 1.3  # Muy reciente
                metadata["final_adjustments"].append(f"🆕 CVE reciente ({dias} días): +30%")
            elif dias < 90:
                age_factor = 1.15  # Reciente
                metadata["final_adjustments"].append(f"🆕 CVE reciente ({dias} días): +15%")
            elif dias < 180:
                age_factor = 1.05  # Semi-reciente
            else:
                age_factor = 1.0
            
            metadata["age_factor"] = age_factor
        except:
            pass
    
    # ========================================
    # 8. CÁLCULO FINAL
    # ========================================
    
    # Fórmula: base_score * tipo_weight * cvss_mult * infra_mult * age_factor + bonuses
    raw_score = (
        base_score * 
        tipo_weight * 
        cvss_multiplier * 
        infra_multiplier * 
        age_factor
    ) + keyword_bonus + exploit_bonus
    
    # Clamp a [0, 1]
    final_score = min(max(raw_score, 0.0), 1.0)
    
    metadata["raw_score"] = raw_score
    metadata["final_score"] = final_score
    
    return final_score, metadata


# ============================================================
# ETIQUETADO CON THRESHOLD DINÁMICO
# ============================================================

def smart_label(cve: Dict, return_metadata: bool = False) -> int:
    """
    Etiqueta un CVE como explotable (1) o no (0).
    Usa threshold dinámico según tipo de vulnerabilidad.
    
    Args:
        cve: Documento CVE
        return_metadata: Si True, retorna (label, score, metadata)
        
    Returns:
        int: 0 o 1 (o tupla si return_metadata=True)
    """
    score, metadata = calculate_exploit_score(cve)
    
    tipo = cve.get("tipo", "Sin clasificar")
    threshold = TIPO_THRESHOLDS.get(tipo, TIPO_THRESHOLDS["Default"])
    
    label = 1 if score >= threshold else 0
    
    if return_metadata:
        metadata["threshold_used"] = threshold
        metadata["label"] = label
        return label, score, metadata
    
    return label


# ============================================================
# PROCESAMIENTO EN BATCH
# ============================================================

def smart_label_batch(cves: List[Dict], verbose: bool = False) -> List[int]:
    """
    Etiqueta una lista de CVEs usando smart labeling.
    
    Args:
        cves: Lista de documentos CVE
        verbose: Si True, imprime estadísticas
        
    Returns:
        Lista de labels (0 o 1)
    """
    labels = []
    scores = []
    tipos_count = {}
    
    for cve in cves:
        label, score, metadata = smart_label(cve, return_metadata=True)
        labels.append(label)
        scores.append(score)
        
        tipo = metadata["tipo"]
        if tipo not in tipos_count:
            tipos_count[tipo] = {"explotable": 0, "no_explotable": 0}
        
        if label == 1:
            tipos_count[tipo]["explotable"] += 1
        else:
            tipos_count[tipo]["no_explotable"] += 1
    
    if verbose:
        print("\n" + "="*70)
        print("  🏷️  SMART LABELING - RESUMEN")
        print("="*70)
        print(f"\n📊 Total CVEs procesados: {len(cves)}")
        print(f"✅ Explotables: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        print(f"❌ No explotables: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
        print(f"\n📈 Score promedio: {sum(scores)/len(scores):.3f}")
        print(f"📈 Score mediana: {sorted(scores)[len(scores)//2]:.3f}")
        
        print(f"\n🏷️  Distribución por tipo de vulnerabilidad:")
        for tipo, counts in sorted(tipos_count.items(), 
                                   key=lambda x: x[1]["explotable"], 
                                   reverse=True)[:10]:
            total_tipo = counts["explotable"] + counts["no_explotable"]
            pct = counts["explotable"] / total_tipo * 100 if total_tipo > 0 else 0
            print(f"   {tipo:40s}: {counts['explotable']:3d}/{total_tipo:3d} ({pct:5.1f}%)")
        
        print("="*70 + "\n")
    
    return labels


# ============================================================
# FUNCIÓN DE EXPLICACIÓN
# ============================================================

def explain_label(cve: Dict) -> str:
    """
    Genera una explicación detallada de por qué un CVE fue etiquetado.
    
    Args:
        cve: Documento CVE
        
    Returns:
        str: Explicación formateada
    """
    label, score, metadata = smart_label(cve, return_metadata=True)
    
    lines = [
        f"\n{'='*70}",
        f"  EXPLICACIÓN DE ETIQUETADO: {cve.get('cve_id')}",
        f"{'='*70}",
        f"\n📊 RESULTADO FINAL:",
        f"   Label: {'✅ EXPLOTABLE (1)' if label == 1 else '❌ NO EXPLOTABLE (0)'}",
        f"   Score: {score:.3f}",
        f"   Threshold: {metadata['threshold_used']:.3f}",
        f"\n📈 COMPONENTES DEL SCORE:",
        f"   Base CVSS: {metadata['base_cvss']:.1f}/10 (norm: {metadata['base_cvss']/10:.3f})",
        f"   Tipo: {metadata['tipo']} (peso: {metadata['tipo_weight']:.2f})",
        f"   Infraestructura multiplier: {metadata['infra_multiplier']:.2f}x",
        f"   Keyword bonus: +{metadata['keyword_bonus']:.3f}",
        f"   Exploit refs bonus: +{metadata['exploit_refs_bonus']:.3f}",
        f"   Age factor: {metadata['age_factor']:.2f}x",
    ]
    
    if metadata['cvss_conditions']:
        lines.append(f"\n🎯 CONDICIONES CVSS:")
        for cond in metadata['cvss_conditions']:
            lines.append(f"   • {cond}")
    
    if metadata['final_adjustments']:
        lines.append(f"\n⚙️  AJUSTES FINALES:")
        for adj in metadata['final_adjustments']:
            lines.append(f"   • {adj}")
    
    lines.append(f"\n{'='*70}\n")
    
    return "\n".join(lines)