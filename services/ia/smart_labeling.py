"""
==============================================================
    SMART LABELING SYSTEM FOR EXPLOIT PREDICTION
    Versión 2.1 - Attack Vector Aware Thresholds
==============================================================

NUEVO en v2.1:
- Thresholds diferenciados por Attack Vector (NETWORK vs LOCAL)
- Penalización extra para DoS sin infraestructura crítica
- Validación mejorada para "Sin clasificar"

Cambios clave:
- LOCAL: threshold 0.75 (era 0.60) → Mucho más restrictivo
- NETWORK: threshold 0.50 (sin cambios)
- DoS sin core 5G: peso reducido 50%
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
    "Denegación de servicio": 0.45,  # Base, se reduce más si no es core
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

# Componentes Core críticos para validación DoS
CORE_5G_CRITICAL = {"AMF", "SMF", "UPF", "AUSF", "UDM"}


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
# THRESHOLDS DINÁMICOS POR ATTACK VECTOR Y TIPO
# ============================================================

# Thresholds base por Attack Vector
AV_THRESHOLDS = {
    "NETWORK": 0.50,      # Acceso remoto = más peligroso
    "ADJACENT": 0.65,     # Red adyacente = intermedio
    "LOCAL": 0.75,        # ⚡ NUEVO: Acceso local = mucho más restrictivo
    "PHYSICAL": 0.85,     # Acceso físico = muy restrictivo
    "UNKNOWN": 0.70,      # Conservador por defecto
}

# Ajustes adicionales por tipo (se suman al threshold del AV)
TIPO_THRESHOLD_ADJUSTMENTS = {
    "Ejecución remota": -0.10,                    # Más permisivo
    "Inyección de comandos/código": -0.10,
    "Inyección SQL": -0.05,
    "Escalada de privilegios": -0.05,
    "Bypass de autenticación": -0.10,
    "Denegación de servicio": +0.15,              # ⚡ MÁS restrictivo
    "Cross-Site Scripting": +0.10,
    "Sin clasificar": +0.10,
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
        "attack_vector": "UNKNOWN",
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
    
    base_score = min(score / 10.0, 1.0)
    metadata["base_cvss"] = score
    
    # ========================================
    # 2. TIPO DE VULNERABILIDAD
    # ========================================
    
    tipo = cve.get("tipo", "Sin clasificar")
    tipo_weight = TIPO_WEIGHTS.get(tipo, 0.5)
    
    # ⚡ NUEVO: Penalización extra para DoS sin core 5G
    if tipo == "Denegación de servicio":
        infra_list = cve.get("infraestructura_5g_afectada", [])
        has_critical_infra = any(i in CORE_5G_CRITICAL for i in infra_list)
        
        if not has_critical_infra:
            tipo_weight *= 0.5  # Reducción 50%: 0.45 → 0.225
            metadata["final_adjustments"].append(
                "⚠️ DoS sin infraestructura core: peso reducido 50%"
            )
    
    metadata["tipo"] = tipo
    metadata["tipo_weight"] = tipo_weight
    
    if tipo == "Sin clasificar":
        metadata["final_adjustments"].append("⚠️ Sin clasificar: penalización 85%")
    
    # ========================================
    # 3. ATTACK VECTOR (para threshold dinámico)
    # ========================================
    
    if "AV:N" in vector:
        attack_vector = "NETWORK"
    elif "AV:A" in vector:
        attack_vector = "ADJACENT"
    elif "AV:L" in vector:
        attack_vector = "LOCAL"
    elif "AV:P" in vector:
        attack_vector = "PHYSICAL"
    else:
        attack_vector = "UNKNOWN"
    
    metadata["attack_vector"] = attack_vector
    
    # ========================================
    # 4. CONDICIONES CVSS (vectores)
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
    # 5. INFRAESTRUCTURA 5G AFECTADA
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
    # 6. KEYWORDS DE PELIGROSIDAD
    # ========================================
    
    descripcion = (
        cve.get("descripcion_general", "") + " " + 
        cve.get("descripcion_tecnica", "")
    ).lower()
    
    keyword_bonus = 0.0
    keywords_encontradas = []
    
    for keyword, multiplier in HIGH_DANGER_KEYWORDS.items():
        if keyword in descripcion:
            bonus = (multiplier - 1.0) * 0.5
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
    # 7. REFERENCIAS A EXPLOITS/PoC
    # ========================================
    
    referencias = cve.get("referencias_mitre", [])
    has_exploit = any(
        isinstance(ref, str) and ("exploit" in ref.lower() or "poc" in ref.lower())
        for ref in referencias
    )
    
    exploit_bonus = 0.0
    if has_exploit:
        exploit_bonus = 0.3
        metadata["exploit_refs_bonus"] = exploit_bonus
        metadata["final_adjustments"].append("💥 Exploit público disponible (+30%)")
    
    # ========================================
    # 8. EDAD DEL CVE
    # ========================================
    
    age_factor = 1.0
    fecha_pub = cve.get("fecha_publicacion")
    
    if fecha_pub:
        try:
            fecha_dt = date_parser.parse(fecha_pub)
            dias = (datetime.now() - fecha_dt).days
            
            if dias < 30:
                age_factor = 1.3
                metadata["final_adjustments"].append(f"🆕 CVE reciente ({dias} días): +30%")
            elif dias < 90:
                age_factor = 1.15
                metadata["final_adjustments"].append(f"🆕 CVE reciente ({dias} días): +15%")
            elif dias < 180:
                age_factor = 1.05
            else:
                age_factor = 1.0
            
            metadata["age_factor"] = age_factor
        except:
            pass
    
    # ========================================
    # 9. CÁLCULO FINAL
    # ========================================
    
    raw_score = (
        base_score * 
        tipo_weight * 
        cvss_multiplier * 
        infra_multiplier * 
        age_factor
    ) + keyword_bonus + exploit_bonus
    
    final_score = min(max(raw_score, 0.0), 1.0)
    
    metadata["raw_score"] = raw_score
    metadata["final_score"] = final_score
    
    return final_score, metadata


# ============================================================
# ETIQUETADO CON THRESHOLD DINÁMICO (Attack Vector Aware)
# ============================================================

def smart_label(cve: Dict, return_metadata: bool = False):
    """
    Etiqueta un CVE como explotable (1) o no (0).
    ⚡ NUEVO: Usa threshold dinámico según Attack Vector + Tipo.
    
    Args:
        cve: Documento CVE
        return_metadata: Si True, retorna (label, score, metadata)
        
    Returns:
        int: 0 o 1 (o tupla si return_metadata=True)
    """
    score, metadata = calculate_exploit_score(cve)
    
    # Threshold base por Attack Vector
    attack_vector = metadata["attack_vector"]
    base_threshold = AV_THRESHOLDS.get(attack_vector, 0.70)
    
    # Ajuste por tipo de vulnerabilidad
    tipo = cve.get("tipo", "Sin clasificar")
    tipo_adjustment = TIPO_THRESHOLD_ADJUSTMENTS.get(tipo, 0.0)
    
    # Threshold final
    threshold = min(max(base_threshold + tipo_adjustment, 0.30), 0.95)
    
    label = 1 if score >= threshold else 0
    
    if return_metadata:
        metadata["threshold_used"] = threshold
        metadata["threshold_base"] = base_threshold
        metadata["threshold_adjustment"] = tipo_adjustment
        metadata["label"] = label
        return label, score, metadata
    
    return label


# ============================================================
# PROCESAMIENTO EN BATCH
# ============================================================

def smart_label_batch(cves: List[Dict], verbose: bool = False) -> List[int]:
    """
    Etiqueta una lista de CVEs usando smart labeling v2.1.
    
    Args:
        cves: Lista de documentos CVE
        verbose: Si True, imprime estadísticas
        
    Returns:
        Lista de labels (0 o 1)
    """
    labels = []
    scores = []
    tipos_count = {}
    av_stats = {"NETWORK": {"exp": 0, "total": 0},
                "LOCAL": {"exp": 0, "total": 0},
                "ADJACENT": {"exp": 0, "total": 0},
                "PHYSICAL": {"exp": 0, "total": 0},
                "UNKNOWN": {"exp": 0, "total": 0}}
    
    for cve in cves:
        label, score, metadata = smart_label(cve, return_metadata=True)
        labels.append(label)
        scores.append(score)
        
        # Stats por tipo
        tipo = metadata["tipo"]
        if tipo not in tipos_count:
            tipos_count[tipo] = {"explotable": 0, "no_explotable": 0}
        
        if label == 1:
            tipos_count[tipo]["explotable"] += 1
        else:
            tipos_count[tipo]["no_explotable"] += 1
        
        # Stats por Attack Vector
        av = metadata["attack_vector"]
        av_stats[av]["total"] += 1
        if label == 1:
            av_stats[av]["exp"] += 1
    
    if verbose:
        print("\n" + "="*70)
        print("  🏷️  SMART LABELING v2.1 - RESUMEN")
        print("="*70)
        print(f"\n📊 Total CVEs procesados: {len(cves)}")
        print(f"✅ Explotables: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        print(f"❌ No explotables: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
        print(f"\n📈 Score promedio: {sum(scores)/len(scores):.3f}")
        print(f"📈 Score mediana: {sorted(scores)[len(scores)//2]:.3f}")
        
        print(f"\n🎯 Distribución por Attack Vector:")
        for av, stats in sorted(av_stats.items(), key=lambda x: x[1]["total"], reverse=True):
            if stats["total"] > 0:
                pct = stats["exp"] / stats["total"] * 100
                threshold = AV_THRESHOLDS.get(av, 0.70)
                print(f"   {av:12s}: {stats['exp']:3d}/{stats['total']:3d} ({pct:5.1f}%) | threshold={threshold:.2f}")
        
        print(f"\n🏷️  Top 10 tipos de vulnerabilidad:")
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
        f"   Threshold: {metadata['threshold_used']:.3f} (base={metadata['threshold_base']:.2f}, adj={metadata['threshold_adjustment']:+.2f})",
        f"\n📈 COMPONENTES DEL SCORE:",
        f"   Base CVSS: {metadata['base_cvss']:.1f}/10 (norm: {metadata['base_cvss']/10:.3f})",
        f"   Tipo: {metadata['tipo']} (peso: {metadata['tipo_weight']:.2f})",
        f"   Attack Vector: {metadata['attack_vector']}",
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