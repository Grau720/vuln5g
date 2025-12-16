"""
==============================================================
    LABEL VALIDATOR - Comparación de Métodos de Etiquetado
==============================================================

Compara el método heurístico original vs Smart Labeling
y genera reportes detallados de las diferencias.
==============================================================
"""

import os
import sys
import pandas as pd
import numpy as np
from pymongo import MongoClient
from collections import Counter

sys.path.append('/app/ia')
from smart_labeling import smart_label, explain_label, smart_label_batch


# Configuración MongoDB
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_HOST = os.getenv("MONGO_HOST", "vulndb_mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB   = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}?authSource={MONGO_AUTH}"


def load_cves():
    """Carga CVEs desde MongoDB"""
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB]
    col = db[MONGO_COLLECTION]
    
    cves = list(col.find({"cvssv3.score": {"$exists": True}}))
    client.close()
    
    return cves


def original_label(cve: dict) -> int:
    """
    Método de etiquetado ORIGINAL (heurístico simple).
    Reproducido del train_exploit_model.py actual.
    """
    cvss = cve.get("cvssv3", {})
    cvss_score = cvss.get("score") or 0
    vector = cvss.get("vector") or ""
    
    referencias = cve.get("referencias_mitre") or []
    has_exploit_refs = any(
        isinstance(ref, str) and (
            'exploit' in ref.lower() or 'poc' in ref.lower()
        )
        for ref in referencias
    )
    
    is_network = "AV:N" in vector
    is_low_complexity = "AC:L" in vector
    no_priv = "PR:N" in vector
    no_ui = "UI:N" in vector
    
    tipo = (cve.get("tipo") or "").lower()
    critical_types = [
        'ejecución remota',
        'ejecución de código',
        'escalada de privilegios',
        'inyección de comandos',
        'inyección sql'
    ]
    is_critical_type = any(ct in tipo for ct in critical_types)
    
    desc = (
        (cve.get("descripcion_tecnica") or "") + " " +
        (cve.get("descripcion_general") or "")
    ).lower()
    dangerous_keywords = [
        'remote code execution', 'rce', 'unauthenticated',
        'memory corruption', 'buffer overflow', 'use after free',
        'arbitrary code', 'root privilege', 'privilege escalation',
        'sql injection', 'command injection', 'path traversal',
        'cross-site scripting', 'xss', 'csrf', 'authentication bypass'
    ]
    has_dangerous_keywords = any(kw in desc for kw in dangerous_keywords)
    
    componente = (cve.get("componente_afectado") or "").lower()
    critical_components = [
        'kernel', 'openssh', 'apache', 'nginx', 'mysql',
        'postgresql', 'wordpress', 'drupal', 'windows'
    ]
    is_critical_component = any(cc in componente for cc in critical_components)
    
    # Sistema de puntuación del método original
    score = 0
    
    if has_exploit_refs:
        score += 100
    
    if cvss_score >= 9.0:
        score += 50
    
    if cvss_score >= 7.0:
        if is_network:
            score += 20
        if is_low_complexity:
            score += 10
        if no_priv:
            score += 5
        if no_ui:
            score += 5
    
    if cvss_score >= 6.0 and is_network and is_low_complexity:
        score += 30
    
    if is_critical_type:
        score += 25
    
    if has_dangerous_keywords:
        score += 20
    
    if is_critical_component:
        score += 15
    
    return 1 if score >= 40 else 0


def compare_methods(cves: list) -> pd.DataFrame:
    """
    Compara ambos métodos de etiquetado y genera reporte detallado.
    """
    print("\n" + "="*70)
    print("  🔬 COMPARACIÓN DE MÉTODOS DE ETIQUETADO")
    print("="*70 + "\n")
    
    print("🔄 Procesando CVEs con ambos métodos...")
    
    results = []
    
    for i, cve in enumerate(cves, 1):
        if i % 50 == 0:
            print(f"   Procesado: {i}/{len(cves)}")
        
        cve_id = cve.get("cve_id")
        cvss_score = cve.get("cvssv3", {}).get("score", 0)
        tipo = cve.get("tipo", "Sin clasificar")
        
        # Etiquetado original
        old_label = original_label(cve)
        
        # Smart labeling
        new_label, score, metadata = smart_label(cve, return_metadata=True)
        
        # Detectar discrepancia
        discrepancia = old_label != new_label
        
        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "tipo": tipo,
            "old_label": old_label,
            "new_label": new_label,
            "smart_score": score,
            "threshold": metadata["threshold_used"],
            "discrepancia": discrepancia,
            "tipo_weight": metadata["tipo_weight"],
            "infra_multiplier": metadata["infra_multiplier"],
            "has_exploit_refs": metadata["exploit_refs_bonus"] > 0,
        })
    
    df = pd.DataFrame(results)
    
    return df


def analyze_comparison(df: pd.DataFrame):
    """
    Analiza las diferencias entre métodos.
    """
    print("\n" + "="*70)
    print("  📊 ANÁLISIS DE RESULTADOS")
    print("="*70 + "\n")
    
    total = len(df)
    
    # Estadísticas generales
    old_pos = (df['old_label'] == 1).sum()
    new_pos = (df['new_label'] == 1).sum()
    discrepancias = df['discrepancia'].sum()
    
    print(f"📈 ETIQUETAS POSITIVAS (explotables):")
    print(f"   Método original: {old_pos} ({old_pos/total*100:.1f}%)")
    print(f"   Smart labeling:  {new_pos} ({new_pos/total*100:.1f}%)")
    print(f"   Diferencia: {new_pos - old_pos:+d} ({(new_pos-old_pos)/total*100:+.1f}%)")
    
    print(f"\n🔀 DISCREPANCIAS:")
    print(f"   Total: {discrepancias} ({discrepancias/total*100:.1f}%)")
    
    # Tipos de discrepancias
    old_1_new_0 = ((df['old_label'] == 1) & (df['new_label'] == 0)).sum()
    old_0_new_1 = ((df['old_label'] == 0) & (df['new_label'] == 1)).sum()
    
    print(f"   Old=1 → New=0 (más restrictivo): {old_1_new_0}")
    print(f"   Old=0 → New=1 (más permisivo):  {old_0_new_1}")
    
    # Análisis por tipo de vulnerabilidad
    print(f"\n🏷️  CAMBIOS POR TIPO DE VULNERABILIDAD:")
    
    tipo_changes = df[df['discrepancia']].groupby('tipo').size().sort_values(ascending=False)
    
    for tipo, count in tipo_changes.head(10).items():
        tipo_df = df[df['tipo'] == tipo]
        old_pos_tipo = (tipo_df['old_label'] == 1).sum()
        new_pos_tipo = (tipo_df['new_label'] == 1).sum()
        
        print(f"   {tipo:40s}: {count:3d} cambios")
        print(f"      Old: {old_pos_tipo:3d}/{len(tipo_df):3d} → New: {new_pos_tipo:3d}/{len(tipo_df):3d}")
    
    # CVEs más afectados por el cambio
    print(f"\n🎯 CASOS MÁS INTERESANTES (discrepancias con CVSS alto):")
    
    interesting = df[df['discrepancia'] & (df['cvss_score'] >= 7.0)].sort_values('cvss_score', ascending=False).head(10)
    
    for idx, row in interesting.iterrows():
        direction = "➡️" if row['old_label'] < row['new_label'] else "⬅️"
        print(f"   {direction} {row['cve_id']}: {row['old_label']}→{row['new_label']} | "
              f"CVSS={row['cvss_score']:.1f} | {row['tipo']}")
    
    # Análisis de DoS específico
    dos_df = df[df['tipo'] == 'Denegación de servicio']
    if len(dos_df) > 0:
        dos_old = (dos_df['old_label'] == 1).sum()
        dos_new = (dos_df['new_label'] == 1).sum()
        
        print(f"\n🔍 ANÁLISIS ESPECÍFICO: Denegación de Servicio")
        print(f"   Total DoS: {len(dos_df)}")
        print(f"   Método original marcó como explotables: {dos_old} ({dos_old/len(dos_df)*100:.1f}%)")
        print(f"   Smart labeling marcó como explotables:  {dos_new} ({dos_new/len(dos_df)*100:.1f}%)")
        print(f"   Reducción: {dos_old - dos_new} CVEs ({(dos_old-dos_new)/len(dos_df)*100:.1f}%)")
    
    # "Sin clasificar"
    sin_clas_df = df[df['tipo'] == 'Sin clasificar']
    if len(sin_clas_df) > 0:
        sc_old = (sin_clas_df['old_label'] == 1).sum()
        sc_new = (sin_clas_df['new_label'] == 1).sum()
        
        print(f"\n🔍 ANÁLISIS ESPECÍFICO: Sin clasificar")
        print(f"   Total Sin clasificar: {len(sin_clas_df)}")
        print(f"   Método original marcó como explotables: {sc_old} ({sc_old/len(sin_clas_df)*100:.1f}%)")
        print(f"   Smart labeling marcó como explotables:  {sc_new} ({sc_new/len(sin_clas_df)*100:.1f}%)")


def generate_report(df: pd.DataFrame, output_dir: str = "/app/ia/reports"):
    """
    Genera reportes en CSV y texto.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n💾 GENERANDO REPORTES...")
    
    # 1. Reporte completo
    csv_path = os.path.join(output_dir, "label_comparison_full.csv")
    df.to_csv(csv_path, index=False)
    print(f"   ✅ {csv_path}")
    
    # 2. Solo discrepancias
    discrepancias_df = df[df['discrepancia']]
    disc_path = os.path.join(output_dir, "label_discrepancias.csv")
    discrepancias_df.to_csv(disc_path, index=False)
    print(f"   ✅ {disc_path} ({len(discrepancias_df)} CVEs)")
    
    # 3. Resumen por tipo
    summary = df.groupby('tipo').agg({
        'old_label': 'sum',
        'new_label': 'sum',
        'cve_id': 'count'
    }).rename(columns={'cve_id': 'total'})
    summary['old_pct'] = summary['old_label'] / summary['total'] * 100
    summary['new_pct'] = summary['new_label'] / summary['total'] * 100
    summary['diff'] = summary['new_label'] - summary['old_label']
    
    summary_path = os.path.join(output_dir, "label_summary_by_type.csv")
    summary.to_csv(summary_path)
    print(f"   ✅ {summary_path}")
    
    # 4. Casos para revisión manual
    for_review = df[df['discrepancia'] & (df['cvss_score'] >= 7.0)].sort_values('cvss_score', ascending=False)
    review_path = os.path.join(output_dir, "cases_for_review.csv")
    for_review.to_csv(review_path, index=False)
    print(f"   ✅ {review_path} ({len(for_review)} CVEs de alta severidad)")
    
    print(f"\n📁 Todos los reportes guardados en: {output_dir}/")


def interactive_review(df: pd.DataFrame):
    """
    Modo interactivo para revisar casos específicos.
    """
    print("\n" + "="*70)
    print("  🔍 MODO INTERACTIVO - Revisión de Casos")
    print("="*70)
    print("\nComandos:")
    print("  'next' - Siguiente CVE con discrepancia")
    print("  'dos'  - Siguiente DoS con discrepancia")
    print("  'exit' - Salir")
    print("="*70 + "\n")
    
    discrepancias = df[df['discrepancia']].reset_index(drop=True)
    idx = 0
    
    while idx < len(discrepancias):
        row = discrepancias.iloc[idx]
        
        print(f"\n{'='*70}")
        print(f"CVE {idx+1}/{len(discrepancias)}: {row['cve_id']}")
        print(f"{'='*70}")
        print(f"CVSS: {row['cvss_score']:.1f} | Tipo: {row['tipo']}")
        print(f"Original: {row['old_label']} | Smart: {row['new_label']}")
        print(f"Smart Score: {row['smart_score']:.3f} (threshold: {row['threshold']:.3f})")
        
        cmd = input("\nComando [next/dos/exit]: ").strip().lower()
        
        if cmd == 'exit':
            break
        elif cmd == 'dos':
            # Buscar siguiente DoS
            dos_idx = discrepancias[idx+1:][discrepancias[idx+1:]['tipo'] == 'Denegación de servicio'].index
            if len(dos_idx) > 0:
                idx = dos_idx[0]
            else:
                print("No hay más DoS con discrepancias")
                idx += 1
        else:  # next o cualquier otra cosa
            idx += 1


def main():
    """
    Función principal.
    """
    print("\n" + "="*70)
    print("  🏷️  LABEL VALIDATOR - Comparación de Métodos")
    print("="*70 + "\n")
    
    # Cargar datos
    print("🔄 Cargando CVEs desde MongoDB...")
    cves = load_cves()
    print(f"✅ {len(cves)} CVEs cargados\n")
    
    # Comparar métodos
    df = compare_methods(cves)
    
    # Analizar resultados
    analyze_comparison(df)
    
    # Generar reportes
    generate_report(df)
    
    # Modo interactivo (opcional)
    if '--interactive' in sys.argv or '-i' in sys.argv:
        interactive_review(df)
    
    print("\n" + "="*70)
    print("  ✅ ANÁLISIS COMPLETADO")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()