"""
Sistema de telemetría para rastrear métricas de ingesta en tiempo real.
Captura estadísticas detalladas de cada fase del pipeline.
"""
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from collections import defaultdict
import json


@dataclass
class IngestMetrics:
    """Métricas completas de un proceso de ingesta."""
    
    # ===== MÉTRICAS GENERALES =====
    total_procesados: int = 0
    inicio: float = field(default_factory=time.time)
    fin: Optional[float] = None
    
    # ===== VALIDACIÓN INICIAL =====
    descartados_sin_cve_obj: int = 0
    descartados_sin_cve_id: int = 0
    descartados_sin_descripcion: int = 0
    descartados_sin_fecha_publicacion: int = 0
    total_descartados: int = 0
    
    # ===== CLASIFICACIÓN (Tipo) =====
    clasificados_fase1_keywords: int = 0
    clasificados_fase2_cwe: int = 0
    clasificados_fase3_impacto: int = 0
    sin_clasificar_final: int = 0
    
    # Distribución de tipos detectados
    tipos_distribucion: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # ===== ENRIQUECIMIENTO MITRE =====
    mitre_intentados: int = 0
    mitre_exitosos: int = 0
    mitre_fallidos: int = 0
    mitre_timeouts: int = 0
    mitre_sin_datos: int = 0
    
    # ===== EXTRACCIÓN DE VERSIONES =====
    con_versiones_extraidas: int = 0
    sin_versiones_extraidas: int = 0
    versiones_config_vacio: int = 0
    versiones_parsing_error: int = 0
    
    # Estadísticas de versiones
    total_versiones_extraidas: int = 0
    max_versiones_por_cve: int = 0
    
    # ===== COMPONENTE AFECTADO =====
    componente_desde_cpe: int = 0
    componente_desde_descripcion: int = 0
    componente_faltante: int = 0
    componente_parsing_error: int = 0
    
    # ===== CAMPOS ENRIQUECIDOS =====
    con_descripcion_tecnica: int = 0
    con_referencias_mitre: int = 0
    con_fecha_registro_mitre: int = 0
    con_remediacion: int = 0
    
    # ===== OPERACIONES DB =====
    nuevos_insertados: int = 0
    actualizados: int = 0
    sin_cambios: int = 0
    errores_db: int = 0
    
    # Razones de actualización
    actualizados_por_fecha_nvd: int = 0
    actualizados_por_campos_enriquecidos: int = 0
    actualizados_por_versiones_diff: int = 0
    
    # ===== CALIDAD DE DATOS =====
    cvss_score_ausente: int = 0
    cvss_vector_ausente: int = 0
    etiquetas_vacias: int = 0
    keywords_vacias: int = 0
    
    # ===== ERRORES Y WARNINGS =====
    errores_por_tipo: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    warnings_por_campo: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # ===== EJEMPLOS PARA DEBUG =====
    ejemplos_sin_clasificar: List[str] = field(default_factory=list)
    ejemplos_sin_versiones: List[str] = field(default_factory=list)
    ejemplos_sin_componente: List[str] = field(default_factory=list)
    ejemplos_mitre_fallidos: List[str] = field(default_factory=list)
    
    MAX_EJEMPLOS = 10  # Limitar para no consumir memoria

    def registrar_descarte(self, razon: str, cve_id: str = None):
        """Registra un CVE descartado con su razón."""
        self.total_descartados += 1
        
        if razon == "sin_cve_obj":
            self.descartados_sin_cve_obj += 1
        elif razon == "sin_cve_id":
            self.descartados_sin_cve_id += 1
        elif razon == "sin_descripcion":
            self.descartados_sin_descripcion += 1
        elif razon == "sin_fecha":
            self.descartados_sin_fecha_publicacion += 1
    
    def registrar_clasificacion(self, tipo: str, fase: int):
        """Registra el resultado de clasificación."""
        self.tipos_distribucion[tipo] += 1
        
        if fase == 1:
            self.clasificados_fase1_keywords += 1
        elif fase == 2:
            self.clasificados_fase2_cwe += 1
        elif fase == 3:
            self.clasificados_fase3_impacto += 1
        
        if tipo == "Sin clasificar":
            self.sin_clasificar_final += 1
    
    def registrar_mitre(self, resultado: str, cve_id: str = None):
        """Registra resultado de enriquecimiento MITRE."""
        self.mitre_intentados += 1
        
        if resultado == "exitoso":
            self.mitre_exitosos += 1
        elif resultado == "fallido":
            self.mitre_fallidos += 1
            if cve_id and len(self.ejemplos_mitre_fallidos) < self.MAX_EJEMPLOS:
                self.ejemplos_mitre_fallidos.append(cve_id)
        elif resultado == "timeout":
            self.mitre_timeouts += 1
        elif resultado == "sin_datos":
            self.mitre_sin_datos += 1
    
    def registrar_versiones(self, num_versiones: int, cve_id: str = None):
        """Registra extracción de versiones."""
        if num_versiones > 0:
            self.con_versiones_extraidas += 1
            self.total_versiones_extraidas += num_versiones
            self.max_versiones_por_cve = max(self.max_versiones_por_cve, num_versiones)
        else:
            self.sin_versiones_extraidas += 1
            if cve_id and len(self.ejemplos_sin_versiones) < self.MAX_EJEMPLOS:
                self.ejemplos_sin_versiones.append(cve_id)
    
    def registrar_componente(self, fuente: str, cve_id: str = None):
        """Registra extracción de componente."""
        if fuente == "cpe":
            self.componente_desde_cpe += 1
        elif fuente == "descripcion":
            self.componente_desde_descripcion += 1
        elif fuente == "faltante":
            self.componente_faltante += 1
            if cve_id and len(self.ejemplos_sin_componente) < self.MAX_EJEMPLOS:
                self.ejemplos_sin_componente.append(cve_id)
        elif fuente == "error":
            self.componente_parsing_error += 1
    
    def registrar_operacion_db(self, tipo_op: str, razon: str = None):
        """Registra operaciones de base de datos."""
        if tipo_op == "nuevo":
            self.nuevos_insertados += 1
        elif tipo_op == "actualizado":
            self.actualizados += 1
            if razon == "fecha_nvd":
                self.actualizados_por_fecha_nvd += 1
            elif razon == "campos_enriquecidos":
                self.actualizados_por_campos_enriquecidos += 1
            elif razon == "versiones_diff":
                self.actualizados_por_versiones_diff += 1
        elif tipo_op == "sin_cambios":
            self.sin_cambios += 1
        elif tipo_op == "error":
            self.errores_db += 1
    
    def registrar_warning(self, campo: str, mensaje: str = None):
        """Registra un warning en un campo específico."""
        self.warnings_por_campo[campo] += 1
    
    def registrar_error(self, tipo_error: str):
        """Registra un error por tipo."""
        self.errores_por_tipo[tipo_error] += 1
    
    def finalizar(self):
        """Marca el fin del proceso."""
        self.fin = time.time()
    
    def duracion_segundos(self) -> float:
        """Retorna la duración del proceso en segundos."""
        if self.fin:
            return self.fin - self.inicio
        return time.time() - self.inicio
    
    def tasa_procesamiento(self) -> float:
        """CVEs procesados por segundo."""
        duracion = self.duracion_segundos()
        if duracion > 0:
            return self.total_procesados / duracion
        return 0.0
    
    def porcentaje_descarte(self) -> float:
        """Porcentaje de CVEs descartados."""
        if self.total_procesados > 0:
            return (self.total_descartados / self.total_procesados) * 100
        return 0.0
    
    def porcentaje_clasificados(self) -> float:
        """Porcentaje de CVEs clasificados correctamente."""
        total_validos = self.total_procesados - self.total_descartados
        if total_validos > 0:
            clasificados = total_validos - self.sin_clasificar_final
            return (clasificados / total_validos) * 100
        return 0.0
    
    def porcentaje_con_versiones(self) -> float:
        """Porcentaje de CVEs con versiones extraídas."""
        total_validos = self.total_procesados - self.total_descartados
        if total_validos > 0:
            return (self.con_versiones_extraidas / total_validos) * 100
        return 0.0
    
    def porcentaje_enriquecidos_mitre(self) -> float:
        """Porcentaje de enriquecimientos MITRE exitosos."""
        if self.mitre_intentados > 0:
            return (self.mitre_exitosos / self.mitre_intentados) * 100
        return 0.0
    
    def promedio_versiones(self) -> float:
        """Promedio de versiones extraídas por CVE."""
        if self.con_versiones_extraidas > 0:
            return self.total_versiones_extraidas / self.con_versiones_extraidas
        return 0.0
    
    def to_dict(self) -> dict:
        """Convierte las métricas a diccionario."""
        data = asdict(self)
        
        # Agregar métricas calculadas
        data['metricas_calculadas'] = {
            'duracion_segundos': round(self.duracion_segundos(), 2),
            'tasa_procesamiento_por_seg': round(self.tasa_procesamiento(), 2),
            'porcentaje_descarte': round(self.porcentaje_descarte(), 2),
            'porcentaje_clasificados': round(self.porcentaje_clasificados(), 2),
            'porcentaje_con_versiones': round(self.porcentaje_con_versiones(), 2),
            'porcentaje_enriquecidos_mitre': round(self.porcentaje_enriquecidos_mitre(), 2),
            'promedio_versiones_por_cve': round(self.promedio_versiones(), 2),
        }
        
        return data
    
    def to_json(self, filepath: str):
        """Exporta las métricas a JSON."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    def resumen_consola(self) -> str:
        """Genera un resumen formateado para consola."""
        lines = [
            "\n" + "="*80,
            "📊 RESUMEN DE TELEMETRÍA - INGESTA CVE",
            "="*80,
            "",
            f"⏱️  Duración: {self.duracion_segundos():.2f}s",
            f"⚡ Tasa: {self.tasa_procesamiento():.2f} CVEs/segundo",
            f"📥 Total procesados: {self.total_procesados}",
            "",
            "--- VALIDACIÓN ---",
            f"✅ Válidos: {self.total_procesados - self.total_descartados}",
            f"❌ Descartados: {self.total_descartados} ({self.porcentaje_descarte():.1f}%)",
            f"   └─ Sin CVE obj: {self.descartados_sin_cve_obj}",
            f"   └─ Sin CVE ID: {self.descartados_sin_cve_id}",
            f"   └─ Sin descripción: {self.descartados_sin_descripcion}",
            f"   └─ Sin fecha: {self.descartados_sin_fecha_publicacion}",
            "",
            "--- CLASIFICACIÓN (Tipo) ---",
            f"🎯 Clasificados: {self.porcentaje_clasificados():.1f}%",
            f"   └─ Fase 1 (keywords): {self.clasificados_fase1_keywords}",
            f"   └─ Fase 2 (CWE): {self.clasificados_fase2_cwe}",
            f"   └─ Fase 3 (impacto): {self.clasificados_fase3_impacto}",
            f"🤷 Sin clasificar: {self.sin_clasificar_final}",
        ]
        
        if self.tipos_distribucion:
            lines.append("\n📊 Distribución de tipos (top 5):")
            top_tipos = sorted(self.tipos_distribucion.items(), key=lambda x: x[1], reverse=True)[:5]
            for tipo, count in top_tipos:
                lines.append(f"   └─ {tipo}: {count}")
        
        lines.extend([
            "",
            "--- ENRIQUECIMIENTO MITRE ---",
            f"🌐 Intentados: {self.mitre_intentados}",
            f"✅ Exitosos: {self.mitre_exitosos} ({self.porcentaje_enriquecidos_mitre():.1f}%)",
            f"❌ Fallidos: {self.mitre_fallidos}",
            f"⏱️  Timeouts: {self.mitre_timeouts}",
            f"📭 Sin datos: {self.mitre_sin_datos}",
            "",
            "--- VERSIONES AFECTADAS ---",
            f"✅ Con versiones: {self.con_versiones_extraidas} ({self.porcentaje_con_versiones():.1f}%)",
            f"❌ Sin versiones: {self.sin_versiones_extraidas}",
            f"📊 Total extraídas: {self.total_versiones_extraidas}",
            f"📈 Promedio: {self.promedio_versiones():.2f} versiones/CVE",
            f"🔝 Máximo: {self.max_versiones_por_cve} versiones en un CVE",
            f"⚠️  Config vacío: {self.versiones_config_vacio}",
            f"❌ Parsing error: {self.versiones_parsing_error}",
            "",
            "--- COMPONENTE AFECTADO ---",
            f"🏷️  Desde CPE: {self.componente_desde_cpe}",
            f"📝 Desde descripción: {self.componente_desde_descripcion}",
            f"❌ Faltante: {self.componente_faltante}",
            f"⚠️  Parsing error: {self.componente_parsing_error}",
            "",
            "--- OPERACIONES BD ---",
            f"🆕 Nuevos: {self.nuevos_insertados}",
            f"🔄 Actualizados: {self.actualizados}",
            f"   └─ Por fecha NVD: {self.actualizados_por_fecha_nvd}",
            f"   └─ Por enriquecimiento: {self.actualizados_por_campos_enriquecidos}",
            f"   └─ Por diff versiones: {self.actualizados_por_versiones_diff}",
            f"⏸️  Sin cambios: {self.sin_cambios}",
            f"❌ Errores DB: {self.errores_db}",
            "",
            "--- CALIDAD DE DATOS ---",
            f"📊 CVSS score ausente: {self.cvss_score_ausente}",
            f"📊 CVSS vector ausente: {self.cvss_vector_ausente}",
            f"🏷️  Etiquetas vacías: {self.etiquetas_vacias}",
            f"🔑 Keywords vacías: {self.keywords_vacias}",
        ])
        
        if self.ejemplos_sin_clasificar:
            lines.append(f"\n🔍 Ejemplos sin clasificar (primeros {len(self.ejemplos_sin_clasificar)}):")
            for cve_id in self.ejemplos_sin_clasificar:
                lines.append(f"   └─ {cve_id}")
        
        if self.ejemplos_sin_versiones:
            lines.append(f"\n🔍 Ejemplos sin versiones (primeros {len(self.ejemplos_sin_versiones)}):")
            for cve_id in self.ejemplos_sin_versiones:
                lines.append(f"   └─ {cve_id}")
        
        if self.ejemplos_sin_componente:
            lines.append(f"\n🔍 Ejemplos sin componente (primeros {len(self.ejemplos_sin_componente)}):")
            for cve_id in self.ejemplos_sin_componente:
                lines.append(f"   └─ {cve_id}")
        
        lines.append("\n" + "="*80 + "\n")
        
        return "\n".join(lines)


# Singleton global para las métricas actuales
_current_metrics: Optional[IngestMetrics] = None


def get_metrics() -> IngestMetrics:
    """Obtiene las métricas actuales (patrón singleton)."""
    global _current_metrics
    if _current_metrics is None:
        _current_metrics = IngestMetrics()
    return _current_metrics


def reset_metrics():
    """Resetea las métricas para un nuevo proceso."""
    global _current_metrics
    _current_metrics = IngestMetrics()


def print_metrics():
    """Imprime el resumen de métricas en consola."""
    metrics = get_metrics()
    print(metrics.resumen_consola())