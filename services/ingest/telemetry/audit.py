"""
Sistema de auditoría por CVE individual.
Registra problemas, warnings y metadatos de calidad para cada documento.
"""
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field


@dataclass
class CVEAudit:
    """Registro de auditoría para un CVE individual."""
    
    cve_id: str
    
    # Campos que están vacíos/faltantes
    campos_vacios: List[str] = field(default_factory=list)
    
    # Campos obtenidos por fallback
    campos_fallback: Dict[str, str] = field(default_factory=dict)
    
    # Warnings de parsing
    parsing_warnings: List[str] = field(default_factory=list)
    
    # Errores (no críticos, procesamiento continuó)
    errores_no_criticos: List[str] = field(default_factory=list)
    
    # Status de enriquecimiento externo
    enriquecimiento_status: Dict[str, str] = field(default_factory=dict)
    
    # Fuentes de datos para cada campo
    fuentes_campos: Dict[str, str] = field(default_factory=dict)
    
    # Score de calidad (0-100)
    quality_score: Optional[int] = None
    
    def agregar_campo_vacio(self, campo: str):
        """Registra un campo que quedó vacío."""
        if campo not in self.campos_vacios:
            self.campos_vacios.append(campo)
    
    def agregar_fallback(self, campo: str, metodo: str):
        """Registra que un campo se obtuvo por fallback."""
        self.campos_fallback[campo] = metodo
    
    def agregar_warning(self, mensaje: str):
        """Agrega un warning de parsing."""
        if mensaje not in self.parsing_warnings:
            self.parsing_warnings.append(mensaje)
    
    def agregar_error(self, mensaje: str):
        """Agrega un error no crítico."""
        if mensaje not in self.errores_no_criticos:
            self.errores_no_criticos.append(mensaje)
    
    def set_enriquecimiento(self, fuente: str, status: str):
        """Registra el status de un enriquecimiento externo."""
        self.enriquecimiento_status[fuente] = status
    
    def set_fuente_campo(self, campo: str, fuente: str):
        """Registra la fuente de un campo."""
        self.fuentes_campos[campo] = fuente
    
    def calcular_quality_score(self, campos_criticos: Set[str]) -> int:
        """
        Calcula un score de calidad 0-100 basado en:
        - Campos críticos presentes (60%)
        - Ausencia de warnings (20%)
        - Ausencia de errores (10%)
        - Enriquecimientos exitosos (10%)
        """
        score = 0.0
        
        # 1. Campos críticos (60 puntos)
        if campos_criticos:
            campos_presentes = campos_criticos - set(self.campos_vacios)
            score += (len(campos_presentes) / len(campos_criticos)) * 60
        
        # 2. Sin warnings (20 puntos)
        if not self.parsing_warnings:
            score += 20
        elif len(self.parsing_warnings) <= 2:
            score += 10
        
        # 3. Sin errores (10 puntos)
        if not self.errores_no_criticos:
            score += 10
        
        # 4. Enriquecimientos (10 puntos)
        if self.enriquecimiento_status:
            exitosos = sum(1 for s in self.enriquecimiento_status.values() if s == "exitoso")
            total = len(self.enriquecimiento_status)
            score += (exitosos / total) * 10
        
        self.quality_score = int(score)
        return self.quality_score
    
    def to_dict(self) -> dict:
        """Convierte a diccionario para almacenar en MongoDB."""
        return {
            "cve_id": self.cve_id,
            "campos_vacios": self.campos_vacios,
            "campos_fallback": self.campos_fallback,
            "parsing_warnings": self.parsing_warnings,
            "errores_no_criticos": self.errores_no_criticos,
            "enriquecimiento_status": self.enriquecimiento_status,
            "fuentes_campos": self.fuentes_campos,
            "quality_score": self.quality_score,
        }
    
    def tiene_problemas(self) -> bool:
        """Retorna True si hay algún problema de calidad."""
        return bool(
            self.campos_vacios or 
            self.parsing_warnings or 
            self.errores_no_criticos or
            any(s != "exitoso" for s in self.enriquecimiento_status.values())
        )


class AuditTracker:
    """
    Rastreador global de auditorías.
    Mantiene un registro de todos los CVEs procesados.
    """
    
    def __init__(self):
        self.audits: Dict[str, CVEAudit] = {}
        
        # Campos considerados críticos para el score
        self.campos_criticos = {
            "tipo",
            "descripcion_general",
            "cvssv3",
            "riesgo",
            "fecha_publicacion",
            "componente_afectado",
            "versiones_afectadas"
        }
    
    def crear_audit(self, cve_id: str) -> CVEAudit:
        """Crea un nuevo registro de auditoría."""
        audit = CVEAudit(cve_id=cve_id)
        self.audits[cve_id] = audit
        return audit
    
    def get_audit(self, cve_id: str) -> Optional[CVEAudit]:
        """Obtiene un audit existente."""
        return self.audits.get(cve_id)
    
    def get_or_create(self, cve_id: str) -> CVEAudit:
        """Obtiene o crea un audit."""
        if cve_id not in self.audits:
            return self.crear_audit(cve_id)
        return self.audits[cve_id]
    
    def finalizar_audits(self):
        """Calcula los quality scores de todos los audits."""
        for audit in self.audits.values():
            audit.calcular_quality_score(self.campos_criticos)
    
    def get_audits_con_problemas(self) -> List[CVEAudit]:
        """Retorna todos los audits que tienen algún problema."""
        return [a for a in self.audits.values() if a.tiene_problemas()]
    
    def get_audits_por_quality(self, min_score: int = 0, max_score: int = 100) -> List[CVEAudit]:
        """Retorna audits filtrados por rango de quality score."""
        return [
            a for a in self.audits.values() 
            if a.quality_score is not None 
            and min_score <= a.quality_score <= max_score
        ]
    
    def estadisticas_campos_vacios(self) -> Dict[str, int]:
        """Retorna un conteo de cuántas veces falta cada campo."""
        from collections import Counter
        campos = []
        for audit in self.audits.values():
            campos.extend(audit.campos_vacios)
        return dict(Counter(campos))
    
    def estadisticas_warnings(self) -> Dict[str, int]:
        """Retorna un conteo de tipos de warnings."""
        from collections import Counter
        warnings = []
        for audit in self.audits.values():
            warnings.extend(audit.parsing_warnings)
        return dict(Counter(warnings))
    
    def estadisticas_enriquecimiento(self) -> Dict[str, Dict[str, int]]:
        """Retorna estadísticas de enriquecimientos por fuente."""
        from collections import defaultdict, Counter
        stats = defaultdict(list)
        
        for audit in self.audits.values():
            for fuente, status in audit.enriquecimiento_status.items():
                stats[fuente].append(status)
        
        return {
            fuente: dict(Counter(statuses))
            for fuente, statuses in stats.items()
        }
    
    def promedio_quality_score(self) -> float:
        """Calcula el promedio de quality scores."""
        scores = [a.quality_score for a in self.audits.values() if a.quality_score is not None]
        if scores:
            return sum(scores) / len(scores)
        return 0.0
    
    def distribucion_quality_scores(self) -> Dict[str, int]:
        """Retorna distribución de scores por rangos."""
        rangos = {
            "0-20": 0,
            "21-40": 0,
            "41-60": 0,
            "61-80": 0,
            "81-100": 0
        }
        
        for audit in self.audits.values():
            if audit.quality_score is not None:
                score = audit.quality_score
                if score <= 20:
                    rangos["0-20"] += 1
                elif score <= 40:
                    rangos["21-40"] += 1
                elif score <= 60:
                    rangos["41-60"] += 1
                elif score <= 80:
                    rangos["61-80"] += 1
                else:
                    rangos["81-100"] += 1
        
        return rangos
    
    def resumen(self) -> str:
        """Genera un resumen de auditoría."""
        lines = [
            "\n" + "="*80,
            "🔍 RESUMEN DE AUDITORÍA - CALIDAD DE DATOS",
            "="*80,
            "",
            f"📊 Total CVEs auditados: {len(self.audits)}",
            f"⚠️  CVEs con problemas: {len(self.get_audits_con_problemas())}",
            f"📈 Quality Score promedio: {self.promedio_quality_score():.1f}/100",
            "",
            "--- DISTRIBUCIÓN DE QUALITY SCORES ---"
        ]
        
        dist = self.distribucion_quality_scores()
        for rango, count in dist.items():
            porcentaje = (count / len(self.audits) * 100) if self.audits else 0
            lines.append(f"{rango}: {count} ({porcentaje:.1f}%)")
        
        lines.append("\n--- CAMPOS VACÍOS MÁS COMUNES (top 10) ---")
        campos_vacios = self.estadisticas_campos_vacios()
        top_campos = sorted(campos_vacios.items(), key=lambda x: x[1], reverse=True)[:10]
        for campo, count in top_campos:
            porcentaje = (count / len(self.audits) * 100) if self.audits else 0
            lines.append(f"{campo}: {count} ({porcentaje:.1f}%)")
        
        lines.append("\n--- WARNINGS MÁS COMUNES (top 5) ---")
        warnings = self.estadisticas_warnings()
        top_warnings = sorted(warnings.items(), key=lambda x: x[1], reverse=True)[:5]
        for warning, count in top_warnings:
            lines.append(f"{warning[:60]}...: {count}")
        
        lines.append("\n--- ENRIQUECIMIENTO EXTERNO ---")
        enriq_stats = self.estadisticas_enriquecimiento()
        for fuente, statuses in enriq_stats.items():
            lines.append(f"{fuente}:")
            for status, count in statuses.items():
                lines.append(f"  └─ {status}: {count}")
        
        lines.append("\n" + "="*80 + "\n")
        
        return "\n".join(lines)


# Singleton global
_current_tracker: Optional[AuditTracker] = None


def get_audit_tracker() -> AuditTracker:
    """Obtiene el tracker de auditoría actual."""
    global _current_tracker
    if _current_tracker is None:
        _current_tracker = AuditTracker()
    return _current_tracker


def reset_audit_tracker():
    """Resetea el tracker de auditoría."""
    global _current_tracker
    _current_tracker = AuditTracker()