import time
import logging

from .telemetry import get_metrics, get_audit_tracker

from ..ingest.kev.kev_loader import load_kev_dataset
from ..ingest.tiempo.fechas import parse_fecha_publicacion_dt
from ..ingest.cvss.cvss_base import obtener_cvss
from ..ingest.cvss.riesgo import riesgo_from_score
from ..ingest.cvss.dificultad import dificultad_from_vector
from ..ingest.cvss.impacto import extraer_impacto
from ..ingest.protocols.mappings import MAP_PROTO_TO_PORTS, MAP_PROTO_TO_SERVICE, inferir_servicio_posible, inferir_puertos
from ..ingest.protocols.detect_protocols import _PROTO_KWS, extract_protocols, inferir_protocolo_principal
from ..ingest.protocols.interfaces import _IFACE_KWS, extract_interfaces
from ..ingest.infraestructura.clasificacion_5g import clasificar_infra
from ..ingest.cpe.componentes import extraer_componente_afectado
from ..ingest.versiones.extract_versiones import extraer_versiones_afectadas
from ..ingest.etiquetas.etiquetas import extraer_etiquetas
from ..ingest.tipos.infer_tipo import inferir_tipo
from ..ingest.tipos.cwe_map import CWE_TO_TIPO, inferir_tipo_por_cwe
from ..ingest.tipos.impacto_inferencia import inferir_tipo_por_impacto
from ..ingest.keywords.keyword_index import build_keyword_index
from ..ingest.remediacion.remediacion_builder import _build_remediacion

logger = logging.getLogger("ingest-nvd")

def normalizar_cve(obj):
    """
    Normaliza una entrada NVD con telemetría completa integrada.
    TODAS las operaciones críticas registran métricas y auditoría.
    """
    
    # ========================================================================
    # MÉTRICAS Y AUDITORÍA
    # ========================================================================
    metrics = get_metrics()
    audit_tracker = get_audit_tracker()
    
    metrics.total_procesados += 1
    
    # ========================================================================
    # VALIDACIÓN INICIAL
    # ========================================================================
    
    if not obj:
        metrics.registrar_descarte("sin_cve_obj")
        return None

    # Normalizar estructura
    if "cve" in obj and isinstance(obj["cve"], dict):
        item = obj
    elif "configurations" in obj and "id" in obj:
        item = {"cve": obj, "configurations": obj.get("configurations")}
    elif isinstance(obj, dict) and obj.get("id"):
        item = {"cve": obj, "configurations": {}}
    else:
        metrics.registrar_descarte("sin_cve_obj")
        return None

    cve = item["cve"]
    cve_id = cve.get("id")
    
    if not cve_id:
        metrics.registrar_descarte("sin_cve_id")
        return None
    
    # Crear audit para este CVE
    audit = audit_tracker.crear_audit(cve_id)

    # Descripción
    descripcion = ""
    for d in (cve.get("descriptions") or []):
        val = d.get("value")
        if val:
            descripcion = val
            break
    
    if not descripcion:
        metrics.registrar_descarte("sin_descripcion", cve_id)
        return None

    # Fecha publicación
    published = cve.get("published", "") or ""
    if not published:
        metrics.registrar_descarte("sin_fecha", cve_id)
        return None

    # ========================================================================
    # CVSS
    # ========================================================================
    
    cvss_data = obtener_cvss(cve.get("metrics", {}) or {})
    score = float(cvss_data.get("baseScore", 0.0) or 0.0)
    vector = cvss_data.get("vectorString", "") or ""
    
    if score == 0.0:
        metrics.cvss_score_ausente += 1
        audit.agregar_warning("CVSS score ausente o 0.0")
    
    if not vector or vector == "N/A":
        metrics.cvss_vector_ausente += 1
        audit.agregar_warning("CVSS vector ausente")

    # ========================================================================
    # CLASIFICACIÓN (TIPO) - CON TELEMETRÍA DE 3 FASES
    # ========================================================================
    
    # FASE 1: Keywords
    tipo = inferir_tipo(descripcion)
    
    if tipo != "Sin clasificar":
        metrics.registrar_clasificacion(tipo, fase=1)
        audit.set_fuente_campo("tipo", "keywords")
    else:
        # FASE 2: CWE
        tipo_cwe = inferir_tipo_por_cwe(cve)
        if tipo_cwe:
            tipo = tipo_cwe
            metrics.registrar_clasificacion(tipo, fase=2)
            audit.agregar_fallback("tipo", "CWE")
            audit.set_fuente_campo("tipo", "cwe")
        else:
            # FASE 3: Impacto CVSS
            tipo_impacto = inferir_tipo_por_impacto(cvss_data)
            if tipo_impacto:
                tipo = tipo_impacto
                metrics.registrar_clasificacion(tipo, fase=3)
                audit.agregar_fallback("tipo", "impacto_cvss")
                audit.set_fuente_campo("tipo", "impacto")
            else:
                # Sin clasificar
                metrics.registrar_clasificacion("Sin clasificar", fase=0)
                audit.agregar_campo_vacio("tipo")
                
                # Guardar ejemplo para debugging
                if len(metrics.ejemplos_sin_clasificar) < metrics.MAX_EJEMPLOS:
                    metrics.ejemplos_sin_clasificar.append(cve_id)

    # ========================================================================
    # ETIQUETAS, IMPACTO, INFRAESTRUCTURA
    # ========================================================================
    
    etiquetas = extraer_etiquetas(descripcion)
    if not etiquetas:
        metrics.etiquetas_vacias += 1
        audit.agregar_campo_vacio("etiquetas")
    
    impacto = extraer_impacto(cvss_data)
    infra = clasificar_infra(descripcion)

    # ========================================================================
    # ENRIQUECIMIENTO EXTERNO - MITRE
    # ========================================================================
    
    try:
        from services.ingest.enrichment.externals import enriquecer_desde_mitre as _enriq_mitre_ext
        enriquecer_desde_mitre = _enriq_mitre_ext
    except Exception:
        def enriquecer_desde_mitre(_id: str) -> dict:
            return {}

    extra_mitre = {}
    try:
        extra_mitre = enriquecer_desde_mitre(cve_id) or {}
        
        # Determinar resultado del enriquecimiento
        tiene_desc = bool(extra_mitre.get("descripcion_tecnica", "").strip())
        tiene_refs = bool(extra_mitre.get("referencias_mitre", []))
        tiene_fecha = bool(extra_mitre.get("fecha_registro_mitre"))
        
        if tiene_desc or tiene_refs or tiene_fecha:
            metrics.registrar_mitre("exitoso", cve_id)
            audit.set_enriquecimiento("mitre", "exitoso")
            
            if tiene_desc:
                metrics.con_descripcion_tecnica += 1
            if tiene_refs:
                metrics.con_referencias_mitre += 1
            if tiene_fecha:
                metrics.con_fecha_registro_mitre += 1
        else:
            metrics.registrar_mitre("sin_datos", cve_id)
            audit.set_enriquecimiento("mitre", "sin_datos")
            audit.agregar_warning("MITRE no retornó datos útiles")
            
    except TimeoutError:
        metrics.registrar_mitre("timeout", cve_id)
        audit.set_enriquecimiento("mitre", "timeout")
        audit.agregar_error("Timeout al consultar MITRE")
        extra_mitre = {}
    except Exception as e:
        metrics.registrar_mitre("fallido", cve_id)
        audit.set_enriquecimiento("mitre", "fallido")
        audit.agregar_error(f"Error MITRE: {str(e)[:100]}")
        logger.warning(f"⚠️ Error enriqueciendo {cve_id} desde MITRE: {e}")
        extra_mitre = {}

    referencias = list(dict.fromkeys(extra_mitre.get("referencias_mitre", []) or []))

    # ========================================================================
    # VERSIONES AFECTADAS - CON TELEMETRÍA DETALLADA
    # ========================================================================
    
    versiones = []
    try:
        # Verificar si configurations está vacío ANTES de parsear
        configs = item.get("configurations")
        if not configs or (isinstance(configs, dict) and not configs.get("nodes")) or \
           (isinstance(configs, list) and not configs):
            metrics.versiones_config_vacio += 1
            audit.agregar_warning("Configurations vacío en NVD")
        
        versiones = extraer_versiones_afectadas(item) or []
        
        num_versiones = len(versiones)
        metrics.registrar_versiones(num_versiones, cve_id)
        
        if num_versiones > 0:
            audit.set_fuente_campo("versiones_afectadas", "configurations")
        else:
            audit.agregar_campo_vacio("versiones_afectadas")
            
    except Exception as e:
        metrics.versiones_parsing_error += 1
        metrics.registrar_versiones(0, cve_id)
        audit.agregar_error(f"Error parsing versiones: {str(e)[:100]}")
        logger.warning(f"⚠️ Error extrayendo versiones para {cve_id}: {e}")
        versiones = []

    # ========================================================================
    # COMPONENTE AFECTADO - CON TELEMETRÍA DE FUENTES
    # ========================================================================
    
    componente = None
    fuente_comp = "NONE"
    
    try:
        componente, fuente_comp = extraer_componente_afectado(item)
        
        if componente:
            if fuente_comp == "CPE":
                metrics.registrar_componente("cpe", cve_id)
                audit.set_fuente_campo("componente_afectado", "CPE")
            elif fuente_comp == "KEV":
                metrics.registrar_componente("cpe", cve_id)  # KEV usa CPEs
                audit.set_fuente_campo("componente_afectado", "KEV")
            elif fuente_comp == "REFERENCES":
                metrics.registrar_componente("descripcion", cve_id)
                audit.set_fuente_campo("componente_afectado", "REFERENCES")
                audit.agregar_fallback("componente_afectado", "referencias")
            elif fuente_comp == "DESCRIPTION":
                metrics.registrar_componente("descripcion", cve_id)
                audit.set_fuente_campo("componente_afectado", "DESCRIPTION")
                audit.agregar_fallback("componente_afectado", "descripcion")
        else:
            metrics.registrar_componente("faltante", cve_id)
            audit.agregar_campo_vacio("componente_afectado")
            
    except Exception as e:
        metrics.componente_parsing_error += 1
        metrics.registrar_componente("error", cve_id)
        audit.agregar_error(f"Error extrayendo componente: {str(e)[:100]}")
        logger.warning(f"⚠️ Error extrayendo componente para {cve_id}: {e}")
        componente = None
        fuente_comp = "ERROR"

    # ========================================================================
    # OTROS CAMPOS
    # ========================================================================
    
    fecha_dt = parse_fecha_publicacion_dt(published)
    riesgo = riesgo_from_score(score)
    dif = dificultad_from_vector(vector)
    protos = extract_protocols(descripcion)
    ifaces = extract_interfaces(descripcion)
    protocolo_principal = inferir_protocolo_principal(protos)
    servicio_posible = inferir_servicio_posible(protocolo_principal)
    puertos_asociados = inferir_puertos(protocolo_principal)
    nombre = descripcion[:80] + "..." if len(descripcion) > 80 else descripcion

    keywords_index = build_keyword_index(
        cve_id=cve_id,
        nombre=nombre,
        descripcion=descripcion,
        tipo=tipo,
        etiquetas=etiquetas,
        protocolo=protocolo_principal,
        servicio=servicio_posible,
        puertos=puertos_asociados
    )
    
    if not keywords_index:
        metrics.keywords_vacias += 1
        audit.agregar_warning("Keywords vacías")

    # ========================================================================
    # REMEDIACIÓN
    # ========================================================================
    
    remediacion_txt = ""
    try:
        remediacion_txt = _build_remediacion(
            cve_id=cve_id,
            cve=cve,
            descripcion=descripcion,
            versiones=versiones,
            etiquetas=etiquetas,
            protos=protos,
            extra_mitre=extra_mitre,
        )
        
        if remediacion_txt:
            metrics.con_remediacion += 1
        else:
            audit.agregar_campo_vacio("recomendaciones_remediacion")
            
    except Exception as e:
        audit.agregar_error(f"Error generando remediación: {str(e)[:100]}")
        logger.warning(f"⚠️ Error generando remediación para {cve_id}: {e}")
        remediacion_txt = ""

    # ========================================================================
    # DOCUMENTO FINAL
    # ========================================================================
    
    doc = {
        "cve_id": cve_id,
        "nombre": nombre,
        "componente_afectado": componente or None,
        "tipo": tipo,
        "descripcion_general": descripcion,
        "descripcion_tecnica": extra_mitre.get("descripcion_tecnica", ""),
        "etiquetas": etiquetas,
        "infraestructura_5g_afectada": infra,
        "versiones_afectadas": versiones,
        "protocolo_principal": protocolo_principal,
        "servicio_posible": servicio_posible,
        "puertos_asociados": puertos_asociados,
        "palabras_clave_normalizadas": keywords_index,
        "recomendaciones_remediacion": remediacion_txt,
        "referencias_mitre": referencias,
        "cvssv3": {"score": score, "vector": vector or "N/A"},
        "riesgo": riesgo,
        "dificultad_explotacion": dif,
        "impacto_potencial": {
            "confidencialidad": impacto.get("confidencialidad", "Desconocida"),
            "integridad": impacto.get("integridad", "Desconocida"),
            "disponibilidad": impacto.get("disponibilidad", "Desconocida"),
        },
        "fecha_publicacion": published,
        "fecha_publicacion_dt": fecha_dt,
        "fuente": "NVD",
        "tipo_fuente": "Oficial",
        "fecha_ingesta": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fecha_registro_mitre": extra_mitre.get("fecha_registro_mitre"),
        "fecha_actualizacion": cve.get("lastModified", "") or "",
        "_metadata": {
            "fuente_componente": fuente_comp,
            "metodo_clasificacion": audit.fuentes_campos.get("tipo", "none"),
        },
        # NUEVO: Incluir auditoría en el documento
        "_quality_audit": audit.to_dict()
    }
    
    return doc