# api/utils/db.py
import os
import pymongo
from bson import SON

def _same_key(idx_key, keys_list):
    """Compara patrón de claves de un índice de Mongo con nuestra lista de tuplas."""
    try:
        return list(idx_key.items()) == list(keys_list)
    except Exception:
        return dict(idx_key) == dict(SON(keys_list))

def _upsert_index(col, keys, name=None, **opts):
    """
    Garantiza un índice con 'keys' y 'opts'. Si existe uno equivalente lo reutiliza.
    Si existe un índice con el mismo nombre o mismas claves pero opciones distintas, lo borra y recrea.
    """
    desired = list(keys)  # lista de tuplas, p.ej. [("cve_id", 1)]
    to_drop = []

    for idx in col.list_indexes():
        idx_name = idx["name"]
        idx_key  = idx["key"]
        is_text  = "weights" in idx  # no tocamos los de texto aquí

        if is_text:
            continue

        same_keys = _same_key(idx_key, desired)

        # Compara opciones relevantes (de momento solo 'unique')
        same_opts = True
        if "unique" in opts:
            same_opts = bool(idx.get("unique", False)) == bool(opts.get("unique", False))

        # Ya existe un índice equivalente: nada que hacer
        if same_keys and same_opts:
            return idx_name

        # Conflicto: mismo nombre con spec diferente, o mismas claves con opciones distintas
        if (name and idx_name == name) or (same_keys and not same_opts):
            to_drop.append(idx_name)

    # Elimina conflictivos y crea el bueno
    for n in to_drop:
        try:
            col.drop_index(n)
        except Exception:
            pass

    return col.create_index(desired, name=name, **opts)

def ensure_text_index(col, language="spanish"):
    """
    Crea un índice de texto en (nombre, descripcion_general, descripcion_tecnica)
    en el idioma indicado. Si hay otro índice de texto distinto, lo elimina primero.
    """
    desired_weights = {"nombre": 1, "descripcion_general": 1, "descripcion_tecnica": 1}
    # ¿ya existe uno equivalente?
    for idx in col.list_indexes():
        if "weights" in idx:
            weights_keys = dict(idx["weights"])
            same_weights = set(weights_keys.keys()) == set(desired_weights.keys())
            same_lang = idx.get("default_language", "english") == language
            if same_weights and same_lang:
                return  # correcto, no tocar

    # Elimina cualquier índice de texto previo (diferente)
    for idx in col.list_indexes():
        if "weights" in idx:
            try:
                col.drop_index(idx["name"])
            except Exception:
                pass

    col.create_index(
        [("nombre", "text"), ("descripcion_general", "text"), ("descripcion_tecnica", "text")],
        name="idx_texto_full",
        default_language=language,
    )

def ensure_indexes(db):
    """
    Crea/ajusta todos los índices necesarios de forma segura e idempotente.
    """
    collection_name = os.getenv("MONGO_COLLECTION", "vulnerabilidades")
    col = db[collection_name]

    # Único por CVE ID (si existe uno no único o con otro nombre, lo sustituye)
    _upsert_index(col, [("cve_id", pymongo.ASCENDING)], name="uniq_cve_id", unique=True)

    # Índices de consulta
    _upsert_index(col, [("fecha_publicacion_dt", pymongo.DESCENDING)], name="idx_fecha_pub")
    _upsert_index(col, [("cvssv3.score", pymongo.DESCENDING)], name="idx_cvss_score")
    _upsert_index(col, [("tipo", pymongo.ASCENDING)], name="idx_tipo")
    _upsert_index(col, [("etiquetas", pymongo.ASCENDING)], name="idx_etiquetas")
    _upsert_index(col, [("infraestructura_5g_afectada", pymongo.ASCENDING)], name="idx_infraestructura")
    _upsert_index(col, [("versiones_afectadas", pymongo.ASCENDING)], name="idx_versiones")
    _upsert_index(col, [("interfaces_implicadas", pymongo.ASCENDING)], name="idx_interfaces")
    _upsert_index(col, [("protocolos_implicados", pymongo.ASCENDING)], name="idx_protocolos")

    # Índice de texto robusto (ES)
    ensure_text_index(col, os.getenv("TEXT_INDEX_LANGUAGE", "spanish"))

