# routes/scan_api.py
from __future__ import annotations

from flask import Blueprint, jsonify, request, current_app, Response, stream_with_context
from uuid import uuid4
from datetime import datetime, timedelta
import json, hashlib, threading, time, os, ipaddress

# Motor y registro externos (tu módulo real)
from scanning.engine import enqueue_job, start_worker
from scanning.registry import available_plugins
from scanning.plugin_base import ScanContext

# RRULE / TZ
from dateutil.rrule import rrulestr
from dateutil.tz import gettz

# --- Export: JSON / CSV / XML (PDF opcional) ---
from io import StringIO, BytesIO
import csv
from xml.etree.ElementTree import Element, SubElement, tostring

# ------------------------------------------------------------------------------
# Blueprint
# ------------------------------------------------------------------------------
scan_bp = Blueprint("scan_api", __name__, url_prefix="/api/scan")

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
DEDUP_WINDOW_MIN = 30
SCHED_TICK_SEC = 15
DEFAULT_TZ = "Europe/Madrid"

# Límite de expansión por CIDR (para no fundir el worker)
MAX_HOSTS_PER_CIDR = int(os.getenv("MAX_HOSTS_PER_CIDR", "256"))

# Capacidades del nodo (ej.: activar sonda RAN vía env)
NODE_CAPS = {
    "ran_probe": os.getenv("ENABLE_RAN", "0").lower() in ("1", "true", "yes"),
}

# ------------------------------------------------------------------------------
# Helpers generales
# ------------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.utcnow()

def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).strftime("%Y-%m-%dT%H:%M:%SZ")

def _jsonify_dt(x):
    """Convierte recursivamente datetime -> ISO para JSON/SSE."""
    if isinstance(x, datetime):
        return _iso(x)
    if isinstance(x, dict):
        return {k: _jsonify_dt(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [_jsonify_dt(v) for v in x]
    return x

def compute_criticity(findings: list[dict]) -> dict:
    """
    Calcula métricas agregadas de criticidad a partir de los findings.
    - coverage: % de findings con severidad High o Critical
    - avg_score: media ponderada de CVSS v3 (más peso a severidades altas)
    - max_score: mayor CVSS encontrado
    """
    if not findings:
        return {"coverage": 0, "avg_score": 0, "max_score": 0}

    scores = []
    weights = []
    crit_high = 0

    for f in findings:
        risk = f.get("risk") or {}
        score = risk.get("cvss_v3", 0) or 0
        label = (risk.get("label") or "").lower()

        # peso por severidad
        w = 1
        if label == "medium":
            w = 2
        elif label == "high":
            w = 3
        elif label == "critical":
            w = 4

        scores.append(score * w)
        weights.append(w)

        if label in ("critical", "high"):
            crit_high += 1

    coverage = crit_high / len(findings)
    avg_score = sum(scores) / max(1, sum(weights))
    max_score = max(r.get("cvss_v3", 0) or 0 for r in (f.get("risk") or {} for f in findings))

    return {
        "coverage": round(coverage, 3),
        "avg_score": round(avg_score, 1),
        "max_score": round(max_score, 1),
    }

def state_app_db():
    return current_app.mongo.db

# ------------------------------------------------------------------------------
# Targets & fingerprint
# ------------------------------------------------------------------------------
def _normalize_targets(t: dict | None) -> dict:
    """Mantiene lo introducido por el usuario (sin expandir CIDR)."""
    return {
        "core": sorted(set((t or {}).get("core") or [])),
        "ran_oam": sorted(set((t or {}).get("ran_oam") or [])),
    }

def _expand_target_items(items: list[str] | None, *, max_hosts: int = 256) -> list[str]:
    """Convierte CIDR en hosts con límite; acepta IPs y hostnames."""
    out: list[str] = []
    for raw in (items or []):
        s = (raw or "").strip()
        if not s:
            continue
        try:
            if "/" in s:
                net = ipaddress.ip_network(s, strict=False)
                for i, h in enumerate(net.hosts()):
                    if i >= max_hosts:
                        break
                    out.append(str(h))
            else:
                try:
                    ipaddress.ip_address(s)
                    out.append(s)  # IP válida
                except ValueError:
                    out.append(s)  # hostname/FQDN
        except ValueError:
            out.append(s)      # formato raro -> lo dejamos
    return sorted(set(out))

def _resolve_targets(targets: dict | None, *, max_hosts: int = 256) -> dict:
    t = targets or {}
    return {
        "core": _expand_target_items(t.get("core"), max_hosts=max_hosts),
        "ran_oam": _expand_target_items(t.get("ran_oam"), max_hosts=max_hosts),
    }

def _fingerprint(profile: str, targets: dict, plugins: list[str]) -> str:
    """Huella para dedupe (se basa en targets normalizados tal cual los escribe el usuario)."""
    body = {
        "profile": profile or "standard",
        "targets": _normalize_targets(targets),
        "plugins": sorted(set(plugins or [])),
    }
    s = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()

# ------------------------------------------------------------------------------
# Plugins (disponibilidad)
# ------------------------------------------------------------------------------
def _plugin_available_default(pid: str) -> bool:
    """Regla local por si el registry no aporta 'available'."""
    if pid == "rogue_gnodeb_detector":
        return NODE_CAPS["ran_probe"]
    return True

def _registry_plugins() -> list[dict]:
    """
    Obtiene plugins del registry y garantiza el campo 'available'.
    Estructura esperada por el front: {id, component, interfaces, profile, available}
    """
    try:
        plugs = available_plugins() or []
    except Exception:
        plugs = []
    out = []
    for p in plugs:
        d = dict(p)
        pid = d.get("id")
        if "available" not in d:
            d["available"] = _plugin_available_default(pid)
        out.append(d)
    return out

def _filter_unsupported(req_plugins: list[str]) -> tuple[list[str], list[str]]:
    reg = _registry_plugins()
    avail_map = {p["id"]: bool(p.get("available", True)) for p in reg if p.get("id")}
    supported = [p for p in sorted(set(req_plugins or [])) if avail_map.get(p, True)]
    unsupported = [p for p in sorted(set(req_plugins or [])) if not avail_map.get(p, True)]
    return supported, unsupported

# ------------------------------------------------------------------------------
# Índices / seed
# ------------------------------------------------------------------------------
def ensure_scan_indexes(db):
    db.scan_jobs.create_index("job_id", unique=True)
    db.scan_jobs.create_index([("created_at", -1)])
    db.scan_jobs.create_index([("status", 1), ("created_at", -1)])
    db.scan_findings.create_index([("job_id", 1), ("finding_id", 1)], unique=True)
    # dedupe por fingerprint + status
    try:
        db.scan_jobs.create_index(
            [("fingerprint", 1), ("status", 1)],
            name="uniq_fp_status",
            unique=True,
        )
    except Exception:
        pass
    # schedules
    db.scan_schedules.create_index("schedule_id", unique=True)
    db.scan_schedules.create_index([("enabled", 1), ("next_run", 1)])
    db.scan_schedules.create_index([("created_at", -1)])

# ------------------------------------------------------------------------------
# Planificador
# ------------------------------------------------------------------------------
def _compute_next_from_rrule(rrule_str: str, tz_name: str, start_at_utc: datetime | None, after_utc: datetime) -> datetime | None:
    """Evalúa RRULE en la TZ indicada y devuelve la próxima ocurrencia en UTC naïve."""
    tz = gettz(tz_name or DEFAULT_TZ)
    dtstart_local = (start_at_utc or after_utc).replace(tzinfo=gettz("UTC")).astimezone(tz)
    rule = rrulestr(rrule_str, dtstart=dtstart_local)
    after_local = after_utc.replace(tzinfo=gettz("UTC")).astimezone(tz)
    nxt_local = rule.after(after_local, inc=False)
    if not nxt_local:
        return None
    return nxt_local.astimezone(gettz("UTC")).replace(tzinfo=None)

def _scheduler_loop(app):
    with app.app_context():
        db = state_app_db()
        while True:
            try:
                now = _now()
                cur = db.scan_schedules.find({"enabled": True, "next_run": {"$lte": now}})
                for s in cur:
                    profile = s.get("profile", "standard")
                    raw_targets = s.get("targets", {})
                    req_plugins = s.get("plugins", [])

                    # Filtra plugins no soportados
                    plugins, _unsupported = _filter_unsupported(req_plugins)

                    # Fingerprint con targets crudos
                    fp = _fingerprint(profile, raw_targets, plugins)

                    # Resolver CIDR a hosts para ejecución real
                    resolved_targets = _resolve_targets(raw_targets, max_hosts=MAX_HOSTS_PER_CIDR)

                    enqueue_job(
                        db,
                        profile,
                        resolved_targets,
                        plugins,
                        fingerprint=fp,
                    )

                    # recalcular siguiente
                    rrule_str = s.get("rrule")
                    run_once = s.get("run_at") is not None and rrule_str is None
                    if rrule_str:
                        nxt = _compute_next_from_rrule(rrule_str, s.get("tz") or DEFAULT_TZ, s.get("start_at"), now + timedelta(seconds=1))
                        if nxt:
                            db.scan_schedules.update_one({"schedule_id": s["schedule_id"]}, {"$set": {"last_run": now, "next_run": nxt, "updated_at": now}})
                        else:
                            db.scan_schedules.update_one({"schedule_id": s["schedule_id"]}, {"$set": {"last_run": now, "enabled": False, "updated_at": now}})
                    elif run_once:
                        db.scan_schedules.update_one({"schedule_id": s["schedule_id"]}, {"$set": {"last_run": now, "enabled": False, "updated_at": now}})
            except Exception as e:
                print(f"[scan-sched] error: {e}")
            time.sleep(SCHED_TICK_SEC)

def start_scheduler(app):
    t = threading.Thread(target=_scheduler_loop, args=(app,), daemon=True)
    t.start()
    print("[scan-sched] thread started")

# ------------------------------------------------------------------------------
# Registro al iniciar
# ------------------------------------------------------------------------------
@scan_bp.record_once
def _on_register(state):
    app = state.app
    with app.app_context():
        db = state_app_db()
        ensure_scan_indexes(db)
    start_worker(app)     # motor real
    start_scheduler(app)  # planificador

# ------------------------------------------------------------------------------
# API: Plugins
# ------------------------------------------------------------------------------
@scan_bp.route("/plugins")
def plugins():
    """Devuelve el catálogo de plugins con 'available' garantizado."""
    return jsonify({"plugins": _registry_plugins()})

# ------------------------------------------------------------------------------
# API: Jobs
# ------------------------------------------------------------------------------
@scan_bp.route("/jobs", methods=["GET"])
def list_jobs():
    db = state_app_db()
    cur = db.scan_jobs.find({}, {"_id": 0}).sort("created_at", -1)
    out = []
    for j in cur:
        # Campos principales a ISO
        j["created_at"] = _iso(j["created_at"])
        if j.get("started_at"):   j["started_at"]   = _iso(j["started_at"])
        if j.get("finished_at"):  j["finished_at"]  = _iso(j["finished_at"])

        # 🆕 Normaliza criticidad si existe en metrics
        metrics = j.get("metrics", {})
        criticity = metrics.get("criticity", {})
        j["metrics"] = {
            **metrics,
            "criticity": {
                "coverage": float(criticity.get("coverage", 0.0)),
                "avg_score": float(criticity.get("avg_score", 0.0)),
                "max_score": float(criticity.get("max_score", 0.0)),
            }
        }

        out.append(j)
    return jsonify({"jobs": out})

@scan_bp.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    db = state_app_db()
    j = db.scan_jobs.find_one({"job_id": job_id}, {"_id": 0})
    if not j:
        return jsonify({"error": "not_found"}), 404
    j["created_at"] = _iso(j["created_at"])
    if j.get("started_at"):  j["started_at"]  = _iso(j["started_at"])
    if j.get("finished_at"): j["finished_at"] = _iso(j["finished_at"])
    return jsonify(j)

@scan_bp.route("/jobs/<job_id>/findings")
def get_findings(job_id):
    db = state_app_db()
    cur = db.scan_findings.find({"job_id": job_id}, {"_id": 0})
    findings = list(cur)

    criticity = compute_criticity(findings)

    # 🆕 Persistir criticidad en el job
    db.scan_jobs.update_one(
        {"job_id": job_id},
        {"$set": {"metrics.criticity": criticity}}
    )

    return jsonify({
        "findings": findings,
        "criticity": criticity
    })

@scan_bp.route("/jobs", methods=["POST"])
def create_job():
    """
    Crea un job:
      - Filtra plugins no soportados (devuelve 'unsupported_plugins').
      - Deduplica por fingerprint (profile + targets **crudos** + plugins soportados).
      - Encola usando targets **resueltos** (CIDR -> hosts).
    """
    db = state_app_db()
    b = request.get_json(force=True) or {}

    profile = b.get("profile", "standard")

    # 1) Lo que el usuario envía (para dedupe y trazabilidad)
    raw_targets = _normalize_targets(b.get("targets", {}))

    # 2) Plugins solicitados → filtra no soportados
    req_plugins = sorted(set(b.get("plugins") or []))
    plugins, unsupported = _filter_unsupported(req_plugins)

    # 3) Fingerprint SIEMPRE con 'raw' (así 10.0.0.0/24 y su expansión siguen siendo el mismo job lógico)
    fp = _fingerprint(profile, raw_targets, plugins)

    # 4) Dedup en ventana
    force = request.args.get("force", "").lower() in ("1", "true", "yes") or \
            request.headers.get("X-Scan-Force", "").lower() in ("1", "true", "yes")

    if not force:
        hit = db.scan_jobs.find_one(
            {"fingerprint": fp, "status": {"$in": ["queued", "running"]}},
            {"job_id": 1, "created_at": 1, "status": 1, "_id": 0},
        )
        if hit and (_now() - hit["created_at"]).total_seconds() / 60.0 < DEDUP_WINDOW_MIN:
            return jsonify({
                "job_id": hit["job_id"],
                "status": hit["status"],
                "already_exists": True,
                "unsupported_plugins": unsupported
            }), 200

    # 5) Resolver CIDR -> hosts para que los plugins no vean "10.0.0.0/24"
    resolved_targets = _resolve_targets(raw_targets, max_hosts=MAX_HOSTS_PER_CIDR)

    # 6) Encolar con targets resueltos
    job_id = enqueue_job(db, profile, resolved_targets, plugins, fp)

    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "unsupported_plugins": unsupported
    }), 202

@scan_bp.route("/jobs/<job_id>/action", methods=["POST"])
def job_action(job_id):
    db = state_app_db()
    b = request.get_json(force=True) or {}
    action = (b.get("action") or "").lower()

    j = db.scan_jobs.find_one({"job_id": job_id})
    if not j:
        return jsonify({"error": "not_found"}), 404

    if action == "cancel":
        if j["status"] in ("queued", "running"):
            db.scan_jobs.update_one({"job_id": job_id}, {"$set": {"status": "cancelled", "finished_at": _now()}})
            db.scan_findings.insert_one({
                "job_id": job_id,
                "finding_id": f"f_cancel_{uuid4().hex[:8]}",
                "component": "CORE", "interface": "—", "protocol": "—",
                "risk": {"cvss_v3": 0.0, "label": "Info"},
                "summary": "Escaneo cancelado por el usuario.",
                "recommendation": "Relanzar si es necesario."
            })
        return jsonify({"ok": True})

    if action == "delete":
        db.scan_findings.delete_many({"job_id": job_id})
        db.scan_jobs.delete_one({"job_id": job_id})
        return jsonify({"ok": True})

    if action == "rerun":
        payload = {
            "profile": j.get("profile", "standard"),
            "targets": j.get("targets", {}),
            "plugins": j.get("plugins", []),
        }
        # Aplica otra vez filtro de soporte
        plugins, _unsupported = _filter_unsupported(payload["plugins"])
        fp = _fingerprint(payload["profile"], payload["targets"], plugins)
        hit = db.scan_jobs.find_one({"fingerprint": fp, "status": {"$in": ["queued", "running"]}}, {"job_id": 1, "_id": 0})
        if hit:
            return jsonify({"job_id": hit["job_id"], "status": "running", "already_exists": True})
        new_id = enqueue_job(db, payload["profile"], payload["targets"], plugins, fp)
        return jsonify({"job_id": new_id, "status": "queued"})

    return jsonify({"error": "bad_action"}), 400

# ------------------------------------------------------------------------------
# SSE: progreso por job
# ------------------------------------------------------------------------------
@scan_bp.route("/jobs/<job_id>/stream")
def stream_job(job_id):
    db = state_app_db()

    def gen():
        last = None
        while True:
            j = db.scan_jobs.find_one({"job_id": job_id}, {"_id": 0})
            if not j:
                yield f"event: gone\ndata: {{\"job_id\":\"{job_id}\"}}\n\n"
                break

            payload_obj = _jsonify_dt(j)
            payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)

            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload

            if payload_obj.get("status") in ("finished", "error"):
                break

            # Keepalive para proxies / devtools
            yield ": keepalive\n\n"
            time.sleep(1.5)

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
    
@scan_bp.route("/jobs/<job_id>/export", methods=["GET"])
def export_job(job_id):
    fmt = (request.args.get("fmt", "json") or "json").lower()
    db = state_app_db()

    job = db.scan_jobs.find_one({"job_id": job_id}, {"_id": 0})
    if not job:
        return jsonify({"error": "not_found"}), 404
    findings = list(db.scan_findings.find({"job_id": job_id}, {"_id": 0}))

    # Normaliza datetimes a ISO
    job_iso = _jsonify_dt(job)
    fins_iso = [_jsonify_dt(f) for f in findings]
    payload = {"job": job_iso, "findings": fins_iso, "generated_at": _iso()}

    if fmt == "json":
        return Response(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{job_id}.json"'},
        )

    if fmt == "csv":
        # CSV plano de findings
        buf = StringIO()
        w = csv.writer(buf)
        headers = ["finding_id","component","interface","protocol","risk_label","risk_cvss","summary"]
        w.writerow(headers)
        for f in fins_iso:
            risk = f.get("risk") or {}
            w.writerow([
                f.get("finding_id",""),
                f.get("component",""),
                f.get("interface",""),
                f.get("protocol",""),
                risk.get("label",""),
                risk.get("cvss_v3",""),
                (f.get("summary","") or "").replace("\n"," ").strip(),
            ])
        data = buf.getvalue().encode("utf-8")
        return Response(
            data, mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{job_id}.csv"'}
        )

    if fmt == "xml":
        root = Element("scanReport")
        meta = SubElement(root, "job")
        for k, v in job_iso.items():
            e = SubElement(meta, k)
            e.text = str(v)
        fins_el = SubElement(root, "findings")
        for f in fins_iso:
            fe = SubElement(fins_el, "finding")
            for k, v in f.items():
                if isinstance(v, dict):
                    de = SubElement(fe, k)
                    for kk, vv in v.items():
                        se = SubElement(de, kk)
                        se.text = str(vv)
                else:
                    se = SubElement(fe, k)
                    se.text = str(v)
        xml_bytes = tostring(root, encoding="utf-8")
        return Response(
            xml_bytes, mimetype="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{job_id}.xml"'}
        )

    if fmt == "pdf":
        # Stub: si no quieres añadir deps aún, devolvemos 501
        return jsonify({"error":"not_implemented","detail":"PDF no disponible todavía"}), 501

    return jsonify({"error": "bad_format", "detail": "Usa fmt=json|csv|xml|pdf"}), 400

# ------------------------------------------------------------------------------
# API: Schedules
# ------------------------------------------------------------------------------
@scan_bp.route("/schedules", methods=["GET"])
def list_schedules():
    db = state_app_db()
    out = []
    for s in db.scan_schedules.find({}, {"_id": 0}).sort("created_at", -1):
        for k in ("created_at", "updated_at", "start_at", "run_at", "next_run", "last_run"):
            if s.get(k) and not isinstance(s[k], str):
                s[k] = _iso(s[k])
        out.append(s)
    return jsonify({"schedules": out})

@scan_bp.route("/schedules/<sid>", methods=["GET"])
def get_schedule(sid):
    db = state_app_db()
    s = db.scan_schedules.find_one({"schedule_id": sid}, {"_id": 0})
    if not s:
        return jsonify({"error": "not_found"}), 404
    for k in ("created_at", "updated_at", "start_at", "run_at", "next_run", "last_run"):
        if s.get(k) and not isinstance(s[k], str):
            s[k] = _iso(s[k])
    return jsonify(s)

@scan_bp.route("/schedules", methods=["POST"])
def create_schedule():
    db = state_app_db()
    b = request.get_json(force=True) or {}
    name = (b.get("name") or "").strip() or "Scan programado"
    profile = b.get("profile", "standard")
    targets = _normalize_targets(b.get("targets", {}))
    req_plugins = sorted(set(b.get("plugins") or []))
    tz = b.get("tz") or DEFAULT_TZ

    # Asegura consistencia con jobs: filtra no soportados
    plugins, _unsupported = _filter_unsupported(req_plugins)

    rrule_str = (b.get("rrule") or "").strip() or None
    run_at = b.get("run_at")    # ISO opcional (one-shot)
    start_at = b.get("start_at")  # ISO opcional (inicio regla)
    enabled = bool(b.get("enabled", True))

    def _parse_iso(s):
        if not s:
            return None
        try:
            ss = s.replace("Z", "")
            dt = datetime.fromisoformat(ss)
            dt_local = dt.replace(tzinfo=gettz(tz))
            return dt_local.astimezone(gettz("UTC")).replace(tzinfo=None)
        except Exception:
            return None

    start_at_utc = _parse_iso(start_at)
    run_at_utc = _parse_iso(run_at)

    if not rrule_str and not run_at_utc:
        return jsonify({"error": "invalid_schedule", "detail": "Proporciona 'rrule' o 'run_at'"}), 400

    now = _now()
    if rrule_str:
        nxt = _compute_next_from_rrule(rrule_str, tz, start_at_utc, now)
        if not nxt:
            return jsonify({"error": "invalid_rrule", "detail": "RRULE sin próximas ocurrencias"}), 400
        next_run = nxt
    else:
        next_run = run_at_utc if (run_at_utc and run_at_utc > now) else now + timedelta(seconds=SCHED_TICK_SEC)

    sid = "sc_" + uuid4().hex[:10]
    doc = {
        "schedule_id": sid,
        "name": name,
        "enabled": enabled,
        "profile": profile,
        "targets": targets,
        "plugins": plugins,
        "tz": tz,
        "rrule": rrule_str,
        "start_at": start_at_utc,
        "run_at": run_at_utc,
        "next_run": next_run,
        "last_run": None,
        "created_at": now,
        "updated_at": now,
    }
    db.scan_schedules.insert_one(doc)
    for k in ("created_at", "updated_at", "start_at", "run_at", "next_run", "last_run"):
        if doc.get(k):
            doc[k] = _iso(doc[k])
    return jsonify(doc), 201

@scan_bp.route("/schedules/<sid>", methods=["PATCH"])
def update_schedule(sid):
    db = state_app_db()
    b = request.get_json(force=True) or {}
    s = db.scan_schedules.find_one({"schedule_id": sid})
    if not s:
        return jsonify({"error": "not_found"}), 404

    updates = {}
    if "name" in b:    updates["name"] = (b["name"] or "").strip() or s["name"]
    if "enabled" in b: updates["enabled"] = bool(b["enabled"])
    if "profile" in b: updates["profile"] = b["profile"] or s["profile"]
    if "targets" in b: updates["targets"] = _normalize_targets(b["targets"])
    if "plugins" in b: updates["plugins"] = _filter_unsupported(sorted(set(b["plugins"] or [])))[0]
    if "tz" in b:      updates["tz"] = b["tz"] or s.get("tz") or DEFAULT_TZ
    if "rrule" in b:   updates["rrule"] = (b["rrule"] or "").strip() or None

    if "start_at" in b:
        updates["start_at"] = None if not b["start_at"] else datetime.fromisoformat(b["start_at"].replace("Z", "")).replace(
            tzinfo=gettz(updates.get("tz", s.get("tz", DEFAULT_TZ)))
        ).astimezone(gettz("UTC")).replace(tzinfo=None)

    if "run_at" in b:
        updates["run_at"] = None if not b["run_at"] else datetime.fromisoformat(b["run_at"].replace("Z", "")).replace(
            tzinfo=gettz(updates.get("tz", s.get("tz", DEFAULT_TZ)))
        ).astimezone(gettz("UTC")).replace(tzinfo=None)

    recalc = any(k in updates for k in ("rrule", "start_at", "run_at", "enabled", "tz"))
    now = _now()
    if recalc:
        rrule_str = updates.get("rrule", s.get("rrule"))
        tz_name = updates.get("tz", s.get("tz") or DEFAULT_TZ)
        start_at_utc = updates.get("start_at", s.get("start_at"))
        run_at_utc = updates.get("run_at", s.get("run_at"))
        enabled = updates.get("enabled", s.get("enabled", True))
        next_run = s.get("next_run")
        if enabled:
            if rrule_str:
                nxt = _compute_next_from_rrule(rrule_str, tz_name, start_at_utc, now)
                next_run = nxt
            else:
                next_run = run_at_utc if (run_at_utc and run_at_utc > now) else now + timedelta(seconds=SCHED_TICK_SEC)
        updates["next_run"] = next_run

    updates["updated_at"] = now
    db.scan_schedules.update_one({"schedule_id": sid}, {"$set": updates})
    s = db.scan_schedules.find_one({"schedule_id": sid}, {"_id": 0})
    for k in ("created_at", "updated_at", "start_at", "run_at", "next_run", "last_run"):
        if s.get(k) and not isinstance(s[k], str):
            s[k] = _iso(s[k])
    return jsonify(s)

@scan_bp.route("/schedules/<sid>/action", methods=["POST"])
def schedule_action(sid):
    db = state_app_db()
    s = db.scan_schedules.find_one({"schedule_id": sid})
    if not s:
        return jsonify({"error": "not_found"}), 404

    b = request.get_json(force=True) or {}
    action = (b.get("action") or "").lower()
    now = _now()

    if action == "pause":
        db.scan_schedules.update_one({"schedule_id": sid}, {"$set": {"enabled": False, "updated_at": now}})
        return jsonify({"ok": True})

    if action == "resume":
        if s.get("rrule"):
            nxt = _compute_next_from_rrule(s["rrule"], s.get("tz") or DEFAULT_TZ, s.get("start_at"), now)
        else:
            nxt = s.get("run_at") or (now + timedelta(seconds=SCHED_TICK_SEC))
        db.scan_schedules.update_one({"schedule_id": sid}, {"$set": {"enabled": True, "next_run": nxt, "updated_at": now}})
        return jsonify({"ok": True})

    if action == "run_now":
        profile = s.get("profile", "standard")
        raw_targets = s.get("targets", {})
        req_plugins = s.get("plugins", [])

        plugins, _unsupported = _filter_unsupported(req_plugins)
        fp = _fingerprint(profile, raw_targets, plugins)
        resolved_targets = _resolve_targets(raw_targets, max_hosts=MAX_HOSTS_PER_CIDR)

        enqueue_job(db, profile, resolved_targets, plugins, fingerprint=fp)
        
        if s.get("rrule"):
            nxt = _compute_next_from_rrule(s["rrule"], s.get("tz") or DEFAULT_TZ, s.get("start_at"), now + timedelta(seconds=1))
            upd = {"last_run": now, "updated_at": now}
            if nxt:
                upd["next_run"] = nxt
            else:
                upd["enabled"] = False
            db.scan_schedules.update_one({"schedule_id": sid}, {"$set": upd})
        else:
            db.scan_schedules.update_one({"schedule_id": sid}, {"$set": {"last_run": now, "enabled": False, "updated_at": now}})
        return jsonify({"ok": True})

    if action == "delete":
        db.scan_schedules.delete_one({"schedule_id": sid})
        return jsonify({"ok": True})

    return jsonify({"error": "bad_action"}), 400

@scan_bp.route("/schedules/<sid>/preview", methods=["GET"])
def schedule_preview(sid):
    """Devuelve próximas N ejecuciones (default 5) según RRULE; one-shot devuelve run_at."""
    db = state_app_db()
    s = db.scan_schedules.find_one({"schedule_id": sid})
    if not s:
        return jsonify({"error": "not_found"}), 404

    count = max(1, min(20, int(request.args.get("count", 5))))
    if not s.get("rrule"):
        run_at = s.get("run_at")
        return jsonify({"occurrences": [_iso(run_at)] if run_at else []})

    tz_name = s.get("tz") or DEFAULT_TZ
    tz = gettz(tz_name)
    dtstart_local = (s.get("start_at") or _now()).replace(tzinfo=gettz("UTC")).astimezone(tz)
    rule = rrulestr(s["rrule"], dtstart=dtstart_local)
    after_local = _now().replace(tzinfo=gettz("UTC")).astimezone(tz)
    occs = []
    cur = rule.after(after_local, inc=False)
    while cur and len(occs) < count:
        occs.append(_iso(cur.astimezone(gettz("UTC")).replace(tzinfo=None)))
        cur = rule.after(cur, inc=False)
    return jsonify({"occurrences": occs})

# Añadir estos endpoints al final de scan_api.py, antes de las schedules

# ------------------------------------------------------------------------------
# API: Discovery (pre-scan para detectar hosts activos)
# ------------------------------------------------------------------------------

@scan_bp.route("/discover", methods=["POST"])
def discover_active_hosts():
    """
    Ejecuta un discovery rápido para identificar hosts activos.
    
    Body:
    {
      "targets": {"core": ["172.22.0.0/24"], "ran_oam": []},
      "profile": "fast"  // opcional, por defecto "fast"
    }
    
    Retorna:
    {
      "active_hosts": {
        "core": ["172.22.0.7", "172.22.0.10", ...],
        "ran_oam": []
      },
      "summary": {
        "total_scanned": 254,
        "total_active": 10,
        "duration_sec": 3.2
      }
    }
    """
    import asyncio
    from scanning.plugins.smart_discovery import SmartDiscovery
    
    b = request.get_json(force=True) or {}
    
    # Targets a escanear (pueden incluir CIDR)
    raw_targets = _normalize_targets(b.get("targets", {}))
    
    # Expandir CIDR a IPs individuales
    resolved_targets = _resolve_targets(raw_targets, max_hosts=MAX_HOSTS_PER_CIDR)
    
    # Perfil para discovery (rápido por defecto)
    profile = b.get("profile", "fast")
    
    # Crear contexto temporal
    ctx = ScanContext(
        job_id="discovery_" + str(int(time.time())),
        profile=profile,
        targets=resolved_targets,
        raw_targets=raw_targets
    )
    
    # Ejecutar discovery
    plugin = SmartDiscovery()
    
    async def run_discovery():
        return await plugin.run(ctx)
    
    start = time.time()
    findings = asyncio.run(run_discovery())
    elapsed = time.time() - start
    
    # Extraer hosts activos de los findings
    active_hosts = {
        "core": [],
        "ran_oam": [],
        "transport": [],
        "support": []
    }
    
    total_scanned = sum(len(v) for v in resolved_targets.values())
    total_active = 0
    
    for f in findings:
        if "active_host" in f.tags:
            host = f.target
            if host:
                # Determinar categoría basándose en la categoría original
                for category, hosts in resolved_targets.items():
                    if host in hosts:
                        active_hosts[category].append(host)
                        total_active += 1
                        break
    
    # Ordenar y deduplicar
    for category in active_hosts:
        active_hosts[category] = sorted(set(active_hosts[category]))
    
    return jsonify({
        "active_hosts": active_hosts,
        "summary": {
            "total_scanned": total_scanned,
            "total_active": total_active,
            "duration_sec": round(elapsed, 2)
        },
        "findings": [
            {
                "finding_id": f.finding_id,
                "summary": f.summary,
                "target": f.target,
                "evidence": f.evidence,
                "tags": f.tags
            }
            for f in findings
        ]
    })


@scan_bp.route("/targets/docker", methods=["GET"])
def discover_docker_targets():
    """
    Descubre targets desde la red Docker de Open5GS.
    Complementario al discovery por ping/TCP.
    
    Query params:
    - network: nombre de la red Docker (default: docker_open5gs_default)
    
    Retorna:
    {
      "network": "docker_open5gs_default",
      "targets": {
        "core": ["172.22.0.7", "172.22.0.10", ...],
        "transport": ["172.22.0.8"],
        "support": ["172.22.0.2", ...]
      },
      "containers": [
        {"name": "smf", "ip": "172.22.0.7", "category": "core"},
        ...
      ]
    }
    """
    import subprocess
    import json as json_lib
    
    network_name = request.args.get("network", "docker_open5gs_default")
    
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", network_name],
            capture_output=True,
            text=True,
            check=True
        )
        network_data = json_lib.loads(result.stdout)[0]
        containers_data = network_data.get("Containers", {})
        
        targets = {
            "core": [],
            "transport": [],
            "support": []
        }
        
        containers = []
        
        # Mapeo de nombres a categorías
        core_names = ["amf", "smf", "udm", "udr", "ausf", "pcf", "nrf", "scp", "bsf", "nssf"]
        transport_names = ["upf"]
        support_names = ["mongo", "webui", "metrics", "grafana"]
        
        for container_info in containers_data.values():
            name = container_info.get("Name", "").lower()
            ip = container_info.get("IPv4Address", "").split("/")[0]
            
            if not ip:
                continue
            
            category = None
            
            if any(comp in name for comp in core_names):
                category = "core"
                targets["core"].append(ip)
            elif any(comp in name for comp in transport_names):
                category = "transport"
                targets["transport"].append(ip)
            elif any(comp in name for comp in support_names):
                category = "support"
                targets["support"].append(ip)
            
            if category:
                containers.append({
                    "name": container_info.get("Name", "unknown"),
                    "ip": ip,
                    "category": category
                })
        
        # Ordenar y deduplicar
        for key in targets:
            targets[key] = sorted(set(targets[key]))
        
        total = sum(len(v) for v in targets.values())
        
        return jsonify({
            "network": network_name,
            "targets": targets,
            "containers": sorted(containers, key=lambda x: x["ip"]),
            "summary": {
                "total_containers": len(containers),
                "by_category": {k: len(v) for k, v in targets.items() if v}
            }
        })
        
    except subprocess.CalledProcessError:
        return jsonify({
            "error": "docker_error",
            "detail": f"No se pudo inspeccionar la red '{network_name}'. ¿Existe la red?"
        }), 404
    except Exception as e:
        return jsonify({
            "error": "discovery_failed",
            "detail": str(e)
        }), 500