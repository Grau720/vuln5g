# api/scanning/engine.py
from __future__ import annotations
import asyncio, threading, time
from dataclasses import is_dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any
from flask import current_app

from .plugin_base import ScanContext, Finding, Plugin
from .registry import REGISTRY
from .profiles import get_profile
from .correlator import correlate_findings

WORKER_TICK_SEC = 1.0
MAX_PARALLEL_JOBS = 3               # nº de jobs simultáneos
PLUGIN_TIMEOUT_FACTOR = 3.5         # multiplica timeouts base del perfil


def _now_utc() -> datetime:
    return datetime.utcnow()


def _normalize_targets(t: Dict[str, List[str]] | None) -> Dict[str, List[str]]:
    return {
        "core": sorted(set((t or {}).get("core") or [])),
        "ran_oam": sorted(set((t or {}).get("ran_oam") or [])),
    }


# ---------------- Queue API ----------------

def enqueue_job(db, profile: str, targets: dict, plugins: List[str], fingerprint: str) -> str:
    job_id = "sj_" + str(int(time.time() * 1000))[-10:]
    doc = {
        "job_id": job_id,
        "created_at": _now_utc(),
        "profile": profile,
        "status": "queued",
        "progress": 0,
        "targets": _normalize_targets(targets),
        "plugins": sorted(set(plugins or [])),
        "fingerprint": fingerprint,
    }
    db.scan_jobs.insert_one(doc)
    return job_id


def _claim_queued_jobs(db) -> List[dict]:
    running = db.scan_jobs.count_documents({"status": "running"})
    slots = max(0, MAX_PARALLEL_JOBS - running)
    if slots <= 0:
        return []
    claimed: List[dict] = []
    for j in db.scan_jobs.find({"status": "queued"}).sort("created_at", 1).limit(slots):
        res = db.scan_jobs.update_one(
            {"job_id": j["job_id"], "status": "queued"},
            {"$set": {"status": "running", "started_at": _now_utc(), "progress": max(1, j.get("progress", 0))}},
        )
        if res.modified_count == 1:
            claimed.append(j)
    return claimed


# ---------------- Helpers ----------------

def _findings_to_docs(job_id: str, fins: List[Any]) -> List[dict]:
    """
    Acepta:
      - lista de Finding (dataclass) -> dict
      - lista de dicts
    y devuelve dicts listos para Mongo.
    """
    docs: List[dict] = []
    for f in fins or []:
        if f is None:
            continue
        if is_dataclass(f):
            d = asdict(f)
        elif isinstance(f, dict):
            d = dict(f)
        else:
            # tipo inesperado -> lo guardamos como evidencia
            d = {
                "finding_id": f"unknown_{int(time.time())}",
                "component": "CORE",
                "interface": "—",
                "protocol": "—",
                "risk": {"cvss_v3": 0.0, "label": "Info"},
                "summary": f"Objeto de hallazgo no soportado: {type(f).__name__}",
                "evidence": {"repr": repr(f)[:400]},
            }
        d["job_id"] = job_id
        docs.append(d)
    return docs


async def _run_plugin_safe(db, job_id: str, plugin_cls: type[Plugin], ctx: ScanContext, profile_cfg: dict) -> List[Any]:
    """
    Ejecuta un plugin con timeout y captura excepciones, devolviendo hallazgos tipo Finding o dict.
    """
    timeout = PLUGIN_TIMEOUT_FACTOR * max(profile_cfg["tcp_timeout"], profile_cfg["udp_timeout"])
    try:
        # cancelación cooperativa
        j = db.scan_jobs.find_one({"job_id": job_id}, {"status": 1})
        if j and j.get("status") not in ("queued", "running"):
            raise asyncio.CancelledError()

        plugin: Plugin = plugin_cls()
        return await asyncio.wait_for(plugin.run(ctx), timeout=timeout)

    except asyncio.TimeoutError:
        return [Finding(
            finding_id=f"{plugin_cls.id}_timeout_{int(time.time())}",
            component=getattr(plugin_cls, "component", "CORE"),
            interface="—",
            protocol="—",
            risk={"cvss_v3": 0.0, "label": "Info"},
            summary=f"Timeout ejecutando {plugin_cls.id}",
            recommendation="Ajustar perfil o revisar reachability.",
            service=plugin_cls.id,
            tags=["timeout"],
        )]
    except asyncio.CancelledError:
        return [Finding(
            finding_id=f"{plugin_cls.id}_cancel_{int(time.time())}",
            component=getattr(plugin_cls, "component", "CORE"),
            interface="—",
            protocol="—",
            risk={"cvss_v3": 0.0, "label": "Info"},
            summary="Ejecución cancelada por cambio de estado del job.",
            recommendation=None,
            service=plugin_cls.id,
            tags=["cancelled"],
        )]
    except Exception as e:
        return [Finding(
            finding_id=f"{plugin_cls.id}_error_{int(time.time())}",
            component=getattr(plugin_cls, "component", "CORE"),
            interface="—",
            protocol="—",
            risk={"cvss_v3": 0.0, "label": "Info"},
            summary=f"Excepción en {plugin_cls.id}: {type(e).__name__}",
            recommendation=None,
            service=plugin_cls.id,
            tags=["exception"],
            evidence={"error": str(e)[:400]},
        )]


def _enrich_ctx_with_profile(ctx: ScanContext, profile_cfg: dict) -> ScanContext:
    ctx.params = {
        "concurrency": profile_cfg["concurrency"],
        "tcp_timeout": profile_cfg["tcp_timeout"],
        "udp_timeout": profile_cfg["udp_timeout"],
        "retries": profile_cfg["retries"],
        "cidr_host_limit": profile_cfg["cidr_host_limit"],
    }
    return ctx


# ---------------- Core runner ----------------

async def _run_job_async(app, job_doc: dict):
    with app.app_context():
        db = current_app.mongo.db

        profile = job_doc.get("profile", "standard")
        profile_cfg = get_profile(profile)

        started_at = _now_utc()

        # marca inicio (por si venía sólo 'queued')
        db.scan_jobs.update_one(
            {"job_id": job_doc["job_id"]},
            {"$set": {"status": "running", "started_at": started_at, "progress": 1, "metrics": {"plugin_times": {}}}},
        )

        # contexto compartido para todos los plugins del job
        ctx = ScanContext(
            job_id=job_doc["job_id"],
            profile=profile,
            targets=job_doc.get("targets", {}),
            raw_targets=job_doc.get("raw_targets", {}),
        )
        ctx = _enrich_ctx_with_profile(ctx, profile_cfg)

        pids = job_doc.get("plugins", []) or []
        total = max(1, len(pids))
        completed = 0
        lock = asyncio.Lock()
        sem = asyncio.Semaphore(profile_cfg["concurrency"])

        async def run_one(pid: str):
            nonlocal completed
            plugin_cls = REGISTRY.get(pid)
            if not plugin_cls:
                docs = _findings_to_docs(job_doc["job_id"], [{
                    "finding_id": f"f_{pid}_unsupported",
                    "component": "CORE",
                    "interface": "—",
                    "protocol": "—",
                    "risk": {"cvss_v3": 0.0, "label": "Info"},
                    "summary": f"Plugin '{pid}' no disponible en este nodo.",
                    "recommendation": "Verifica el registro de plugins.",
                }])
                if docs:
                    db.scan_findings.insert_many(docs, ordered=False)
                async with lock:
                    completed += 1
                    db.scan_jobs.update_one(
                        {"job_id": job_doc["job_id"]},
                        {"$set": {"progress": int(completed * 100 / total)}},
                    )
                return

            async with sem:
                start = time.time()
                fins = await _run_plugin_safe(db, job_doc["job_id"], plugin_cls, ctx, profile_cfg)
                elapsed = time.time() - start

                docs = _findings_to_docs(job_doc["job_id"], fins)
                if docs:
                    docs = correlate_findings(docs)
                    db.scan_findings.insert_many(docs, ordered=False)

                # guardar tiempo por plugin
                db.scan_jobs.update_one(
                    {"job_id": job_doc["job_id"]},
                    {"$set": {f"metrics.plugin_times.{pid}": elapsed}}
                )

                async with lock:
                    completed += 1
                    db.scan_jobs.update_one(
                        {"job_id": job_doc["job_id"]},
                        {"$set": {"progress": int(completed * 100 / total)}},
                    )

        # lanza todos los plugins (concurrencia limitada por sem)
        await asyncio.gather(*(run_one(pid) for pid in pids))

        # fin
        finished_at = _now_utc()
        dur_ms = (finished_at - started_at).total_seconds() * 1000

        db.scan_jobs.update_one(
            {"job_id": job_doc["job_id"]},
            {"$set": {
                "status": "finished",
                "finished_at": finished_at,
                "progress": 100,
                "dur_ms": dur_ms
            }},
        )


def _worker_loop(app):
    def spawn(job_doc: dict):
        def _th():
            asyncio.run(_run_job_async(app, job_doc))
        t = threading.Thread(target=_th, daemon=True, name=f"scan-job-{job_doc['job_id']}")
        t.start()

    while True:
        try:
            with app.app_context():
                db = current_app.mongo.db
                for job in _claim_queued_jobs(db):
                    spawn(job)
        except Exception as e:
            # no hacemos crash del worker por errores puntuales
            print(f"[scan-worker] error: {e}")
        time.sleep(WORKER_TICK_SEC)


def start_worker(app):
    t = threading.Thread(target=_worker_loop, args=(app,), daemon=True, name="scan-worker")
    t.start()
    print("[scan-worker] started")
