# api/scanning/plugin_base.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Finding:
    finding_id: str
    component: str
    interface: str
    protocol: str
    risk: Dict[str, Any]            # p.ej. {"cvss_v3": 7.5, "label": "High"}
    summary: str
    recommendation: Optional[str] = None

    # Campos extra normalizados (opcionales)
    service: Optional[str] = None   # "pfcp", "http2", etc.
    target: Optional[str] = None    # host/ip
    transport: Optional[str] = None # "tcp" | "udp"
    port: Optional[int] = None

    tags: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    cve_refs: List[str] = field(default_factory=list)

@dataclass
class ScanContext:
    job_id: str
    profile: str                     # "fast" | "standard" | "exhaustive"
    targets: Dict[str, List[str]]    # {"core":[...], "ran_oam":[...]}
    raw_targets: Dict[str, List[str]] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)  # timeouts, retries, concurrency...

class Plugin:
    id: str = "base"
    component: str = "CORE"
    interfaces: List[str] = []
    profile: str = "all"

    async def run(self, ctx: ScanContext) -> List[Finding]:
        raise NotImplementedError
