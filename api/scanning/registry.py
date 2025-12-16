# scanning/registry.py
import os
from typing import Dict, Type, List
from .plugin_base import Plugin
from .plugins.smart_discovery import SmartDiscovery
from .plugins.http2_sba_check import Http2SbaCheck
from .plugins.pfcp_check import PfcpCheck
from .plugins.sip_check import SipCheck
from .plugins.diameter_check import DiameterCheck
from .plugins.discovery_5g import Discovery5G

REGISTRY: Dict[str, Type[Plugin]] = {
    # SmartDiscovery.id: SmartDiscovery,  # ⭐ Nuevo plugin de discovery
    Discovery5G.id: Discovery5G,
    Http2SbaCheck.id: Http2SbaCheck,
    PfcpCheck.id: PfcpCheck,
    DiameterCheck.id: DiameterCheck,
    SipCheck.id: SipCheck,
}

NODE_CAPS = {"ran_probe": os.getenv("ENABLE_RAN","0").lower() in ("1","true","yes")}

def _is_available(pid: str) -> bool:
    if pid == "rogue_gnodeb_detector":
        return NODE_CAPS["ran_probe"]
    return True

def available_plugins() -> List[dict]:
    out = []
    for cls in REGISTRY.values():
        out.append({
            "id": cls.id,
            "component": cls.component,
            "interfaces": cls.interfaces,
            "profile": getattr(cls, "profile", "all"),
            "available": _is_available(cls.id),
        })
    return out