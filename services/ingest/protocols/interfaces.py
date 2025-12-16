import re

_IFACE_KWS = [
    "n1", "n2", "n3", "n4", "n6", "n9", "n11", "n22", "n26", "n32", "s1", "x2", "ng", "e1", "f1"
]

def extract_interfaces(text: str):
    if not text:
        return []
    t = text.lower()
    found = set()
    for kw in _IFACE_KWS:
        if re.search(rf"\b{re.escape(kw)}\b", t):
            found.add(kw.upper())
    return sorted(found)
