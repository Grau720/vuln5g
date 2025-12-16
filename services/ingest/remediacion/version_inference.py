import re
from ..versiones.semver_utils import _bump_patch

def _infer_min_safe_from_ranges(versiones: list[str]) -> str | None:
    """
    Intenta deducir una 'versión mínima segura' mirando rangos tipo:
    - '< 1.2.3'  → sugiere '>= 1.2.4'
    - '<= 2.4.59' → sugiere '>= 2.4.60'
    """
    candidates = []
    for v in versiones or []:
        v = v.strip()

        # "< 1.2.3", "<= 1.2.3"
        if v.startswith("<") or v.startswith("<="):
            raw = v.lstrip("<=").strip()
            bump = _bump_patch(raw)
            if bump:
                candidates.append(bump)

        # Rangos tipo ">= X y < Y"
        m = re.search(r"<\s*([0-9][\w\.\-]*)", v)
        if m:
            raw = m.group(1)
            bump = _bump_patch(raw)
            candidates.append(bump or raw)

    candidates = [c for c in candidates if c]
    if not candidates:
        return None

    candidates.sort(key=lambda x: (len(x), x))
    return candidates[-1]

