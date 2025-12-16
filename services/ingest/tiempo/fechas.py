from datetime import datetime, timezone

def parse_fecha_publicacion_dt(published: str):
    if not published:
        return None
    s = published.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s[:len(fmt)], fmt)
            return dt.replace(tzinfo=timezone.utc).replace(tzinfo=None)
        except Exception:
            pass
    return None