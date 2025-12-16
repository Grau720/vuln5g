# perfiles y parámetros comunes para TODO el motor y plugins
PROFILES = {
    "fast": {
        "concurrency": 8,
        "tcp_timeout": 0.5,
        "udp_timeout": 0.4,
        "retries": 0,
        "cidr_host_limit": 64,
    },
    "standard": {
        "concurrency": 16,
        "tcp_timeout": 1.0,
        "udp_timeout": 0.8,
        "retries": 1,
        "cidr_host_limit": 256,
    },
    "exhaustive": {
        "concurrency": 32,
        "tcp_timeout": 2.0,
        "udp_timeout": 1.5,
        "retries": 2,
        "cidr_host_limit": 1024,
    },
}

def get_profile(name: str) -> dict:
    return PROFILES.get(name, PROFILES["standard"])
