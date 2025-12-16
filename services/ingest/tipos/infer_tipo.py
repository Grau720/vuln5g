import re

def _norm(t: str) -> str:
    return (t or "").lower().strip()

def inferir_tipo(texto: str) -> str:
    """
    Clasificador de vulnerabilidades con 6 fases mejoradas:
    1. Tipos MUY ESPECÍFICOS (alta confianza)
    2. Análisis contextual con regex patterns MEJORADOS
    3. Co-ocurrencia de keywords
    4. Análisis de verbos + sustantivos
    5. Tipos adicionales con contexto
    6. Fallback a "Sin clasificar"
    
    MEJORAS:
    - Más patrones para Control de acceso y Validación
    - Mejor detección de configuraciones incorrectas
    - Filtros más estrictos para evitar falsos positivos
    """
    if not texto:
        return "Sin clasificar"
    
    t = _norm(texto)
    
    # =========================================================================
    # FASE 1: TIPOS MUY ESPECÍFICOS (mayor confianza)
    # =========================================================================
    
    # --- RCE: Requiere evidencia FUERTE ---
    rce_strong = [
        "remote code execution", "execute arbitrary code", 
        "arbitrary code execution", "rce"
    ]
    
    if any(k in t for k in rce_strong):
        return "Ejecución remota"

    access_control_strong = [
        "improper authorization", "unauthorized access",
        "access control", "insufficient authorization",
        "missing authorization", "unauthenticated access"
    ]

    if any(k in t for k in access_control_strong):
        return "Control de acceso incorrecto"
    
    # RCE contextual: "code execution" + contexto remoto
    if "code execution" in t:
        remote_context = ["remote", "attacker", "network", "unauthenticated", "remotely"]
        if any(ctx in t for ctx in remote_context):
            return "Ejecución remota"
    
    # --- Inyección SQL ---
    if "sql injection" in t or "sqli" in t:
        return "Inyección SQL"
    
    # --- Inyección de Comandos/Código (separar claramente) ---
    if any(k in t for k in ["command injection", "shell injection", "os command injection"]):
        return "Inyección de comandos/código"
    
    if "code injection" in t and "sql" not in t:
        return "Inyección de comandos/código"
    
    # --- XSS ---
    if "cross-site scripting" in t or (t.count("xss") > 0 and "xss" in t.split()):
        return "Cross-Site Scripting"
    
    # --- CSRF ---
    if "csrf" in t or "cross-site request forgery" in t:
        return "Cross-Site Request Forgery"
    
    # --- Path Traversal ---
    if any(k in t for k in ["path traversal", "directory traversal"]):
        return "Traversal de ruta"
    
    if "../" in t or "file inclusion" in t or "local file inclusion" in t:
        return "Traversal de ruta"
    
    # --- SSRF ---
    if "ssrf" in t or "server-side request forgery" in t:
        return "SSRF"
    
    # --- XXE ---
    if "xxe" in t or "xml external entity" in t:
        return "XXE"
    
    # =========================================================================
    # FASE 2: ANÁLISIS CONTEXTUAL CON REGEX PATTERNS (MEJORADO)
    # =========================================================================
    
    action_patterns = {
        "Ejecución remota": [
            (r"allows?\s+(?:remote\s+)?(?:unauthenticated\s+)?attackers?\s+to\s+execute\s+(?:arbitrary\s+)?(?:code|commands?)", "high"),
            (r"(?:can|could)\s+execute\s+(?:arbitrary\s+)?(?:code|commands?)", "medium"),
            (r"leads?\s+to\s+(?:remote\s+)?code\s+execution", "medium"),
            (r"results?\s+in\s+(?:remote\s+)?code\s+execution", "medium"),
            (r"enable(?:s)?\s+(?:remote\s+)?code\s+execution", "medium"),
        ],
        "Escalada de privilegios": [
            (r"allows?\s+(?:local\s+)?users?\s+to\s+(?:gain|obtain|elevate)\s+privileges?", "high"),
            (r"escalat(?:e|ion)\s+(?:of\s+)?privileges?", "high"),
            (r"(?:become|gain)\s+(?:root|administrator|superuser)", "high"),
            (r"allows?\s+local\s+users?\s+to\s+(?:execute|run)", "medium"),
            (r"gain(?:s)?\s+(?:elevated|higher|root)\s+privileges?", "high"),
        ],
        "Divulgación de información": [
            (r"allows?\s+(?:remote\s+)?attackers?\s+to\s+(?:read|obtain|access|view)\s+sensitive", "high"),
            (r"disclos(?:e|ure)\s+(?:of\s+)?(?:sensitive\s+)?information", "high"),
            (r"leak(?:s|age)?\s+(?:kernel\s+)?memory", "high"),
            (r"exposes?\s+sensitive\s+(?:data|information|files?)", "high"),
            (r"allows?\s+(?:remote\s+)?attackers?\s+to\s+read\s+(?:arbitrary\s+)?files?", "medium"),
            (r"(?:reveal|expose)(?:s)?\s+(?:sensitive|confidential)", "medium"),
        ],
        "Denegación de servicio": [
            (r"(?:cause|trigger|lead(?:s)?\s+to)\s+(?:a\s+)?(?:denial.of.service|dos\b)", "high"),
            (r"allows?\s+(?:remote\s+)?attackers?\s+to\s+cause\s+(?:a\s+)?(?:crash|dos\b)", "high"),
            (r"results?\s+in\s+(?:a\s+)?(?:crash|denial.of.service)", "high"),
            (r"resource\s+exhaustion", "medium"),
            (r"infinite\s+loop", "medium"),
            (r"consume\s+(?:all|excessive)\s+(?:cpu|memory|resources?)", "medium"),
        ],
        "Control de acceso incorrecto": [
            (r"(?:bypass|circumvent)\s+(?:access\s+)?(?:control|restrictions?|authorization)", "high"),
            (r"allows?\s+unauthenticated\s+(?:users?|attackers?)\s+to", "high"),
            (r"allows?\s+(?:unauthorized|unprivileged)\s+(?:users?|attackers?)", "high"),
            (r"improper\s+(?:access\s+)?control", "medium"),
            (r"missing\s+(?:access\s+)?control", "medium"),
            (r"insufficient\s+(?:access\s+)?control", "medium"),
            (r"(?:permissions?|access)\s+(?:check|validation)\s+(?:missing|insufficient)", "medium"),
            (r"allows?\s+access\s+to\s+(?:restricted|protected)", "medium"),
        ],
        "Bypass de autenticación": [
            (r"(?:bypass|circumvent)\s+authentication", "high"),
            (r"authentication\s+bypass", "high"),
            (r"auth\s+bypass", "high"),
        ],
        "Desbordamiento de memoria": [
            (r"buffer\s+(?:overflow|overrun)", "high"),
            (r"(?:heap|stack)\s+(?:overflow|corruption)", "high"),
            (r"out.of.bounds\s+(?:read|write)", "high"),
            (r"use.after.free", "high"),
            (r"memory\s+corruption", "medium"),
        ],
        "Validación insuficiente": [
            (r"fails?\s+to\s+(?:validate|sanitize|check)\s+(?:input|user\s+input)", "high"),
            (r"improper\s+(?:validation|sanitization)", "high"),
            (r"does\s+not\s+(?:validate|check|sanitize)", "medium"),
            (r"lack\s+of\s+(?:validation|input\s+validation)", "medium"),
            (r"insufficient\s+(?:validation|input\s+validation)", "medium"),
            (r"missing\s+(?:validation|sanitization)", "medium"),
        ],
        "Configuración incorrecta": [
            (r"default\s+(?:password|credential|configuration)", "high"),
            (r"hardcoded\s+(?:password|key|credential)", "high"),
            (r"insecure\s+default", "high"),
            (r"misconfiguration", "medium"),
            (r"insecure\s+configuration", "medium"),
        ],
    }
    
    # Evaluar patrones con sistema de scoring
    scores = {}
    for tipo, patterns in action_patterns.items():
        for pattern, confidence in patterns:
            if re.search(pattern, t, re.IGNORECASE):
                weight = 3 if confidence == "high" else 1
                scores[tipo] = scores.get(tipo, 0) + weight
    
    # Retornar el tipo con mayor score si supera threshold
    if scores:
        best_tipo, best_score = max(scores.items(), key=lambda x: x[1])
        if best_score >= 2:  # Threshold: al menos 2 puntos
            return best_tipo
    
    # =========================================================================
    # FASE 3: CO-OCURRENCIA DE KEYWORDS (keywords que aparecen juntas)
    # =========================================================================
    
    tokens = set(t.split())
    
    keyword_combos = {
        "Ejecución remota": [
            {"execute", "remote"},
            {"run", "arbitrary", "code"},
            {"command", "execution", "remote"},
            {"arbitrary", "code", "execution"},
            {"execute", "arbitrary"},
        ],
        "Escalada de privilegios": [
            {"local", "user", "privileges"},
            {"gain", "root"},
            {"elevate", "permissions"},
            {"local", "privileges", "escalation"},
            {"become", "root"},
        ],
        "Divulgación de información": [
            {"read", "sensitive", "information"},
            {"leak", "memory"},
            {"disclose", "data"},
            {"access", "unauthorized", "files"},
            {"kernel", "memory", "read"},
            {"sensitive", "data", "exposure"},
        ],
        "Denegación de servicio": [
            {"crash", "application"},
            {"hang", "service"},
            {"consume", "resources"},
            {"exhaust", "memory"},
            {"infinite", "loop"},
            {"resource", "exhaustion"},
        ],
        "Inyección de comandos/código": [
            {"inject", "command"},
            {"execute", "shell"},
            {"arbitrary", "input", "execution"},
            {"command", "injection"},
            {"shell", "execution"},
        ],
        "Desbordamiento de memoria": [
            {"buffer", "overflow"},
            {"heap", "overflow"},
            {"stack", "overflow"},
            {"memory", "corruption"},
            {"out-of-bounds", "write"},
        ],
        "Traversal de ruta": [
            {"path", "traversal"},
            {"directory", "traversal"},
            {"file", "inclusion"},
        ],
        "Cross-Site Scripting": [
            {"cross-site", "scripting"},
            {"xss", "vulnerability"},
        ],
        "Inyección SQL": [
            {"sql", "injection"},
        ],
        "Validación insuficiente": [
            {"improper", "validation"},
            {"insufficient", "validation"},
            {"missing", "validation"},
            {"validate", "input"},
        ],
        "Control de acceso incorrecto": [
            {"unauthorized", "access"},
            {"improper", "access", "control"},
            {"bypass", "authorization"},
        ],
    }
    
    for tipo, combos in keyword_combos.items():
        for combo in combos:
            if combo.issubset(tokens):
                return tipo
    
    # =========================================================================
    # FASE 4: TIPOS ESPECÍFICOS CON CONTEXTO ADICIONAL
    # =========================================================================
    
    # --- Escalada de privilegios: requiere contexto claro ---
    priv_esc_strong = [
        "privilege escalation", "gain privileges", 
        "elevate privileges", "escalate privileges"
    ]
    priv_esc_context = ["gain root", "become root", "root access"]
    
    if any(k in t for k in priv_esc_strong + priv_esc_context):
        return "Escalada de privilegios"
    
    # Contexto adicional: local user + privileges/root/admin
    if any(k in t for k in ["local user can", "local users can"]):
        if any(p in t for p in ["privileges", "root", "admin", "superuser"]):
            return "Escalada de privilegios"
    
    # --- Divulgación de información: términos específicos ---
    info_disclosure_strong = [
        "information disclosure", "information leak", 
        "data leak", "sensitive information disclosure",
        "leak sensitive", "expose sensitive"
    ]
    
    memory_leak_strong = [
        "kernel memory", "read kernel memory", "memory disclosure",
        "uninitialized memory", "uninitialised memory",
        "memory leak", "stack leak", "heap leak"
    ]
    
    if any(k in t for k in info_disclosure_strong + memory_leak_strong):
        return "Divulgación de información"
    
    # Contexto: read + sensitive data
    if "read" in t:
        sensitive_targets = [
            "kernel memory", "uninitialized", "sensitive data",
            "sensitive information", "confidential", "private key",
            "password", "credentials"
        ]
        if any(m in t for m in sensitive_targets):
            return "Divulgación de información"
    
    # --- Bypass de autenticación (adicional a FASE 1) ---
    if any(k in t for k in ["bypass authentication", "auth bypass", "without authentication"]):
        return "Bypass de autenticación"
    
    # --- Configuración incorrecta: términos específicos ---
    if any(k in t for k in ["insecure default", "default credential", "hardcoded credential", "hardcoded password"]):
        return "Configuración incorrecta"
    
    if "misconfiguration" in t:
        return "Configuración incorrecta"
    
    # --- Validación insuficiente: NUEVA SECCIÓN ---
    validation_strong = [
        "improper input validation", "insufficient input validation",
        "missing input validation", "inadequate validation",
        "fails to validate", "does not validate", "lack of validation"
    ]
    
    if any(k in t for k in validation_strong):
        return "Validación insuficiente"
    
    # =========================================================================
    # FASE 5: MEMORY CORRUPTION Y DoS (evaluar con cuidado para evitar overlap)
    # =========================================================================
    
    # --- Buffer overflow y memory corruption ---
    overflow_terms = [
        "buffer overflow", "heap overflow", "stack overflow",
        "buffer overrun", "memory corruption", "use after free",
        "uaf", "double free", "use-after-free"
    ]
    
    oob_terms = [
        "out-of-bounds", "out of bounds", "oob",
        "buffer over-read", "write beyond", "invalid write",
        "buffer over-read", "read beyond"
    ]
    
    if any(k in t for k in overflow_terms + oob_terms):
        return "Desbordamiento de memoria"
    
    # --- DoS: evaluar AL FINAL para evitar false positives ---
    dos_strong = [
        "denial of service", "denial-of-service",
        "resource exhaustion", "infinite loop"
    ]
    
    if any(k in t for k in dos_strong):
        return "Denegación de servicio"
    
    # "crash" solo si no es vector de RCE/overflow
    if any(k in t for k in ["crash", "hang", "freeze"]):
        # Verificar que NO sea un crash como parte de exploit más serio
        exclude_context = [
            "execute", "overflow", "memory corruption", 
            "arbitrary code", "escalate", "gain privileges"
        ]
        if not any(k in t for k in exclude_context):
            return "Denegación de servicio"
    
    # =========================================================================
    # FASE 6: CRIPTOGRAFÍA DÉBIL
    # =========================================================================
    
    crypto_weak = [
        "weak cryptography", "weak encryption", "insecure cryptography",
        "use of weak", "weak cipher", "broken cryptography",
        "inadequate encryption"
    ]
    
    if any(k in t for k in crypto_weak):
        return "Criptografía débil"
    
    # =========================================================================
    # RESULTADO FINAL: Sin clasificar
    # =========================================================================
    
    return "Sin clasificar"

def obtener_tipos_multiples(texto: str) -> list[str]:
    """
    Versión mejorada que evita sobre-clasificación.
    Útil para debugging y análisis.
    """
    t = _norm(texto)
    tipos = []

    # === Solo tipos con evidencia FUERTE ===
    
    # RCE
    if any(k in t for k in [
        "remote code execution", "execute arbitrary code", 
        "arbitrary code execution", "rce"
    ]):
        tipos.append("Ejecución remota")

    # Privilege Escalation
    if any(k in t for k in [
        "privilege escalation", "gain privileges", "elevate privileges"
    ]):
        tipos.append("Escalada de privilegios")

    # Information Disclosure
    if any(k in t for k in [
        "information disclosure", "information leak", "data leak",
        "kernel memory", "uninitialized memory"
    ]):
        tipos.append("Divulgación de información")

    # Memory issues
    if any(k in t for k in [
        "buffer overflow", "heap overflow", "stack overflow",
        "out-of-bounds", "memory corruption", "use after free"
    ]):
        tipos.append("Desbordamiento de memoria")

    # Injection attacks
    if "sql injection" in t or "sqli" in t:
        tipos.append("Inyección SQL")

    if any(k in t for k in ["command injection", "code injection", "shell injection"]):
        tipos.append("Inyección de comandos/código")

    # Web attacks
    if "xss" in t or "cross-site scripting" in t:
        tipos.append("Cross-Site Scripting")

    if "csrf" in t or "cross-site request forgery" in t:
        tipos.append("Cross-Site Request Forgery")

    # Path issues
    if any(k in t for k in ["path traversal", "directory traversal", "../"]):
        tipos.append("Traversal de ruta")

    # Other specific types
    if "ssrf" in t or "server-side request forgery" in t:
        tipos.append("SSRF")

    if "xxe" in t or "xml external entity" in t:
        tipos.append("XXE")

    if any(k in t for k in ["authentication bypass", "bypass authentication"]):
        tipos.append("Bypass de autenticación")

    # DoS - requiere evidencia clara
    if any(k in t for k in [
        "denial of service", "denial-of-service",
        "resource exhaustion", "infinite loop"
    ]):
        tipos.append("Denegación de servicio")

    # REMOVIDO: "Vulnerabilidad genérica"
    # REMOVIDO: checks vagos como "allows", "could allow"

    return tipos if tipos else ["Sin clasificar"]