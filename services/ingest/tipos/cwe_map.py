CWE_TO_TIPO = {
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "Inyección SQL",
    "CWE-20": "Validación insuficiente",
    "CWE-22": "Traversal de ruta",
    "CWE-23": "Traversal de ruta",
    "CWE-73": "Traversal de ruta",
    "CWE-200": "Divulgación de información",
    "CWE-264": "Control de acceso incorrecto",
    "CWE-284": "Control de acceso incorrecto",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-119": "Desbordamiento de memoria",
    "CWE-120": "Desbordamiento de memoria",
    "CWE-125": "Desbordamiento de memoria",
    "CWE-327": "Criptografía débil",
    "CWE-328": "Criptografía débil",
    "CWE-329": "Criptografía débil",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-434": "Traversal de ruta",
    "CWE-611": "XML External Entity",
}

def inferir_tipo_por_cwe(cve: dict) -> str | None:
    """
    Intenta inferir el tipo a partir de los CWE de NVD.
    """
    weaknesses = cve.get("weaknesses") or []
    for w in weaknesses:
        descs = w.get("description") or []
        for d in descs:
            cwe_val = (d.get("value") or "").strip()
            if cwe_val in CWE_TO_TIPO:
                return CWE_TO_TIPO[cwe_val]
    return None
