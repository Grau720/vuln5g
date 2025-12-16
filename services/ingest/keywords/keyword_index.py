def build_keyword_index(cve_id, nombre, descripcion, tipo, etiquetas, protocolo, servicio, puertos):
    words = set()

    def add(x):
        if not x:
            return
        if isinstance(x, list):
            for v in x:
                add(v)
        else:
            s = str(x).lower().strip()
            if len(s) > 1:
                words.add(s)

    add(cve_id)
    add(nombre)
    add(descripcion)
    add(tipo)
    add(etiquetas)
    add(protocolo)
    add(servicio)

    for p in puertos:
        add(str(p))

    return sorted(words)

