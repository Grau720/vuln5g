import os
from pymongo import MongoClient, ASCENDING, DESCENDING

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27017))
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_DB = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH_DB = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

def main():
    uri = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/?authSource={MONGO_AUTH_DB}"
    col = MongoClient(uri)[MONGO_DB][MONGO_COLLECTION]

    print("Creando índices… (idempotente)")

    col.create_index("cve_id", unique=True)
    col.create_index([("fecha_publicacion_date", DESCENDING)])
    col.create_index([("cvssv3.score", DESCENDING)])
    col.create_index([("tipo", ASCENDING)])
    col.create_index([("etiquetas", ASCENDING)])  # multikey
    col.create_index([("infraestructura_5g_afectada", ASCENDING)])  # multikey

    # Compound útiles
    col.create_index([("fecha_publicacion_date", DESCENDING), ("cvssv3.score", DESCENDING)])
    col.create_index([("tipo", ASCENDING), ("cvssv3.score", DESCENDING)])

    # Texto (opcional para búsqueda libre por 'q' sin prefijo)
    col.create_index([("nombre", "text"), ("descripcion_general", "text")])

    print("Listo.")

if __name__ == "__main__":
    main()
