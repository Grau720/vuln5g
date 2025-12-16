import os
from pymongo import MongoClient

# Lee credenciales del entorno (.env ya está montado en el contenedor 'vulndb_ingest')
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

    # Backfill con pipeline (MongoDB >= 4.2 — tu 4.4 va perfecto):
    # - fecha_publicacion_date = toDate(fecha_publicacion) si falta
    # - cvssv3.score -> double
    res = col.update_many(
        {},
        [
            {
                "$set": {
                    "fecha_publicacion_date": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": [{"$type": "$fecha_publicacion_date"}, "missing"]},
                                    {"$eq": ["$fecha_publicacion_date", None]},
                                ]
                            },
                            {"$toDate": "$fecha_publicacion"},
                            "$fecha_publicacion_date"
                        ]
                    },
                    "cvssv3": {
                        "$mergeObjects": [
                            "$cvssv3",
                            {"score": {"$toDouble": "$cvssv3.score"}}
                        ]
                    }
                }
            }
        ]
    )
    print(f"Actualizados: {res.modified_count}")

if __name__ == "__main__":
    main()
import os
from pymongo import MongoClient

# Lee credenciales del entorno (.env ya está montado en el contenedor 'vulndb_ingest')
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

    # Backfill con pipeline (MongoDB >= 4.2 — tu 4.4 va perfecto):
    # - fecha_publicacion_date = toDate(fecha_publicacion) si falta
    # - cvssv3.score -> double
    res = col.update_many(
        {},
        [
            {
                "$set": {
                    "fecha_publicacion_date": {
                        "$cond": [
                            {
                                "$or": [
                                    {"$eq": [{"$type": "$fecha_publicacion_date"}, "missing"]},
                                    {"$eq": ["$fecha_publicacion_date", None]},
                                ]
                            },
                            {"$toDate": "$fecha_publicacion"},
                            "$fecha_publicacion_date"
                        ]
                    },
                    "cvssv3": {
                        "$mergeObjects": [
                            "$cvssv3",
                            {"score": {"$toDouble": "$cvssv3.score"}}
                        ]
                    }
                }
            }
        ]
    )
    print(f"Actualizados: {res.modified_count}")

if __name__ == "__main__":
    main()
