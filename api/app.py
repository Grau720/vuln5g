from flask import Flask
from flask_pymongo import PyMongo
import os
import logging
import sys
from pathlib import Path

# Asegurar que /app está en sys.path
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

# Blueprints - AHORA SÍ encontrará 'services'
from routes import cves, cves_api, scan_ui, scan_api
from routes.frontend import bp_frontend
from taxii.routes import bp_taxii
from routes.ia_api import bp_ia
from routes.rules_api import bp_rules
from routes.alerts_api import bp_alerts
from routes.assets_api import bp_assets
from utils.db import ensure_indexes

def create_app():
    app = Flask(__name__)
    
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    
    app.config["MONGO_URI"] = (
        f"mongodb://{os.getenv('MONGO_USER')}:{os.getenv('MONGO_PASS')}@"
        f"{os.getenv('MONGO_HOST')}:{os.getenv('MONGO_PORT')}/"
        f"{os.getenv('MONGO_DB')}?authSource={os.getenv('MONGO_AUTH_DB')}"
    )
    
    mongo = PyMongo(app)
    app.mongo = mongo
    
    with app.app_context():
        ensure_indexes(app.mongo.db)
    
    app.register_blueprint(cves.bp)
    app.register_blueprint(cves_api.bp_api)
    app.register_blueprint(bp_taxii, url_prefix="/taxii2")
    # app.register_blueprint(scan_ui.bp_scan)
    # app.register_blueprint(scan_api.scan_bp)
    app.register_blueprint(bp_ia)
    app.register_blueprint(bp_frontend)
    app.register_blueprint(bp_rules)
    app.register_blueprint(bp_alerts)
    app.register_blueprint(bp_assets)

    print("\n=== Rutas registradas ===")
    for rule in app.url_map.iter_rules():
        methods = ",".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
        print(f"{methods:10} {rule.rule}")
    print("=========================\n")
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", debug=True, port=5000)