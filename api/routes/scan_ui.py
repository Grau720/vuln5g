# routes/scan_ui.py
from flask import Blueprint, render_template

bp_scan = Blueprint("scan_ui", __name__)

@bp_scan.route("/scan")
def scan_panel():
    # Renderiza la misma plantilla que el dashboard React
    return render_template("dashboard.html")
