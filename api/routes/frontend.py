import os
from flask import Blueprint, render_template, request

bp_frontend = Blueprint("frontend", __name__)

@bp_frontend.route("/", defaults={"path": ""})
@bp_frontend.route("/<path:path>")
def catch_all(path):
    # No interceptar API
    if path.startswith("api/"):
        return "Not Found", 404
    return render_template("dashboard.html")
