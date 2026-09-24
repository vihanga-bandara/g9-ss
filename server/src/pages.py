"""Front-end pages and the health check."""

from collections.abc import Callable

from flask import Blueprint, current_app, jsonify
from sqlalchemy import Engine, text


def create_blueprint(get_engine: Callable[[], Engine]) -> Blueprint:
    bp = Blueprint("pages", __name__)

    @bp.route("/<path:filename>")
    def static_files(filename):
        return current_app.send_static_file(filename)

    @bp.route("/")
    def home():
        return current_app.send_static_file("index.html")

    @bp.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify(
            {"message": "The server is up and running.", "db_connected": db_ok}
        ), 200

    return bp
