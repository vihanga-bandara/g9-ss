"""Flask application setup: configuration, services and blueprints."""

import os
from pathlib import Path

from flask import Flask, jsonify
from sqlalchemy import create_engine

import auth
import documents
import pages
import watermarks
from auth_service import AuthService
from document_service import DocumentService
from watermark_service import WatermarkService
from service_errors import ServiceError


def create_app() -> Flask:
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(
        os.environ.get("STORAGE_DIR", "./storage")
    ).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    auth_service = AuthService(
        get_engine, app.config["SECRET_KEY"], app.config["TOKEN_TTL_SECONDS"]
    )
    document_service = DocumentService(
        get_engine, app.config["STORAGE_DIR"], app.logger
    )
    watermark_service = WatermarkService(get_engine, document_service)
    require_auth = auth.make_require_auth(auth_service)

    @app.errorhandler(ServiceError)
    def service_error(error):
        return jsonify({"error": str(error)}), error.status_code

    app.register_blueprint(pages.create_blueprint(get_engine))
    app.register_blueprint(auth.create_blueprint(auth_service))
    app.register_blueprint(documents.create_blueprint(document_service, require_auth))
    app.register_blueprint(watermarks.create_blueprint(watermark_service, require_auth))

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
