"""Flask application setup and HTTP adapters for the application services."""

import os
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request, send_file
from sqlalchemy import create_engine, text

from auth_service import AuthService
from document_service import DocumentService
from watermark_service import WatermarkService
from service_errors import ServiceError


def create_app():
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
    documents = DocumentService(get_engine, app.config["STORAGE_DIR"])
    watermarks = WatermarkService(get_engine, documents)

    @app.errorhandler(ServiceError)
    def service_error(error):
        return jsonify({"error": str(error)}), error.status_code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise ServiceError("Missing or invalid Authorization header", 401)
            g.user = auth_service.validate_token(auth.split(" ", 1)[1].strip())
            return f(*args, **kwargs)

        return wrapper

    def document_id_from_request(document_id, allow_json=False):
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            if not document_id and allow_json and request.is_json:
                document_id = (request.get_json(silent=True) or {}).get("id")
        try:
            return int(document_id)
        except (TypeError, ValueError) as exc:
            raise ServiceError("document id required", 400) from exc

    def pdf_response(file_path, name, cache_control, sha256=None):
        response = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=name if name.lower().endswith(".pdf") else f"{name}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        if isinstance(sha256, str) and sha256:
            response.set_etag(sha256.lower())
        response.headers["Cache-Control"] = cache_control
        return response

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
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

    @app.post("/api/create-user")
    def create_user():
        return jsonify(
            auth_service.create_user(request.get_json(silent=True) or {})
        ), 201

    @app.post("/api/login")
    def login():
        return jsonify(auth_service.login(request.get_json(silent=True) or {})), 200

    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            raise ServiceError("file is required (multipart/form-data)", 400)
        file = request.files["file"]
        if not file or file.filename == "":
            raise ServiceError("empty filename", 400)
        result = documents.upload_document(
            g.user["id"], file.filename, file.read(), request.form.get("name")
        )
        return jsonify(result), 201

    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        return jsonify(documents.list_documents(g.user["id"])), 200

    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        doc_id = document_id_from_request(document_id)
        return jsonify(watermarks.list_versions(g.user["id"], doc_id)), 200

    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        return jsonify(watermarks.list_all_versions(g.user["id"])), 200

    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        doc_id = document_id_from_request(document_id)
        row, path = documents.get_document(g.user["id"], doc_id)
        return pdf_response(
            path, row.name, "private, max-age=0, must-revalidate", row.sha256_hex
        )

    @app.get("/api/get-version/<link>")
    def get_version(link: str):

        row, path = watermarks.get_version(link)
        return pdf_response(path, row.link, "private, max-age=0")

    @app.route(
        "/api/delete-document", methods=["DELETE", "POST"]
    )  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        return jsonify(documents.delete_document(g.user["id"], doc_id)), 200

    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        result = watermarks.create_watermark(
            g.user["id"], doc_id, request.get_json(silent=True) or {}
        )
        return jsonify(result), 201

    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        return jsonify(watermarks.get_watermarking_methods()), 200

    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        result = watermarks.read_watermark(
            g.user["id"], doc_id, request.get_json(silent=True) or {}
        )
        return jsonify(result), 201

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
