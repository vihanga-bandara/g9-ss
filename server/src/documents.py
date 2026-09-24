"""Document routes and the request helpers the watermark routes share."""

from collections.abc import Callable

from flask import Blueprint, g, jsonify, request, send_file

from document_service import DocumentService
from service_errors import ServiceError


def document_id_from_request(document_id, allow_json=False):
    if document_id is None or (allow_json and not document_id):
        document_id = request.args.get("id") or request.args.get("documentid")
        if not document_id and allow_json:
            document_id = request.is_json and (request.get_json(silent=True) or {}).get(
                "id"
            )
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


def create_blueprint(documents: DocumentService, require_auth: Callable) -> Blueprint:
    bp = Blueprint("documents", __name__)

    @bp.post("/api/upload-document")
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

    @bp.get("/api/list-documents")
    @require_auth
    def list_documents():
        return jsonify(documents.list_documents(g.user["id"])), 200

    @bp.get("/api/get-document")
    @bp.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        doc_id = document_id_from_request(document_id)
        row = documents.find_document(g.user["id"], doc_id)
        path = documents.check_stored_file(row.path)
        return pdf_response(
            path, row.name, "private, max-age=0, must-revalidate", row.sha256_hex
        )

    @bp.route(
        "/api/delete-document", methods=["DELETE", "POST"]
    )  # POST supported for convenience
    @bp.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        return jsonify(documents.delete_document(g.user["id"], doc_id)), 200

    return bp
