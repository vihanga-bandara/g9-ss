"""Watermark and version routes."""

from collections.abc import Callable

from flask import Blueprint, g, jsonify, request

from documents import document_id_from_request, pdf_response
from watermark_service import WatermarkService


def create_blueprint(watermarks: WatermarkService, require_auth: Callable) -> Blueprint:
    bp = Blueprint("watermarks", __name__)

    @bp.get("/api/list-versions")
    @bp.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        doc_id = document_id_from_request(document_id)
        return jsonify(watermarks.list_versions(g.user["id"], doc_id)), 200

    @bp.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        return jsonify(watermarks.list_all_versions(g.user["id"])), 200

    @bp.get("/api/get-version/<link>")
    def get_version(link: str):

        row, path = watermarks.get_version(link)
        return pdf_response(path, row.link, "private, max-age=0")

    @bp.post("/api/create-watermark")
    @bp.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        result = watermarks.create_watermark(
            g.user["id"], doc_id, request.get_json(silent=True) or {}
        )
        return jsonify(result), 201

    @bp.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        return jsonify(watermarks.get_watermarking_methods()), 200

    @bp.post("/api/read-watermark")
    @bp.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        doc_id = document_id_from_request(document_id, allow_json=True)
        result = watermarks.read_watermark(
            g.user["id"], doc_id, request.get_json(silent=True) or {}
        )
        return jsonify(result), 201

    return bp
