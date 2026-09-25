import secrets
from dataclasses import dataclass
from pathlib import Path

from flask import Blueprint, jsonify, request
from rmap import RMAPError, RMAPServer

from service_errors import ServiceError
from watermark_service import WatermarkService

# Decryptable messages with a missing or mistyped field escape the library as these.
BAD_MESSAGE_ERRORS = (RMAPError, KeyError, TypeError, ValueError)


@dataclass(frozen=True)
class RmapSettings:
    """Document handed out over RMAP, its owner, and how each copy is watermarked."""

    owner_id: int
    document_id: int
    method: str
    watermark_key: str


def load_rmap_server(keys_dir: Path, passphrase: str | None) -> RMAPServer:
    rmap_server = RMAPServer(
        server_public_key_path=keys_dir / "server_pub.asc",
        server_private_key_path=keys_dir / "server_priv.asc",
        passphrase=passphrase,
    )
    rmap_server.loadIdentities(keys_dir / "clients")
    return rmap_server


def create_blueprint(
    rmap_server: RMAPServer, watermarks: WatermarkService, settings: RmapSettings
) -> Blueprint:
    bp = Blueprint("rmap", __name__)

    @bp.post("/api/rmap-initiate")
    def rmap_initiate():
        try:
            _, response = rmap_server.receiveMsg1(request.get_json(silent=True) or {})
        except BAD_MESSAGE_ERRORS:
            raise ServiceError("invalid RMAP message", 400)
        return jsonify(response), 200

    @bp.post("/api/rmap-get-link")
    def rmap_get_link():
        try:
            identity, link, response = rmap_server.receiveMsg2(
                request.get_json(silent=True) or {}
            )
        except BAD_MESSAGE_ERRORS:
            raise ServiceError("invalid RMAP message", 400)
        watermarks.create_watermark(
            settings.owner_id,
            settings.document_id,
            {
                "method": settings.method,
                "intended_for": identity,
                "secret": secrets.token_hex(16),
                "key": settings.watermark_key,
            },
            link=link,
        )
        return jsonify(response), 200

    return bp
