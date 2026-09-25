"""Watermark operations and the persisted versions they produce."""

import secrets
from pathlib import Path
from typing import Any

from sqlalchemy import text
from werkzeug.utils import secure_filename
import watermarking_utils as WMUtils
from service_errors import ServiceError


class WatermarkService:
    def __init__(self, get_engine, documents):
        self.get_engine = get_engine
        self.documents = documents

    def list_versions(self, owner_id, document_id):
        try:
            with self.get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Versions v
                        JOIN Documents d ON d.id = v.documentid
                        WHERE d.ownerid = :uid AND d.id = :did
                    """),
                    {"uid": int(owner_id), "did": document_id},
                ).all()
        except Exception:
            raise ServiceError("database error", 503)

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "secret": r.secret,
                "method": r.method,
            }
            for r in rows
        ]
        return {"versions": versions}

    def list_all_versions(self, owner_id):
        try:
            with self.get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Versions v
                        JOIN Documents d ON d.id = v.documentid

                        WHERE d.ownerid = :uid
                    """),
                    {"uid": int(owner_id)},
                ).all()
        except Exception:
            raise ServiceError("database error", 503)

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "method": r.method,
            }
            for r in rows
        ]
        return {"versions": versions}

    def get_version(self, link):
        try:
            with self.get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception:
            raise ServiceError("database error", 503)

        # Don’t leak whether a doc exists for another user
        if not row:
            raise ServiceError("document not found", 404)

        return row, self.documents.check_stored_file(row.path)

    def create_watermark(
        self,
        owner_id: int,
        document_id: int,
        payload: dict[str, Any],
        link: str | None = None,
    ) -> dict[str, object]:
        doc_id = document_id
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            raise ServiceError("document_id (int) is required", 400)
        if (
            not method
            or not intended_for
            or not isinstance(secret, str)
            or not isinstance(key, str)
        ):
            raise ServiceError(
                "method, intended_for, secret, and key are required", 400
            )

        row, file_path = self.documents.get_document(owner_id, doc_id)

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method, pdf=str(file_path), position=position
            )
            if applicable is False:
                raise ServiceError("watermarking method not applicable", 400)
        except ServiceError:
            raise
        except Exception as e:
            raise ServiceError(f"watermark applicability check failed: {e}", 400)

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position,
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                raise ServiceError("watermarking produced no output", 500)
        except ServiceError:
            raise
        except Exception as e:
            raise ServiceError(f"watermarking failed: {e}", 500)

        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        # Random so links can't be guessed; files named after it never collide.
        link_token = link or secrets.token_hex(16)
        dest_path = dest_dir / f"{link_token}.pdf"

        # reserve the row first: a failed insert must not touch an existing file
        try:
            with self.get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path,
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception:
            raise ServiceError("database error", 503)

        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except ServiceError:
            raise
        except Exception as e:
            raise ServiceError(f"failed to write watermarked file: {e}", 500)

        return {
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }

    def get_watermarking_methods(self):
        methods = []

        for m in WMUtils.METHODS:
            methods.append(
                {"name": m, "description": WMUtils.get_method(m).get_usage()}
            )

        return {"methods": methods, "count": len(methods)}

    def read_watermark(self, owner_id, document_id, payload):
        doc_id = document_id
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            raise ServiceError("document_id (int) is required", 400)
        if not method or not isinstance(key, str):
            raise ServiceError("method, and key are required", 400)

        row, file_path = self.documents.get_document(owner_id, doc_id)

        secret = None
        try:
            secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
        except ServiceError:
            raise
        except Exception as e:
            raise ServiceError(f"Error when attempting to read watermark: {e}", 400)
        return {
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position,
        }
