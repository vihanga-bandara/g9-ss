"""Original document persistence, ownership and storage paths."""

import datetime as dt
import hashlib
import logging
from pathlib import Path

from sqlalchemy import text
from watermarking_method import is_pdf_bytes
from service_errors import ServiceError


class DocumentService:
    def __init__(self, get_engine, storage_root):
        self.get_engine = get_engine
        self.storage_root = Path(storage_root).resolve()
        self.logger = logging.getLogger(__name__)

    def _sha256_file(self, path: Path):
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _safe_resolve_under_storage(self, p: str, storage_root: Path):
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    def upload_document(self, owner_id, filename, data, name=None):

        if not is_pdf_bytes(data):
            raise ServiceError("file is not a valid PDF", 400)

        fname = filename

        user_dir = self.storage_root / "files" / str(owner_id)
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = name or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        stored_path.write_bytes(data)

        sha_hex = self._sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with self.get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(owner_id),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception:
            raise ServiceError("database error", 503)

        return {
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat()
            if hasattr(row.creation, "isoformat")
            else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }

    def list_documents(self, owner_id):
        try:
            with self.get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(owner_id)},
                ).all()
        except Exception:
            raise ServiceError("database error", 503)

        docs = [
            {
                "id": int(r.id),
                "name": r.name,
                "creation": r.creation.isoformat()
                if hasattr(r.creation, "isoformat")
                else str(r.creation),
                "sha256": r.sha256_hex,
                "size": int(r.size),
            }
            for r in rows
        ]
        return {"documents": docs}

    def find_document(self, owner_id, document_id):
        try:
            with self.get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(owner_id)},
                ).first()
        except Exception:
            raise ServiceError("database error", 503)

        # Don’t leak whether a doc exists for another user
        if not row:
            raise ServiceError("document not found", 404)

        return row

    def resolve_file(self, path):
        try:
            file_path = self._safe_resolve_under_storage(path, self.storage_root)
        except (RuntimeError, ValueError, OSError) as exc:
            raise ServiceError("document path invalid", 500) from exc
        if not file_path.exists():
            raise ServiceError("file missing on disk", 410)
        return file_path

    def get_document(self, owner_id, document_id):
        row = self.find_document(owner_id, document_id)
        return row, self.resolve_file(row.path)

    def delete_document(self, owner_id, document_id):
        doc_id = document_id
        row = self.find_document(owner_id, doc_id)

        # Resolve and delete file (best effort)
        storage_root = Path(self.storage_root)
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = self._safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    self.logger.warning(
                        "Failed to delete file %s for doc id=%s: %s", fp, row.id, e
                    )
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            self.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with self.get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(owner_id)},
                )
        except Exception:
            raise ServiceError("database error", 503)

        return {
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,  # null/omitted if everything was fine
        }
