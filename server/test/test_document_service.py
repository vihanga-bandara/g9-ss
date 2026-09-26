"""Document service tests using temporary files and a mocked database."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from document_service import DocumentService
from service_errors import ServiceError


@pytest.fixture
def documents(tmp_path):
    connection = MagicMock()
    engine = MagicMock()
    engine.connect.return_value.__enter__.return_value = connection
    engine.begin.return_value.__enter__.return_value = connection
    get_engine = Mock(return_value=engine)
    service = DocumentService(get_engine, tmp_path / "storage", Mock())
    service.storage_root.mkdir()
    return service, get_engine, connection


def test_invalid_pdf_is_rejected_without_writes(documents, monkeypatch):
    service, get_engine, _ = documents
    validator = Mock(return_value=False)
    monkeypatch.setattr("document_service.is_pdf_bytes", validator)

    with pytest.raises(ServiceError) as failure:
        service.upload_document(1, "report.pdf", b"not a PDF")

    assert failure.value.status_code == 400
    validator.assert_called_once_with(b"not a PDF")
    get_engine.assert_not_called()
    assert list(service.storage_root.iterdir()) == []


def test_get_document_returns_owned_row_and_file(documents):
    service, _, connection = documents
    path = service.storage_root / "report.pdf"
    path.write_bytes(b"original")
    row = SimpleNamespace(id=7, path=str(path))
    connection.execute.return_value.first.return_value = row

    assert service.get_document(1, 7) == (row, path)
    statement, parameters = connection.execute.call_args.args
    assert "where id = :id and ownerid = :uid" in " ".join(
        str(statement).lower().split()
    )
    assert parameters == {"id": 7, "uid": 1}


@pytest.mark.parametrize("resolver", ["resolve_file", "check_stored_file"])
def test_symlink_cannot_expose_file_outside_storage(documents, tmp_path, resolver):
    service, _, _ = documents
    outside = tmp_path / "private.pdf"
    outside.write_bytes(b"private")
    link = service.storage_root / "link.pdf"
    link.symlink_to(outside)

    with pytest.raises(ServiceError) as failure:
        getattr(service, resolver)(str(link))

    assert failure.value.status_code == 500
    assert outside.read_bytes() == b"private"


@pytest.mark.parametrize("file_exists", [False, True])
def test_delete_document_reports_file_outcome_and_deletes_owned_row(
    documents, file_exists
):
    service, _, connection = documents
    path = service.storage_root / "report.pdf"
    if file_exists:
        path.write_bytes(b"original")
    connection.execute.return_value.first.return_value = SimpleNamespace(
        id=7, path=str(path)
    )

    result = service.delete_document(1, 7)

    assert result == {
        "deleted": True, "id": 7, "file_deleted": file_exists,
        "file_missing": not file_exists, "note": None,
    }
    assert not path.exists()
    statement, parameters = connection.execute.call_args.args
    assert "delete from documents where id = :id and ownerid = :uid" in " ".join(
        str(statement).lower().split()
    )
    assert parameters == {"id": 7, "uid": 1}


def test_delete_document_never_removes_outside_file(documents, tmp_path):
    service, _, connection = documents
    outside = tmp_path / "private.pdf"
    outside.write_bytes(b"private")
    connection.execute.return_value.first.return_value = SimpleNamespace(
        id=7, path=str(outside)
    )

    result = service.delete_document(1, 7)

    assert outside.read_bytes() == b"private"
    assert result["file_deleted"] is False
    assert result["file_missing"] is False
    assert result["note"]


def test_delete_document_reports_unlink_failure(documents, monkeypatch):
    service, _, connection = documents
    path = service.storage_root / "report.pdf"
    path.write_bytes(b"original")
    connection.execute.return_value.first.return_value = SimpleNamespace(
        id=7, path=str(path)
    )
    monkeypatch.setattr(Path, "unlink", Mock(side_effect=PermissionError("denied")))

    result = service.delete_document(1, 7)

    assert result["deleted"] is True
    assert result["file_deleted"] is False
    assert result["file_missing"] is False
    assert "failed to delete file" in result["note"]
    assert path.read_bytes() == b"original"


def test_empty_document_list(documents):
    service, _, connection = documents
    connection.execute.return_value.all.return_value = []
    assert service.list_documents(1) == {"documents": []}
    statement, parameters = connection.execute.call_args.args
    assert "where ownerid = :uid" in " ".join(str(statement).lower().split())
    assert parameters == {"uid": 1}


@pytest.mark.parametrize(
    "operation,args", [("list_documents", (1,)), ("find_document", (1, 7))]
)
def test_document_database_failure_returns_service_error(documents, operation, args):
    service, _, connection = documents
    connection.execute.side_effect = RuntimeError("database unavailable")
    with pytest.raises(ServiceError) as failure:
        getattr(service, operation)(*args)
    assert failure.value.status_code == 503
    assert str(failure.value) == "database error"
