"""Watermark orchestration tests with mocked algorithms and database."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from service_errors import ServiceError
from watermark_service import WatermarkService


@pytest.fixture
def watermark(tmp_path, monkeypatch):
    connection = MagicMock()
    connection.execute.return_value.scalar.return_value = 9
    engine = MagicMock()
    engine.begin.return_value.__enter__.return_value = connection
    engine.connect.return_value.__enter__.return_value = connection
    get_engine = Mock(return_value=engine)
    documents = Mock()
    source = tmp_path / "report.pdf"
    source.write_bytes(b"original")
    documents.get_document.return_value = (SimpleNamespace(name="report.pdf"), source)
    workers = {
        "is_watermarking_applicable": Mock(return_value=True),
        "apply_watermark": Mock(return_value=b"watermarked PDF"),
        "read_watermark": Mock(return_value="recovered secret"),
    }
    for name, worker in workers.items():
        monkeypatch.setattr(f"watermark_service.WMUtils.{name}", worker)
    return SimpleNamespace(
        service=WatermarkService(get_engine, documents),
        get_engine=get_engine, documents=documents, connection=connection,
        source=source, workers=workers,
    )


@pytest.fixture
def payload():
    return {
        "method": "toy-eof", "intended_for": "alice",
        "secret": "test-secret", "key": "test-key", "position": "1",
    }


@pytest.mark.parametrize(
    "field,value",
    [("method", None), ("intended_for", ""), ("secret", 123), ("key", None)],
)
def test_invalid_create_payload_stops_before_dependencies(
    watermark, payload, field, value
):
    payload[field] = value
    with pytest.raises(ServiceError) as failure:
        watermark.service.create_watermark(1, 7, payload)
    assert failure.value.status_code == 400
    watermark.documents.get_document.assert_not_called()
    watermark.get_engine.assert_not_called()
    for worker in watermark.workers.values():
        worker.assert_not_called()


@pytest.mark.parametrize("operation", ["create_watermark", "read_watermark"])
@pytest.mark.parametrize("document_id", [None, "invalid"])
def test_invalid_document_id_stops_before_lookup(
    watermark, payload, operation, document_id
):
    with pytest.raises(ServiceError) as failure:
        getattr(watermark.service, operation)(1, document_id, payload)
    assert failure.value.status_code == 400
    watermark.documents.get_document.assert_not_called()
    watermark.get_engine.assert_not_called()


def test_create_watermark_saves_algorithm_output_and_version(watermark, payload):
    result = watermark.service.create_watermark(1, 7, payload, link="test-link")

    watermark.documents.get_document.assert_called_once_with(1, 7)
    watermark.workers["apply_watermark"].assert_called_once_with(
        pdf=str(watermark.source), secret="test-secret", key="test-key",
        method="toy-eof", position="1",
    )
    parameters = watermark.connection.execute.call_args_list[0].args[1]
    assert parameters["documentid"] == 7
    assert parameters["link"] == "test-link"
    assert parameters["secret"] == "test-secret"
    assert parameters["method"] == "toy-eof"
    assert Path(parameters["path"]).read_bytes() == b"watermarked PDF"
    assert watermark.source.read_bytes() == b"original"
    assert result == {
        "id": 9, "documentid": 7, "link": "test-link", "intended_for": "alice",
        "method": "toy-eof", "position": "1", "filename": "report__alice.pdf",
        "size": len(b"watermarked PDF"),
    }


@pytest.mark.parametrize(
    "worker,status", [("is_watermarking_applicable", 400), ("apply_watermark", 500)]
)
def test_algorithm_exception_does_not_persist_version(
    watermark, payload, worker, status
):
    watermark.workers[worker].side_effect = ValueError("algorithm failed")
    with pytest.raises(ServiceError) as failure:
        watermark.service.create_watermark(1, 7, payload)
    assert failure.value.status_code == status
    watermark.get_engine.assert_not_called()
    assert list(watermark.source.parent.iterdir()) == [watermark.source]


def test_read_watermark_returns_extracted_secret(watermark, payload):
    result = watermark.service.read_watermark(1, 7, payload)
    watermark.documents.get_document.assert_called_once_with(1, 7)
    watermark.workers["read_watermark"].assert_called_once_with(
        method="toy-eof", pdf=str(watermark.source), key="test-key"
    )
    assert result == {
        "documentid": 7, "secret": "recovered secret",
        "method": "toy-eof", "position": "1",
    }
    watermark.get_engine.assert_not_called()


def test_read_algorithm_failure_returns_bad_request(watermark, payload):
    watermark.workers["read_watermark"].side_effect = ValueError("invalid watermark")
    with pytest.raises(ServiceError) as failure:
        watermark.service.read_watermark(1, 7, payload)
    assert failure.value.status_code == 400
    watermark.get_engine.assert_not_called()


def test_unknown_version_does_not_access_storage(watermark):
    watermark.connection.execute.return_value.first.return_value = None
    with pytest.raises(ServiceError) as failure:
        watermark.service.get_version("unknown")
    assert failure.value.status_code == 404
    watermark.documents.check_stored_file.assert_not_called()


def test_get_version_checks_stored_path(watermark):
    row = SimpleNamespace(path=str(watermark.source))
    watermark.connection.execute.return_value.first.return_value = row
    watermark.documents.check_stored_file.return_value = watermark.source
    assert watermark.service.get_version("test-link") == (row, watermark.source)
    watermark.documents.check_stored_file.assert_called_once_with(row.path)
    assert watermark.connection.execute.call_args.args[1] == {"link": "test-link"}
