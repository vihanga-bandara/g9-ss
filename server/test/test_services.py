"""Service contracts work without a Flask application or request context."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash

from auth_service import AuthService
from document_service import DocumentService
from service_errors import ServiceError
from watermark_service import WatermarkService


def test_login_token_is_compatible_with_existing_tokens():
    connection = Mock()
    connection.execute.return_value.first.return_value = SimpleNamespace(
        id=1,
        login="alice",
        email="alice@example.test",
        hpassword=generate_password_hash("example-password"),
    )
    engine = Mock()
    engine.connect.return_value.__enter__ = Mock(return_value=connection)
    engine.connect.return_value.__exit__ = Mock(return_value=False)
    auth = AuthService(lambda: engine, "test-key", 3600)
    result = auth.login({"email": "alice@example.test", "password": "example-password"})
    existing_serializer = URLSafeTimedSerializer("test-key", salt="tatou-auth")
    assert existing_serializer.loads(result["token"])["uid"] == 1
    assert auth.validate_token(result["token"]) == {
        "id": 1,
        "login": "alice",
        "email": "alice@example.test",
    }
    assert result["expires_in"] == 3600


@pytest.mark.parametrize("expired", [False, True])
def test_token_failures_keep_their_error_contract(expired):
    auth = AuthService(Mock(), "test-key", -1 if expired else 3600)
    token = (
        auth.serializer.dumps({"uid": 1, "login": "alice"}) if expired else "invalid"
    )
    with pytest.raises(ServiceError) as failure:
        auth.validate_token(token)
    assert failure.value.status_code == 401
    assert str(failure.value) == ("Token expired" if expired else "Invalid token")


def test_document_paths_resolve_under_storage(tmp_path):
    documents = DocumentService(Mock(), tmp_path)
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"example")
    assert documents.resolve_file("report.pdf") == pdf
    assert documents.resolve_file(str(pdf)) == pdf
    for unsafe in ["../outside.pdf", str(tmp_path.parent / "outside.pdf")]:
        with pytest.raises(ServiceError) as failure:
            documents.resolve_file(unsafe)
        assert failure.value.status_code == 500
    with pytest.raises(ServiceError) as failure:
        documents.resolve_file("missing.pdf")
    assert failure.value.status_code == 410


@pytest.mark.parametrize(
    "applicable,output,message,code",
    [
        (False, b"", "watermarking method not applicable", 400),
        (True, b"", "watermarking produced no output", 500),
    ],
)
def test_watermark_failures_preserve_messages(
    monkeypatch, tmp_path, applicable, output, message, code
):
    documents = Mock()
    documents.get_document.return_value = (
        SimpleNamespace(name="report"),
        tmp_path / "report.pdf",
    )
    engine = Mock()
    service = WatermarkService(engine, documents)
    monkeypatch.setattr(
        "watermark_service.WMUtils.is_watermarking_applicable", lambda **kw: applicable
    )
    monkeypatch.setattr(
        "watermark_service.WMUtils.apply_watermark", lambda **kw: output
    )
    with pytest.raises(ServiceError) as failure:
        service.create_watermark(
            1,
            7,
            {
                "method": "toy-eof",
                "intended_for": "alice",
                "secret": "secret",
                "key": "key",
            },
        )
    assert str(failure.value) == message
    assert failure.value.status_code == code
    engine.assert_not_called()
