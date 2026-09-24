"""
if we think as Alice and Bob, two users, each with thier own documents, 
each of the should should be able to access their own documents, but not each other's.
Anonymous users cannot access originals or private metadata.
Repeat checks for path, query-string, and JSON ID variants where supported.
"""

import datetime as dt
import importlib
import io
from pathlib import Path
from unittest.mock import Mock

import pytest
from itsdangerous import URLSafeTimedSerializer

VALID_PDF = Path(__file__).parent / "valid_test.pdf"


@pytest.fixture
def app(monkeypatch, tmp_path):
    # Configure temporary storage before importing server because importing
    # it also calls create_app().
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "authorization-test-key")

    server = importlib.import_module("server")
    app = server.create_app()
    app.config["TESTING"] = True

    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(app):
    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "alice",
        "email": "alice@example.test",
    })

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def database(app):
    connection = Mock()
    engine = Mock()

    engine.connect.return_value.__enter__ = Mock(
        return_value=connection
    )
    engine.connect.return_value.__exit__ = Mock(
        return_value=False
    )

    # Simulate no document matching both document ID and owner ID.
    connection.execute.return_value.first.return_value = None
    app.config["_ENGINE"] = engine

    return connection


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        (
            "/api/create-watermark/101",
            {
                "method": "toy-eof",
                "secret": "test-secret",
                "key": "test-key",
                "intended_for": "recipient@example.test",
            },
        ),
        (
            "/api/read-watermark/101",
            {
                "method": "toy-eof",
                "key": "test-key",
            },
        ),
    ],
)
def test_document_lookup_enforces_owner(
    client,
    auth_headers,
    database,
    endpoint,
    payload,
):
    response = client.post(
        endpoint,
        json=payload,
        headers=auth_headers,
    )

    database.execute.assert_called_once()

    statement, parameters = database.execute.call_args.args
    sql = " ".join(str(statement).lower().split())

    assert "where id = :id and ownerid = :uid" in sql
    assert parameters == {"id": 101, "uid": 1}

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "document not found"
    }


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/create-watermark/101",
        "/api/read-watermark/101",
    ],
)
def test_missing_authentication_rejected(
    client,
    database,
    endpoint,
):
    response = client.post(endpoint, json={})

    assert response.status_code == 401
    database.execute.assert_not_called()


def test_request_cannot_override_authenticated_owner(
    client,
    auth_headers,
    database,
):
    response = client.post(
        "/api/read-watermark/101",
        headers=auth_headers,
        json={
            "method": "toy-eof",
            "key": "test-key",
            "uid": 99,
            "ownerid": 99,
        },
    )

    _, parameters = database.execute.call_args.args

    # Ownership must come from the verified token.
    assert parameters["uid"] == 1
    assert response.status_code == 404

@pytest.fixture
def upload_database(app):
    """Engine that accepts the insert and answers the read-back."""
    connection = Mock()
    engine = Mock()
    engine.begin.return_value.__enter__ = Mock(return_value=connection)
    engine.begin.return_value.__exit__ = Mock(return_value=False)

    stored = Mock()
    stored.id = 7
    stored.name = "report"
    stored.creation = dt.datetime(2026, 1, 1)
    stored.sha256_hex = "ab" * 32
    stored.size = VALID_PDF.stat().st_size
    connection.execute.return_value.one.return_value = stored
    connection.execute.return_value.scalar.return_value = 7

    app.config["_ENGINE"] = engine
    return connection


def test_upload_stores_file_under_owner_id(client, auth_headers, app, upload_database):
    response = client.post(
        "/api/upload-document",
        data={
            "file": (io.BytesIO(VALID_PDF.read_bytes()), "report.pdf"),
            "name": "report",
        },
        headers=auth_headers,
        content_type="multipart/form-data",
    )

    assert response.status_code == 201

    files_root = Path(app.config["STORAGE_DIR"]) / "files"
    # The token carries uid 1 and login "alice"; the path must use the uid.
    assert [d.name for d in files_root.iterdir()] == ["1"]
    assert len(list((files_root / "1").glob("*.pdf"))) == 1


@pytest.fixture
def watermark_database(app, tmp_path):
    """Engine that finds the document but fails the version insert."""
    source = tmp_path / "files" / "1" / "report.pdf"
    source.parent.mkdir(parents=True)
    source.write_bytes(VALID_PDF.read_bytes())

    document = Mock()
    document.id = 7
    document.name = "report"
    document.path = str(source)

    connection = Mock()
    connection.execute.return_value.first.return_value = document

    engine = Mock()
    engine.connect.return_value.__enter__ = Mock(return_value=connection)
    engine.connect.return_value.__exit__ = Mock(return_value=False)
    engine.begin.side_effect = RuntimeError("insert failed")

    app.config["_ENGINE"] = engine
    return source


def test_failed_version_insert_leaves_existing_file_intact(
    client,
    auth_headers,
    watermark_database,
):
    watermarks = watermark_database.parent / "watermarks"
    existing = watermarks / "report__recipientexample.test.pdf"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"watermark that already belongs to someone")

    response = client.post(
        "/api/create-watermark/7",
        headers=auth_headers,
        json={
            "method": "toy-eof",
            "intended_for": "recipient@example.test",
            "secret": "test-secret",
            "key": "test-key",
        },
    )

    assert response.status_code == 503
    assert existing.read_bytes() == b"watermark that already belongs to someone"
    assert list(watermarks.iterdir()) == [existing]


@pytest.fixture
def versions_database(app, watermark_database):
    """Same document as watermark_database, but every version insert succeeds."""
    inserts = Mock()
    inserts.execute.return_value.scalar.return_value = 1
    engine = app.config["_ENGINE"]
    engine.begin.side_effect = None
    engine.begin.return_value.__enter__ = Mock(return_value=inserts)
    engine.begin.return_value.__exit__ = Mock(return_value=False)
    return watermark_database


def test_versions_for_one_recipient_get_their_own_link_and_file(
    client,
    auth_headers,
    versions_database,
):
    payload = {
        "method": "toy-eof",
        "intended_for": "recipient@example.test",
        "secret": "test-secret",
        "key": "test-key",
    }
    responses = [
        client.post("/api/create-watermark/7", headers=auth_headers, json=payload)
        for _ in range(2)
    ]
    links = [response.get_json()["link"] for response in responses]
    file_names = sorted(
        path.name for path in (versions_database.parent / "watermarks").iterdir()
    )

    assert [response.status_code for response in responses] == [201, 201]
    assert links[0] != links[1]
    assert file_names == sorted(f"{link}.pdf" for link in links)
