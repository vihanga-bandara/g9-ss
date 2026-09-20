"""
if we think as Alice and Bob, two users, each with thier own documents, 
each of the should should be able to access their own documents, but not each other's.
Anonymous users cannot access originals or private metadata.
Repeat checks for path, query-string, and JSON ID variants where supported.
"""

import importlib
from unittest.mock import Mock

import pytest
from itsdangerous import URLSafeTimedSerializer


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