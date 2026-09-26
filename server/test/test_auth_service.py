"""Account service tests without Flask or a live database."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from auth_service import AuthService
from service_errors import ServiceError


@pytest.fixture
def account():
    connection = MagicMock()
    engine = MagicMock()
    engine.begin.return_value.__enter__.return_value = connection
    engine.connect.return_value.__enter__.return_value = connection
    get_engine = Mock(return_value=engine)
    return AuthService(get_engine, "test-key", 3600), get_engine, connection


def test_create_user_normalizes_identity_and_hashes_password(account):
    service, _, connection = account
    connection.execute.return_value.lastrowid = 7
    connection.execute.return_value.one.return_value = SimpleNamespace(
        id=7, email="alice@example.test", login="alice"
    )

    result = service.create_user(
        {"email": " ALICE@example.test ", "login": " alice ", "password": "example"}
    )

    parameters = connection.execute.call_args_list[0].args[1]
    assert parameters["email"] == "alice@example.test"
    assert parameters["login"] == "alice"
    assert parameters["hpw"] != "example"
    assert check_password_hash(parameters["hpw"], "example")
    assert result == {"id": 7, "email": "alice@example.test", "login": "alice"}


@pytest.mark.parametrize("field", ["email", "login", "password"])
@pytest.mark.parametrize("value", [None, ""])
def test_create_user_rejects_missing_fields_before_database(account, field, value):
    service, get_engine, _ = account
    payload = {"email": "alice@example.test", "login": "alice", "password": "example"}
    payload[field] = value

    with pytest.raises(ServiceError) as failure:
        service.create_user(payload)

    assert failure.value.status_code == 400
    get_engine.assert_not_called()


def test_duplicate_user_returns_conflict(account):
    service, _, connection = account
    connection.execute.side_effect = IntegrityError(
        "INSERT", {}, Exception("duplicate")
    )

    with pytest.raises(ServiceError) as failure:
        service.create_user(
            {"email": "alice@example.test", "login": "alice", "password": "example"}
        )

    assert failure.value.status_code == 409
    assert str(failure.value) == "email or login already exists"


@pytest.mark.parametrize("user_exists", [False, True])
def test_login_uses_same_error_for_unknown_user_and_wrong_password(
    account, user_exists
):
    service, _, connection = account
    connection.execute.return_value.first.return_value = (
        SimpleNamespace(hpassword=generate_password_hash("correct"))
        if user_exists else None
    )

    with pytest.raises(ServiceError) as failure:
        service.login({"email": "alice@example.test", "password": "wrong"})

    assert failure.value.status_code == 401
    assert str(failure.value) == "invalid credentials"


@pytest.mark.parametrize(
    "payload", [{}, {"email": "alice@example.test"}, {"password": "x"}]
)
def test_login_rejects_missing_credentials_before_database(account, payload):
    service, get_engine, _ = account
    with pytest.raises(ServiceError) as failure:
        service.login(payload)
    assert failure.value.status_code == 400
    get_engine.assert_not_called()


@pytest.mark.parametrize("operation", ["create_user", "login"])
def test_database_failure_is_reported_without_internal_details(account, operation):
    service, _, connection = account
    connection.execute.side_effect = RuntimeError("private database details")
    with pytest.raises(ServiceError) as failure:
        getattr(service, operation)(
            {"email": "alice@example.test", "login": "alice", "password": "example"}
        )
    assert failure.value.status_code == 503
    assert str(failure.value) == "database error"
