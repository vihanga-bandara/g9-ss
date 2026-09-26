import importlib
from pathlib import Path
from unittest.mock import Mock

import pytest
from rmap import RMAPClient
from rmap.crypto import decrypt_json, encrypt_json
from rmap.keygen import generate_keypair

import watermarking_utils as WMUtils

VALID_PDF = Path(__file__).parent / "valid_test.pdf"
GROUP = "Group_01"
WATERMARK_KEY = "rmap-test-watermark-key"


@pytest.fixture(scope="module")
def server_key():
    return generate_keypair("Group_09", "group09@example.test")


@pytest.fixture(scope="module")
def group_key():
    return generate_keypair(GROUP, "group01@example.test")


@pytest.fixture(scope="module")
def keys_dir(tmp_path_factory, server_key, group_key) -> Path:
    keys_dir = tmp_path_factory.mktemp("keys")
    (keys_dir / "server_priv.asc").write_text(str(server_key))
    (keys_dir / "server_pub.asc").write_text(str(server_key.pubkey))
    (keys_dir / "clients").mkdir()
    (keys_dir / "clients" / f"{GROUP}.asc").write_text(str(group_key.pubkey))
    return keys_dir


@pytest.fixture(scope="module")
def group_key_file(tmp_path_factory, group_key) -> Path:
    path = tmp_path_factory.mktemp("group") / "private.asc"
    path.write_text(str(group_key))
    return path


@pytest.fixture
def app(monkeypatch, tmp_path, keys_dir):
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "rmap-test-key")
    monkeypatch.setenv("RMAP_KEYS_DIR", str(keys_dir))
    monkeypatch.setenv("RMAP_OWNER_ID", "1")
    monkeypatch.setenv("RMAP_DOCUMENT_ID", "7")
    monkeypatch.setenv("RMAP_METHOD", "toy-eof")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", WATERMARK_KEY)

    return importlib.import_module("server").create_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def database(app, tmp_path):
    source = tmp_path / "files" / "1" / "Group_9.pdf"
    source.parent.mkdir(parents=True)
    source.write_bytes(VALID_PDF.read_bytes())

    document = Mock()
    document.id = 7
    document.name = "Group_9"
    document.path = str(source)

    reads = Mock()
    reads.execute.return_value.first.return_value = document
    inserts = Mock()
    inserts.execute.return_value.scalar.return_value = 1

    engine = Mock()
    engine.connect.return_value.__enter__ = Mock(return_value=reads)
    engine.connect.return_value.__exit__ = Mock(return_value=False)
    engine.begin.return_value.__enter__ = Mock(return_value=inserts)
    engine.begin.return_value.__exit__ = Mock(return_value=False)

    app.config["_ENGINE"] = engine
    return inserts


def fetch_link(client, group_key_file: Path, server_public_key: Path) -> str:
    group = RMAPClient(GROUP, group_key_file, server_public_key)
    resp1 = client.post("/api/rmap-initiate", json=group.build_msg1())
    assert resp1.status_code == 200
    group.process_resp1(resp1.get_json())
    resp2 = client.post("/api/rmap-get-link", json=group.build_msg2())
    assert resp2.status_code == 200
    return group.process_resp2(resp2.get_json())


def test_each_handshake_gets_its_own_watermarked_copy(
    client, database, group_key_file, keys_dir, tmp_path
):
    links = [
        fetch_link(client, group_key_file, keys_dir / "server_pub.asc")
        for _ in range(2)
    ]
    versions = [
        call.args[1] for call in database.execute.call_args_list if len(call.args) == 2
    ]
    copies = [tmp_path / "files" / "1" / "watermarks" / f"{link}.pdf" for link in links]

    assert [version["link"] for version in versions] == links
    assert [version["intended_for"] for version in versions] == [GROUP, GROUP]
    assert [version["documentid"] for version in versions] == [7, 7]
    assert versions[0]["secret"] != versions[1]["secret"]
    assert [
        WMUtils.read_watermark("toy-eof", str(copy), WATERMARK_KEY) for copy in copies
    ] == [version["secret"] for version in versions]


@pytest.mark.parametrize(
    "route,message",
    [
        pytest.param(
            "/api/rmap-initiate",
            {"identity": "Group_99", "nonceClient": 1},
            id="unknown group",
        ),
        pytest.param(
            "/api/rmap-initiate",
            {"nonceClient": 1},
            id="identity missing",
        ),
        pytest.param(
            "/api/rmap-initiate",
            {"identity": [GROUP], "nonceClient": 1},
            id="identity not text",
        ),
        pytest.param(
            "/api/rmap-get-link",
            {"nonceServer": 1},
            id="get-link before initiate",
        ),
    ],
)
def test_bad_messages_are_rejected(client, server_key, route, message):
    response = client.post(route, json=encrypt_json(message, server_key.pubkey))

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid RMAP message"}


def test_text_nonce_is_rejected_at_get_link(client, server_key, group_key):
    resp1 = client.post(
        "/api/rmap-initiate",
        json=encrypt_json(
            {"identity": GROUP, "nonceClient": "5465464"}, server_key.pubkey
        ),
    )
    assert resp1.status_code == 200
    nonce_server = decrypt_json(resp1.get_json(), group_key)["nonceServer"]
    resp2 = client.post(
        "/api/rmap-get-link",
        json=encrypt_json({"nonceServer": nonce_server}, server_key.pubkey),
    )

    assert resp2.status_code == 400
    assert resp2.get_json() == {"error": "invalid RMAP message"}
