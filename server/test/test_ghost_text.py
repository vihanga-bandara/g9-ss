import pytest

from ghost_text import decrypt_secret, encrypt_secret
from watermarking_method import InvalidKeyError

KEY = "unit-test-key"
# Known answer: if it changes, PDFs watermarked earlier can no longer be read.
BOB_PAYLOAD = "6NYt79C+QMQbI43K7x7YJ4ZdUUXXuIz/sS5Mhg=="


def test_encrypt_and_decrypt_match_the_known_answer() -> None:
    assert encrypt_secret("copy-for-bob", KEY) == BOB_PAYLOAD
    assert decrypt_secret(BOB_PAYLOAD, KEY) == "copy-for-bob"


@pytest.mark.parametrize(
    "payload, key",
    [(BOB_PAYLOAD, "not-the-key"), (BOB_PAYLOAD[:-1], KEY)],
    ids=["wrong-key", "broken-base64"],
)
def test_decrypt_secret_raises_invalid_key_error(payload: str, key: str) -> None:
    with pytest.raises(InvalidKeyError):
        decrypt_secret(payload, key)
