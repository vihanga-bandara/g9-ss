import pytest

from ghost_text import decrypt_secret, encrypt_secret
from watermarking_method import InvalidKeyError

KEY = "unit-test-key"
# Fixed answer: if it changes, PDFs watermarked earlier can no longer be read.
BOB_PAYLOAD = "1ckKwyCJFd7RnSYC3KZXeKU7H95kTwER5HH+vw=="


def test_encrypt_and_decrypt_match_the_known_answer() -> None:
    assert encrypt_secret("copy-for-bob", KEY) == BOB_PAYLOAD
    assert decrypt_secret(BOB_PAYLOAD, KEY) == "copy-for-bob"


@pytest.mark.parametrize(
    "payload, key",
    [(BOB_PAYLOAD, "not-the-key"), (BOB_PAYLOAD[:-1], KEY)],
    ids=["wrong key", "damaged payload"],
)
def test_decrypt_secret_refuses_what_it_cannot_unlock(payload: str, key: str) -> None:
    with pytest.raises(InvalidKeyError):
        decrypt_secret(payload, key)
