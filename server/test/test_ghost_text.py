from collections.abc import Callable
from pathlib import Path

import pymupdf
import pytest

from ghost_text import GhostText, decrypt_secret, encrypt_secret
from watermarking_method import InvalidKeyError, SecretNotFoundError

KEY = "unit-test-key"
# Known answer: if it changes, PDFs watermarked earlier can no longer be read.
BOB_PAYLOAD = "6NYt79C+QMQbI43K7x7YJ4ZdUUXXuIz/sS5Mhg=="
SAMPLE_PDF = (Path(__file__).parent / "valid_test.pdf").read_bytes()


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


def resave_with_cleanup(pdf: bytes) -> bytes:
    with pymupdf.open(stream=pdf, filetype="pdf") as doc:
        return doc.tobytes(garbage=4, deflate=True, clean=True)


def copy_first_page(pdf: bytes) -> bytes:
    with pymupdf.open(stream=pdf, filetype="pdf") as doc, pymupdf.open() as copy:
        copy.insert_pdf(doc, from_page=0, to_page=0)
        return copy.tobytes()


@pytest.mark.parametrize(
    "edit", [resave_with_cleanup, copy_first_page], ids=["resave", "page-copy"]
)
def test_ghost_text_survives_common_pdf_edits(edit: Callable[[bytes], bytes]) -> None:
    marked = GhostText().add_watermark(SAMPLE_PDF, "copy-for-bob", KEY)
    assert GhostText().read_secret(edit(marked), KEY) == "copy-for-bob"


def test_read_secret_tells_a_missing_watermark_from_a_wrong_key() -> None:
    with pytest.raises(SecretNotFoundError):
        GhostText().read_secret(SAMPLE_PDF, KEY)
    marked = GhostText().add_watermark(SAMPLE_PDF, "copy-for-bob", KEY)
    with pytest.raises(InvalidKeyError):
        GhostText().read_secret(marked, "not-the-key")
