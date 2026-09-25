"""Watermark that hides the encrypted secret as invisible text on every page."""

import base64
import binascii
import functools
import hashlib
import re

import pymupdf
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)

# Fixed and public, not random: add_watermark must stay deterministic.
KEY_SALT = b"tatou-ghost-text-v1"
PBKDF2_ITERATIONS = 600_000  # OWASP's figure for PBKDF2-HMAC-SHA256
MARKER = "TATOUWM1:"
PAYLOAD_PATTERN = re.compile(MARKER + r"([A-Za-z0-9+/]+={0,2});")
INVISIBLE_RENDER_MODE = 3
MARGIN = 2
MAX_FONT_SIZE = 1


# One slow stretch per read, even when a PDF holds many copies.
@functools.lru_cache(maxsize=1)
def _stretch_key(key: str) -> bytes:
    """Stretch the owner's key into a 32-byte AES-SIV key with PBKDF2."""
    return hashlib.pbkdf2_hmac(
        "sha256", key.encode("utf-8"), KEY_SALT, PBKDF2_ITERATIONS
    )


def encrypt_secret(secret: str, key: str) -> str:
    """Encrypt and seal the secret with AES-SIV; the same inputs give the same text.

    Args:
        secret: The text to hide, for example who the copy is for.
        key: The key the document owner chose for this watermark.

    Returns:
        Base64 text of the 16-byte seal followed by the ciphertext.
    """
    sealed = AESSIV(_stretch_key(key)).encrypt(secret.encode("utf-8"), None)
    return base64.b64encode(sealed).decode("ascii")


def decrypt_secret(payload: str, key: str) -> str:
    """Return the secret that encrypt_secret sealed into the payload.

    Args:
        payload: Base64 text made by encrypt_secret.
        key: The key the document owner chose for this watermark.

    Returns:
        The original secret.

    Raises:
        InvalidKeyError: The key is wrong or the payload was damaged.
    """
    try:
        sealed = base64.b64decode(payload)
        data = AESSIV(_stretch_key(key)).decrypt(sealed, None)
    except (binascii.Error, InvalidTag) as exc:
        raise InvalidKeyError("Wrong key or damaged watermark") from exc
    return data.decode("utf-8")


def _hide_on_page(page: pymupdf.Page, text: str) -> None:
    """Write the text invisibly along the page's bottom edge, shrunk to fit."""
    area = page.rect * page.derotation_matrix  # insert_text uses unrotated coordinates
    width_at_one_point = pymupdf.get_text_length(text, fontsize=1)
    fontsize = min(MAX_FONT_SIZE, (area.width - 2 * MARGIN) / width_at_one_point)
    page.insert_text(
        (area.x0 + MARGIN, area.y1 - MARGIN),
        text,
        fontsize=fontsize,
        render_mode=INVISIBLE_RENDER_MODE,
    )


class GhostText(WatermarkingMethod):
    """Watermarking method that writes the encrypted secret as invisible page text."""

    name = "ghost-text"

    @staticmethod
    def get_usage() -> str:
        return (
            "Hides the secret, encrypted with the key, as invisible text on every "
            "page. Position is ignored."
        )

    def is_watermark_applicable(
        self, pdf: PdfSource, position: str | None = None
    ) -> bool:
        return True

    def add_watermark(
        self, pdf: PdfSource, secret: str, key: str, position: str | None = None
    ) -> bytes:
        """Return the PDF with the encrypted secret hidden on every page."""
        if not secret or not key:
            raise ValueError("Secret and key must not be empty")
        text = f"{MARKER}{encrypt_secret(secret, key)};"
        with pymupdf.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            for page in doc:
                _hide_on_page(page, text)
            return doc.tobytes(no_new_id=True)  # a fresh /ID would break determinism

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Return the secret from the first hidden copy that the key unlocks."""
        with pymupdf.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            text = "\n".join(page.get_textpage().extractText() for page in doc)
        payloads = dict.fromkeys(PAYLOAD_PATTERN.findall(text))
        if not payloads:
            raise SecretNotFoundError("No ghost-text watermark found")
        for payload in payloads:
            try:
                return decrypt_secret(payload, key)
            except InvalidKeyError:
                continue
        raise InvalidKeyError("Wrong key or damaged watermark")
