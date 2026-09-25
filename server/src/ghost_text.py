"""Encryption for the ghost-text watermarking method."""

import base64
import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from watermarking_method import InvalidKeyError

# Fixed, not random: add_watermark must give the same PDF for the same inputs.
KEY_SALT = b"tatou-ghost-text-v1"
PBKDF2_ITERATIONS = 600_000  # OWASP's figure for PBKDF2-HMAC-SHA256
# Safe to reuse with AES-GCM-SIV: a repeat only reveals that two secrets are equal.
NONCE = bytes(12)


def _stretch_key(key: str) -> bytes:
    """Stretch the owner's key into a 32-byte AES key, slowly to resist guessing."""
    return hashlib.pbkdf2_hmac(
        "sha256", key.encode("utf-8"), KEY_SALT, PBKDF2_ITERATIONS
    )


def encrypt_secret(secret: str, key: str) -> str:
    """Encrypt and seal the secret with AES-GCM-SIV.

    Args:
        secret: The text to hide, for example who the copy is for.
        key: The key the document owner chose for this watermark.

    Returns:
        Base64 text of the ciphertext followed by its 16-byte tag.
    """
    sealed = AESGCMSIV(_stretch_key(key)).encrypt(NONCE, secret.encode("utf-8"), None)
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
        sealed = base64.b64decode(payload, validate=True)
        data = AESGCMSIV(_stretch_key(key)).decrypt(NONCE, sealed, None)
    except (ValueError, InvalidTag) as exc:  # not base64, or the seal does not match
        raise InvalidKeyError("Wrong key or damaged watermark") from exc
    return data.decode("utf-8")
