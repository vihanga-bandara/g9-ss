"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations

from typing import Final

from watermarking_method import (
    PdfSource,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    name: Final[str] = "bash-bridge-eof"

    @staticmethod
    def get_usage() -> str:
        return (
            "Appends a watermark after the PDF EOF marker. "
            "Position and key are ignored."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:

        data = load_pdf_bytes(pdf)

        if not isinstance(secret, str):
            raise ValueError("secret must be a string")

        return data + secret.encode("utf-8")

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:

        data = load_pdf_bytes(pdf)

        marker = b"%%EOF"
        index = data.rfind(marker)

        if index == -1:
            raise SecretNotFoundError("PDF EOF marker not found")

        secret_bytes = data[index + len(marker):]
        secret_bytes = secret_bytes.lstrip(b"\r\n")

        if not secret_bytes:
            raise SecretNotFoundError("No watermark found after EOF")

        return secret_bytes.decode("utf-8")


__all__ = ["UnsafeBashBridgeAppendEOF"]