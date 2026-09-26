"""Repeated page-marker watermarking method."""

from __future__ import annotations

import hashlib
import hmac
import re

import pymupdf
from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class TeosRepeatedWatermark(WatermarkingMethod):
    """Embed a repeated marker across PDF pages."""

    name = "Teos-Repeated-Watermark"
    supported_positions = {
        "top-left",
        "top-right",
        "center",
        "bottom-left",
        "bottom-right",
    }

    @staticmethod
    def get_usage() -> str:
        return """
        Repeated invisible text watermark using HMAC-SHA256 authentication.

        The method embeds a watermark on every page of the PDF. Supported
        positions are: top-left, top-right, center, bottom-left, and bottom-right.

        Each watermark contains the supplied secret together with an HMAC-SHA256
        authentication tag generated from the secret and key. The watermark is
        inserted as non-rendered PDF text, making it visually unobtrusive during
        normal viewing while remaining recoverable through PDF text extraction.

        Repeating the watermark on every page provides redundancy and allows the
        secret to remain recoverable if pages are removed or a single original
        page is extracted from the document.

        When reading a watermark, all recognizable markers are examined and their
        HMACs are verified using the supplied key. Authenticated markers must agree
        on the same secret; conflicting authenticated secrets result in an error.
        """

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Return whether this watermark can be applied to the PDF."""

        if position is None:
            position = "top-left"

        if position not in self.supported_positions:
            return False

        doc = None

        try:
            pdf_bytes = load_pdf_bytes(pdf)
            doc = pymupdf.open(
                stream=pdf_bytes,
                filetype="pdf",
            )

            return doc.page_count > 0

        except Exception:
            return False

        finally:
            if doc is not None:
                doc.close()

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embed the secret and return the resulting PDF."""

        if not secret:
            raise WatermarkingError("No secret to embed")

        if not key:
            raise WatermarkingError("No key provided for HMAC authentication")

        if position is None:
            position = "top-left"

        if position not in self.supported_positions:
            raise WatermarkingError(f"Unsupported position: {position}")

        key_bytes = key.encode("utf-8")
        secret_bytes = secret.encode("utf-8")
        mac = hmac.new(
            key_bytes,
            secret_bytes,
            hashlib.sha256,
        )

        new_secret = f"TEO_WM:<{secret}|{mac.hexdigest()}>"
        pdf_bytes = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        try:
            for page_index in range(doc.page_count):
                page = doc.load_page(page_index)


                area = page.rect * page.derotation_matrix
                margin = 50

                top_left = (
                    area.x0 + margin,
                    area.y0 + margin,
                )
                top_right = (
                    area.x1 - margin,
                    area.y0 + margin,
                )
                center = (
                    (area.x0 + area.x1) / 2,
                    (area.y0 + area.y1) / 2,
                )
                bottom_left = (
                    area.x0 + margin,
                    area.y1 - margin,
                )
                bottom_right = (
                    area.x1 - margin,
                    area.y1 - margin,
                )

                coordinates = {
                    "top-left": top_left,
                    "top-right": top_right,
                    "center": center,
                    "bottom-left": bottom_left,
                    "bottom-right": bottom_right,
                }

                selected_position = coordinates[position]

                page.insert_text(
                    selected_position,
                    new_secret,
                    fontsize=0.001,
                    render_mode=3,
                )
            watermarked_pdf = doc.tobytes(no_new_id=True)
            return watermarked_pdf
        except Exception as exc:
            raise WatermarkingError("Failed to add watermark") from exc

        finally:
            doc.close()

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:
        """Recover the embedded secret."""

        pdf_bytes = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")

        recovered_secret_collection: list[str] = []
        marker_found = False

        try:
            for page_index in range(doc.page_count):
                page = doc.load_page(page_index)
                page_text = page.get_text()

                matches = re.finditer(
                    r"TEO_WM:<(.*?)\|(.*?)>",
                    page_text,
                )

                for match in matches:
                    marker_found = True

                    recovered_secret = match.group(1)
                    stored_hmac = match.group(2)

                    key_bytes = key.encode("utf-8")
                    recovered_secret_bytes = recovered_secret.encode("utf-8")

                    recovered_mac = hmac.new(
                        key_bytes,
                        recovered_secret_bytes,
                        hashlib.sha256,
                    )

                    comparison = hmac.compare_digest(
                        recovered_mac.hexdigest(),
                        stored_hmac,
                    )

                    if comparison:
                        recovered_secret_collection.append(recovered_secret)

            if not marker_found:
                raise SecretNotFoundError("Secret not found")

            if not recovered_secret_collection:
                raise InvalidKeyError(
                    "No watermark could be authenticated with this key"
                )

            if len(set(recovered_secret_collection)) > 1:
                raise WatermarkingError(
                    "Conflicting authenticated watermark secrets found"
                )

            return recovered_secret_collection[0]

        finally:
            doc.close()
