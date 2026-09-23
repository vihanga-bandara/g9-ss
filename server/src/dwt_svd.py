"""
DWT-SVD watermarking algorithm implementation. Based on this github repository: #vicentinileonardo/DWT-SVD-digital-watermarking#
But has been modified to work with the tatou project structure and requirements.


"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
import zlib

import fitz
import numpy as np
import pywt

from watermarking_method import (
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


# Fixed decoding profile. Changing these requires a new method version.
DPI = 144
BLOCK_SIZE = 16
QUANTIZATION_STEP = 48.0
REPETITIONS = 3
WAVELET = "haar"

MAX_PAGES = 32
MAX_PAGE_PIXELS = 12_000_000
MAX_SECRET_BYTES = 4096

MAGIC = b"DWS1"
HEADER = struct.Struct(">4sH")  # Magic/version + payload byte length.
CHECKSUM = struct.Struct(">I")


# ---------- Payload layer ----------
# A future version can encrypt here before framing/error correction.
# Its decoder must retain support for existing DWS1 payloads.

def encode_payload(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")

    payload = secret.encode("utf-8")
    if len(payload) > MAX_SECRET_BYTES:
        raise ValueError("secret exceeds the supported byte limit")

    body = HEADER.pack(MAGIC, len(payload)) + payload
    return body + CHECKSUM.pack(zlib.crc32(body))


def decode_payload(frame: bytes) -> str:
    if len(frame) < HEADER.size + CHECKSUM.size:
        raise ValueError("truncated watermark")

    magic, length = HEADER.unpack(frame[:HEADER.size])
    expected = HEADER.size + length + CHECKSUM.size

    if magic != MAGIC or not 0 < length <= MAX_SECRET_BYTES:
        raise ValueError("unrecognized watermark frame")
    if len(frame) != expected:
        raise ValueError("invalid watermark length")

    body = frame[:-CHECKSUM.size]
    stored_crc = CHECKSUM.unpack(frame[-CHECKSUM.size:])[0]
    if zlib.crc32(body) != stored_crc:
        raise ValueError("watermark checksum mismatch")

    return frame[HEADER.size:-CHECKSUM.size].decode("utf-8")


def encode_bits(frame: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(frame, dtype=np.uint8))
    return np.repeat(bits, REPETITIONS)


def decode_bits(bits: np.ndarray) -> bytes:
    groups = bits.reshape(-1, REPETITIONS)
    recovered = (groups.sum(axis=1) > REPETITIONS // 2).astype(np.uint8)
    return np.packbits(recovered).tobytes()


# ---------- Image embedding layer ----------

def luminance(rgb: np.ndarray) -> np.ndarray:
    rgb = rgb.astype(np.float64)
    return (
        0.299 * rgb[..., 0]
        + 0.587 * rgb[..., 1]
        + 0.114 * rgb[..., 2]
    )


def singular_value(rgb: np.ndarray) -> float:
    ll, _ = pywt.dwt2(
        luminance(rgb), WAVELET, mode="periodization"
    )
    return float(np.linalg.svd(ll, compute_uv=False)[0])


def decode_block(rgb: np.ndarray) -> int:
    level = math.floor(
        singular_value(rgb) / QUANTIZATION_STEP + 0.5
    )
    return level % 2


def embed_block(rgb: np.ndarray, bit: int) -> np.ndarray:
    """Quantize the largest LL singular value to an even/odd level.

    Test the rounded RGB result, since clipping and pixel rounding
    can invalidate a watermark that worked in floating-point space.
    """
    original = rgb.astype(np.float64)
    y = luminance(original)
    ll, details = pywt.dwt2(y, WAVELET, mode="periodization")
    u, s, vh = np.linalg.svd(ll, full_matrices=False)

    # Even quantization levels encode 0; odd levels encode 1.
    nearest = (
        2 * math.floor(
            (s[0] / QUANTIZATION_STEP - bit) / 2 + 0.5
        )
        + bit
    )

    best = None
    best_error = float("inf")

    # Nearby alternatives help with saturated white/black pixels.
    for offset in (0, -2, 2, -4, 4):
        target = (nearest + offset) * QUANTIZATION_STEP

        # Preserve the modified value as the largest singular value.
        if target < 0 or target < s[1]:
            continue

        modified = s.copy()
        modified[0] = target
        reconstructed_ll = (u * modified) @ vh
        reconstructed_y = pywt.idwt2(
            (reconstructed_ll, details),
            WAVELET,
            mode="periodization",
        )

        delta = reconstructed_y - y
        candidate = np.clip(
            np.rint(original + delta[..., None]), 0, 255
        ).astype(np.uint8)

        observed = singular_value(candidate) / QUANTIZATION_STEP
        level = math.floor(observed + 0.5)

        # Require the correct bit plus distance from a decision boundary.
        if level % 2 != bit or abs(observed - level) > 0.25:
            continue

        error = float(
            np.mean((candidate.astype(np.float64) - original) ** 2)
        )
        if error < best_error:
            best = candidate
            best_error = error

    if best is None:
        raise WatermarkingError(
            "Could not reliably embed a bit in a selected block"
        )

    return best


def placement_order(count: int, key: str) -> list[int]:
    """Stable keyed ordering independent of a library's PRNG version.

    This controls placement; it does not encrypt the payload.
    """
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")

    seed = hashlib.sha256(
        b"tatou:dwt-svd:v1:placement\0" + key.encode("utf-8")
    ).digest()

    return sorted(
        range(count),
        key=lambda index: hmac.digest(
            seed, index.to_bytes(8, "big"), "sha256"
        ),
    )


def block_view(image: np.ndarray, index: int) -> np.ndarray:
    columns = image.shape[1] // BLOCK_SIZE
    row, column = divmod(index, columns)
    y = row * BLOCK_SIZE
    x = column * BLOCK_SIZE
    return image[y:y + BLOCK_SIZE, x:x + BLOCK_SIZE]


def block_count(image: np.ndarray) -> int:
    return (
        (image.shape[0] // BLOCK_SIZE)
        * (image.shape[1] // BLOCK_SIZE)
    )


def render_page(page: fitz.Page) -> np.ndarray:
    width = math.ceil(page.rect.width * DPI / 72)
    height = math.ceil(page.rect.height * DPI / 72)

    if width <= 0 or height <= 0:
        raise ValueError("invalid page dimensions")
    if width * height > MAX_PAGE_PIXELS:
        raise ValueError("page exceeds the rendering pixel limit")

    pixmap = page.get_pixmap(
        dpi=DPI,
        colorspace=fitz.csRGB,
        alpha=False,
        annots=True,
    )

    return np.frombuffer(
        pixmap.samples, dtype=np.uint8
    ).reshape(pixmap.height, pixmap.width, 3).copy()


def read_bytes(
    image: np.ndarray,
    order: list[int],
    byte_count: int,
) -> bytes:
    required = byte_count * 8 * REPETITIONS
    if required > len(order):
        raise ValueError("watermark exceeds page capacity")

    bits = np.fromiter(
        (
            decode_block(block_view(image, index))
            for index in order[:required]
        ),
        dtype=np.uint8,
        count=required,
    )
    return decode_bits(bits)


# ---------- Tatou integration ----------

class DWTSVDWatermark(WatermarkingMethod):
    name = "dwt-svd-v1"

    @staticmethod
    def get_usage() -> str:
        return (
            " DWT–SVD image watermark. "
            "position is a one-based page number, default 1. "
            "The selected page is rasterized. "
            "No encryption or authentication."
        )

    @staticmethod
    def _page_index(position: str | None, page_count: int) -> int:
        if position is None:
            number = 1
        elif isinstance(position, str) and position.isdecimal():
            number = int(position)
        else:
            raise ValueError("position must be a one-based page number")

        if not 1 <= number <= page_count:
            raise ValueError("selected page does not exist")
        return number - 1

    @staticmethod
    def _validate_document(document: fitz.Document) -> None:
        if document.needs_pass:
            raise ValueError("password-protected PDFs are unsupported")
        if not 1 <= document.page_count <= MAX_PAGES:
            raise ValueError(
                f"PDF must contain between 1 and {MAX_PAGES} pages"
            )

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        try:
            with fitz.open(
                stream=load_pdf_bytes(pdf), filetype="pdf"
            ) as document:
                self._validate_document(document)
                index = self._page_index(position, document.page_count)
                image = render_page(document[index])

                # Applicability checks the minimum payload only.
                # add_watermark checks the actual secret's capacity.
                minimum = (
                    HEADER.size + 1 + CHECKSUM.size
                ) * 8 * REPETITIONS
                return block_count(image) >= minimum
        except (ValueError, RuntimeError):
            return False

    def add_watermark(
        self, pdf, secret: str, key: str, position=None
    ) -> bytes:
        frame = encode_payload(secret)
        bits = encode_bits(frame)

        with fitz.open(
            stream=load_pdf_bytes(pdf), filetype="pdf"
        ) as source:
            self._validate_document(source)
            index = self._page_index(position, source.page_count)
            page = source[index]
            image = render_page(page)

            capacity = block_count(image)
            if len(bits) > capacity:
                maximum = max(
                    0,
                    capacity // (8 * REPETITIONS)
                    - HEADER.size
                    - CHECKSUM.size,
                )
                raise ValueError(
                    f"Secret does not fit; this page supports about "
                    f"{maximum} UTF-8 payload bytes"
                )

            order = placement_order(capacity, key)

            for selected, bit in zip(order, bits):
                block = block_view(image, selected)
                block[:] = embed_block(block, int(bit))

            height, width, _ = image.shape
            pixmap = fitz.Pixmap(
                fitz.csRGB, width, height, image.tobytes(), False
            )

            # Rebuild instead of placing an image over the original:
            # the selected page's original content is not retained.
            with fitz.open() as output:
                if index:
                    output.insert_pdf(
                        source, from_page=0, to_page=index - 1
                    )

                replacement = output.new_page(
                    width=page.rect.width,
                    height=page.rect.height,
                )
                replacement.insert_image(
                    replacement.rect,
                    pixmap=pixmap,
                    keep_proportion=False,
                )

                if index + 1 < source.page_count:
                    output.insert_pdf(
                        source,
                        from_page=index + 1,
                        to_page=source.page_count - 1,
                    )

                result = output.tobytes(
                    garbage=4,
                    deflate=True,
                    no_new_id=True,
                )

        # Verify the actual saved PDF, not just intermediate pixels.
        try:
            recovered = self.read_secret(result, key)
        except SecretNotFoundError as exc:
            raise WatermarkingError(
                "Watermark did not survive PDF reconstruction"
            ) from exc

        if recovered != secret:
            raise WatermarkingError("Watermark round-trip mismatch")

        return result

    def read_secret(self, pdf, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")

        with fitz.open(
            stream=load_pdf_bytes(pdf), filetype="pdf"
        ) as document:
            self._validate_document(document)

            # No position argument exists in the current read interface.
            for page in document:
                image = render_page(page)
                order = placement_order(block_count(image), key)

                try:
                    header = read_bytes(image, order, HEADER.size)
                    magic, length = HEADER.unpack(header)

                    if magic != MAGIC:
                        continue
                    if not 0 < length <= MAX_SECRET_BYTES:
                        continue

                    total = HEADER.size + length + CHECKSUM.size
                    frame = read_bytes(image, order, total)
                    return decode_payload(frame)

                except ValueError:
                    # Invalid framing, capacity, checksum, or UTF-8.
                    continue

        # Without authentication, reliably distinguishing a wrong key
        # from an absent or damaged watermark is not possible.
        raise SecretNotFoundError(
            "No valid watermark found: wrong key, absent watermark, "
            "or damaged payload"
        )