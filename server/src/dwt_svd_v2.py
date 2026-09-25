"""A robust DWT-SVD image watermark embedded into rasterized PDF pages.
The watermarking method was inspired by DWT-SVD watermarking techniques,
including the approach demonstrated by Vicentini et al.'s DWT-SVD implementation.
The method retains the general principle of applying DWT to image blocks
and modifying singular values in the LL sub-band,
but uses a different embedding and extraction scheme based on binary
quantization of the dominant singular value.
It additionally incorporates keyed placement, synchronization,
Reed-Solomon error correction,
and HMAC authentication for the Tatou use case.

The core idea is: each 16×16 image block carries one bit;
DWT selects the low-frequency image information,
SVD gives a stable numerical feature, and the parity of the quantized largest
singular value represents 0 or 1.
Everything else—Reed-Solomon, HMAC, synchronization, keyed placement, repetition,
and rotation/alignment search—makes that basic idea more reliable and secure.

"""

import hashlib
import hmac
import math
import struct

import fitz
import numpy as np
import pywt
from reedsolo import RSCodec, ReedSolomonError

from watermarking_method import (
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

# ============================================================
# 1. Configuration and watermark format
# ============================================================
# PDF rendering resolution used before embedding the watermark.
DPI = 144
# Each 16×16 pixel block carries one bit;
BLOCK_SIZE = 16
# Haar wavelet is used for the DWT transformation.
WAVELET = "haar"
# safty and security limits for PDF and image sizes
MAX_PAGES = 32
MAX_PAGE_PIXELS = 12_000_000
## Watermark grid: 32x24 blocks = 768 bits.
ROWS, COLS = 32, 24
HEIGHT, WIDTH = ROWS * 16, COLS * 16
# Payload and error-correction sizes.
STEP = 96.0
# payload and error-correction sizes.
PAYLOAD_BYTES = 42
DATA_BYTES = 64
PARITY_BYTES = 24
# Frame header contains the format identifier and secret length.
HEADER = struct.Struct(">4sH")
# Known 64-bit pattern used to locate the watermark during extraction.
SYNC = np.unpackbits(
    np.frombuffer(hashlib.sha256(b"tatou-v2-sync").digest()[:8], dtype=np.uint8)
)


# ============================================================
# 2. DWT-SVD block embedding and extraction
# ============================================================
# Image processing
def luminance(rgb: np.ndarray) -> np.ndarray:
    rgb = rgb.astype(np.float64)
    return 0.299 * rgb[..., 0] + 0.587 * rgb[..., 1] + 0.114 * rgb[..., 2]


def singular_value(rgb: np.ndarray) -> float:
    ll, _ = pywt.dwt2(luminance(rgb), WAVELET, mode="periodization")
    return float(np.linalg.svd(ll, compute_uv=False)[0])


# embedding and reading the watermark in the image
def embed_block(rgb: np.ndarray, bit: int, step=STEP) -> np.ndarray:
    """Quantize the largest LL singular value to an even/odd level.

    Test the rounded RGB result, since clipping and pixel rounding
    can invalidate a watermark that worked in floating-point space.
    """
    original = rgb.astype(np.float64)
    y = luminance(original)
    ll, details = pywt.dwt2(y, WAVELET, mode="periodization")
    u, s, vh = np.linalg.svd(ll, full_matrices=False)

    # Even quantization levels encode 0; odd levels encode 1.
    nearest = 2 * math.floor((s[0] / step - bit) / 2 + 0.5) + bit

    best = None
    best_error = float("inf")

    # Nearby alternatives help with saturated white/black pixels.
    for offset in (0, -2, 2, -4, 4):
        target = (nearest + offset) * step

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
        candidate = np.clip(np.rint(original + delta[..., None]), 0, 255).astype(
            np.uint8
        )

        observed = singular_value(candidate) / step
        level = math.floor(observed + 0.5)

        # Require the correct bit plus distance from a decision boundary.
        if level % 2 != bit or abs(observed - level) > 0.25:
            continue

        error = float(np.mean((candidate.astype(np.float64) - original) ** 2))
        if error < best_error:
            best = candidate
            best_error = error

    if best is None:
        raise WatermarkingError("Could not reliably embed a bit in a selected block")

    return best


# ============================================================
# 3. Keyed placement and authentication
# ============================================================


# The key controls where payload bits are placed.
# It does not encrypt the secret.
def placement_order(count: int, key: str) -> list[int]:
    """Stable keyed ordering independent of a library's PRNG version.

    This controls placement; it does not encrypt the payload.
    """
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")

    # Retain this domain separator to preserve existing DWS2 block placement.
    seed = hashlib.sha256(
        b"tatou:dwt-svd:v1:placement\0" + key.encode("utf-8")
    ).digest()

    return sorted(
        range(count),
        key=lambda index: hmac.digest(seed, index.to_bytes(8, "big"), "sha256"),
    )


# Render PDF pages before embedding or extracting image watermarks.
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

    return (
        np.frombuffer(pixmap.samples, dtype=np.uint8)
        .reshape(pixmap.height, pixmap.width, 3)
        .copy()
    )


# Derive a separate HMAC authentication key from the user key.
# Frame before Reed-Solomon:
# [ DWS2 | length | secret + padding | HMAC ]
#
# Reed-Solomon then adds 24 parity bytes.
# Final result: 88 bytes = 704 bits
def auth_key(key):
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")
    return hmac.digest(key.encode(), b"tatou:dwt-svd:v2:authentication", "sha256")


# ============================================================
# 4. Payload encoding and Reed-Solomon error correction
# ============================================================
def encode_frame(secret, key):
    signing_key = auth_key(key)
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must be a non-empty string")
    payload = secret.encode("utf-8")
    if len(payload) > PAYLOAD_BYTES:
        raise ValueError("Secret does not fit; v2 supports 42 UTF-8 payload bytes")
    body = HEADER.pack(b"DWS2", len(payload)) + payload.ljust(PAYLOAD_BYTES, b"\0")
    tag = hmac.digest(signing_key, body, "sha256")[:16]
    return bytes(RSCodec(PARITY_BYTES).encode(body + tag))


#
def decode_frame(encoded, key):
    if len(encoded) != DATA_BYTES + PARITY_BYTES:
        raise ValueError("invalid encoded frame size")
    try:
        data = bytes(RSCodec(PARITY_BYTES).decode(encoded)[0])
    except ReedSolomonError as exc:
        raise ValueError("uncorrectable watermark") from exc
    if len(data) != DATA_BYTES:
        raise ValueError("invalid frame size")
    body, tag = data[:-16], data[-16:]
    if not hmac.compare_digest(tag, hmac.digest(auth_key(key), body, "sha256")[:16]):
        raise ValueError("watermark authentication failed")
    magic, length = HEADER.unpack(body[: HEADER.size])
    if magic != b"DWS2" or not 0 < length <= PAYLOAD_BYTES:
        raise ValueError("invalid watermark header")
    return body[HEADER.size : HEADER.size + length].decode("utf-8")


# ============================================================
# 5. Image-level watermark embedding and recovery
# ============================================================


def origins(image):
    height, width = image.shape[:2]
    if height < HEIGHT or width < WIDTH:
        return []
    # Center a non-overlapping grid; margins protect against small edge crops.
    ny, nx = height // HEIGHT, width // WIDTH
    y0, x0 = (height - ny * HEIGHT) // 2, (width - nx * WIDTH) // 2
    return [(y0 + y * HEIGHT, x0 + x * WIDTH) for y in range(ny) for x in range(nx)]


def embed_image(image, frame, key):
    order = placement_order(704, "v2:" + key)
    bits = np.empty(ROWS * COLS, dtype=np.uint8)
    bits[:64] = SYNC
    bits[64 + np.asarray(order)] = np.unpackbits(np.frombuffer(frame, dtype=np.uint8))
    for y, x in origins(image):
        for index, bit in enumerate(bits):
            row, col = divmod(index, COLS)
            block = image[
                y + row * 16 : y + (row + 1) * 16, x + col * 16 : x + (col + 1) * 16
            ]
            block[:] = embed_block(block, int(bit), step=STEP)
    return image


## Decode all 16x16 blocks into a grid of candidate watermark bits.
def bit_grid(image, dy, dx):
    h = (image.shape[0] - dy) // 16
    w = (image.shape[1] - dx) // 16
    if not ((h >= ROWS and w >= COLS) or (h >= COLS and w >= ROWS)):
        return None
    y = image[dy : dy + h * 16, dx : dx + w * 16]
    if y.ndim == 3:
        y = luminance(y)
    # Haar LL coefficients, equivalent to dwt2(..., 'haar') on each block.
    ll = (y[::2, ::2] + y[1::2, ::2] + y[::2, 1::2] + y[1::2, 1::2]) / 2
    blocks = ll.reshape(h, 8, w, 8).transpose(0, 2, 1, 3)
    singular = np.linalg.svd(blocks, compute_uv=False)[..., 0]
    return (np.floor(singular / STEP + 0.5).astype(np.int64) % 2).astype(np.uint8)


def quick_offsets(height, width):
    """Map centered tile alignment in each orientation back to original pixels."""
    for turns in range(4):
        h, w = (width, height) if turns % 2 else (height, width)
        if h < HEIGHT or w < WIDTH:
            continue
        y = (h % HEIGHT) // 2
        x = (w % WIDTH) // 2
        dy, dx = ((y, x), (x, width - y), (height - y, width - x), (height - x, y))[
            turns
        ]
        yield dy % BLOCK_SIZE, dx % BLOCK_SIZE


def read_grid(grid, order, key):
    # Haar LL's largest singular value is invariant under quarter turns:
    # row/column permutations and transposition do not change singular values.
    for turns in range(4):
        rotated = np.rot90(grid, turns)
        h, w = rotated.shape
        if h < ROWS or w < COLS:
            continue
        windows = np.lib.stride_tricks.sliding_window_view(rotated, (3, COLS))
        windows = windows[: h - ROWS + 1]
        scores = np.sum(
            windows.reshape(*windows.shape[:2], -1)[..., :64] == SYNC, axis=-1
        )
        for row, col in np.argwhere(scores >= 58):
            tile = rotated[row : row + ROWS, col : col + COLS]
            encoded = np.packbits(tile.ravel()[64 + order]).tobytes()
            try:
                return decode_frame(encoded, key)
            except ValueError:
                continue
    raise SecretNotFoundError("No authenticated v2 watermark found")


def read_image(image, key, *, search_offsets=False):
    """Run either the quick pass or remaining crop alignments, without overlap."""
    order = np.asarray(placement_order(704, "v2:" + key))
    quick = set(quick_offsets(*image.shape[:2]))
    offsets = (
        [
            (y, x)
            for y in range(BLOCK_SIZE)
            for x in range(BLOCK_SIZE)
            if (y, x) not in quick
        ]
        if search_offsets
        else sorted(quick)
    )
    # Convert once; each grid/SVD is shared by all four orientations.
    gray = luminance(image)
    for dy, dx in offsets:
        grid = bit_grid(gray, dy, dx)
        if grid is None:
            continue
        try:
            return read_grid(grid, order, key)
        except SecretNotFoundError:
            continue
    raise SecretNotFoundError("No authenticated v2 watermark found")


def page_images(page):
    """Yield unique candidates, skipping pages with no displayed raster image."""
    info_list = page.get_image_info(xrefs=True)
    if not info_list:
        return
    seen_xrefs, seen_pixels = set(), set()
    count = 0
    for info in info_list:
        xref = info["xref"]
        if (
            not xref
            or xref in seen_xrefs
            or info["width"] * info["height"] > MAX_PAGE_PIXELS
        ):
            continue
        seen_xrefs.add(xref)
        pix = fitz.Pixmap(page.parent, xref)
        if pix.colorspace is None:
            continue
        if pix.colorspace.n != 3:
            pix = fitz.Pixmap(fitz.csRGB, pix)
        if pix.alpha:
            pix = fitz.Pixmap(pix, 0)
        image = np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.width, 3)
        identity = (image.shape, hashlib.sha256(image.tobytes()).digest())
        if identity not in seen_pixels:
            seen_pixels.add(identity)
            yield image
        count += 1
        if count == 4:
            break
    try:
        image = render_page(page)
    except ValueError:
        return
    identity = (image.shape, hashlib.sha256(image.tobytes()).digest())
    if identity not in seen_pixels:
        yield image


# ============================================================
# 6. PDF integration
# ============================================================
class DWTSVDWatermarkV2(WatermarkingMethod):
    name = "dwt-svd-v2"

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
            raise ValueError(f"PDF must contain between 1 and {MAX_PAGES} pages")

    @staticmethod
    def get_usage():
        return (
            "Authenticated DWT-SVD v2; maximum 42 UTF-8 bytes. Position is a "
            "one-based page number (default 1), or all for every fitting page. "
            "Marked pages are rasterized. Keep the supplied key private. "
            "Supports bounded recovery; not arbitrary geometric distortion."
        )

    def is_watermark_applicable(self, pdf, position=None):
        try:
            with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
                self._validate_document(doc)
                indices = (
                    range(len(doc))
                    if position == "all"
                    else [self._page_index(position, len(doc))]
                )
                return any(self._fits(doc[i]) for i in indices)
        except (ValueError, RuntimeError):
            return False

    @staticmethod
    def _fits(page):
        try:
            return bool(origins(render_page(page)))
        except ValueError:
            return False

    def add_watermark(self, pdf, secret, key, position=None):
        # Create the authenticated and error-corrected watermark payload.
        frame = encode_frame(secret, key)
        with (
            fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as source,
            fitz.open() as out,
        ):
            self._validate_document(source)
            indices = (
                set(range(len(source)))
                if position == "all"
                else {self._page_index(position, len(source))}
            )
            marked = 0
            for i, page in enumerate(source):
                if i not in indices or (position == "all" and not self._fits(page)):
                    out.insert_pdf(source, from_page=i, to_page=i)
                    continue
                image = render_page(page)
                if not origins(image):
                    raise ValueError(
                        "Secret does not fit; page needs a 384 x 512 pixel region"
                    )
                embed_image(image, frame, key)
                # Verify every marked page independently, never an earlier copy.
                if read_image(image, key) != secret:
                    raise WatermarkingError("Page watermark verification failed")
                h, w = image.shape[:2]
                replacement = out.new_page(
                    width=page.rect.width, height=page.rect.height
                )
                replacement.insert_image(
                    replacement.rect,
                    pixmap=fitz.Pixmap(fitz.csRGB, w, h, image.tobytes(), False),
                )
                marked += 1
            if not marked:
                raise ValueError("No page has sufficient watermark capacity")
            result = out.tobytes(garbage=4, deflate=True, no_new_id=True)
        if self.read_secret(result, key) != secret:
            raise WatermarkingError("Saved PDF watermark verification failed")
        return result

    def read_secret(self, pdf, key):
        """Try every page's quick alignment before any expensive crop search."""
        auth_key(key)
        with fitz.open(stream=load_pdf_bytes(pdf), filetype="pdf") as doc:
            self._validate_document(doc)
            for search in (False, True):
                for page in doc:
                    for image in page_images(page):
                        try:
                            return read_image(image, key, search_offsets=search)
                        except SecretNotFoundError:
                            continue
        raise SecretNotFoundError(
            "No authenticated v2 watermark found: absent, damaged, or wrong key"
        )
