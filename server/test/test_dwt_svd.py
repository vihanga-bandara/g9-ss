import struct

import fitz
import numpy as np
import pytest

from dwt_svd import (
    BLOCK_SIZE,
    MAX_PAGES,
    MAX_SECRET_BYTES,
    DWTSVDWatermark,
    decode_bits,
    decode_block,
    decode_payload,
    embed_block,
    encode_bits,
    encode_payload,
    placement_order,
)
from watermarking_method import SecretNotFoundError
from watermarking_utils import get_method


def make_pdf(style="text", pages=1, width=300, height=400):
    """Generate a small but genuinely renderable PDF."""
    with fitz.open() as document:
        for index in range(pages):
            page = document.new_page(width=width, height=height)

            if style == "text":
                for line in range(12):
                    page.insert_text(
                        (20, 35 + line * 24),
                        f"Page {index + 1}, line {line + 1}: Tatou test",
                        fontsize=10,
                    )

            elif style == "dark":
                page.draw_rect(
                    page.rect,
                    color=(0.05, 0.05, 0.05),
                    fill=(0.05, 0.05, 0.05),
                )
                page.insert_text(
                    (20, 40),
                    "Dark page",
                    fontsize=16,
                    color=(1, 1, 1),
                )

            elif style == "color":
                for band in range(10):
                    rectangle = fitz.Rect(
                        0,
                        band * height / 10,
                        width,
                        (band + 1) * height / 10,
                    )
                    color = (band / 10, 0.3, 1 - band / 10)
                    page.draw_rect(
                        rectangle, color=color, fill=color
                    )

            elif style != "blank":
                raise ValueError(f"Unknown style: {style}")

        return document.tobytes()


def render_rgb(document, page_index):
    pixmap = document[page_index].get_pixmap(
        dpi=144,
        colorspace=fitz.csRGB,
        alpha=False,
    )
    return np.frombuffer(
        pixmap.samples, dtype=np.uint8
    ).reshape(pixmap.height, pixmap.width, 3)


@pytest.fixture
def method():
    return DWTSVDWatermark()


@pytest.fixture
def original_pdf():
    return make_pdf()


# ---------- Payload format and error correction ----------

@pytest.mark.parametrize(
    "secret",
    ["group-07", "åäö秘密", "a" * 40],
)
def test_payload_roundtrip(secret):
    assert decode_payload(encode_payload(secret)) == secret


def test_payload_checksum_rejects_corruption():
    frame = bytearray(encode_payload("group-07"))

    # Alter a payload byte without updating its checksum.
    frame[-5] ^= 1

    with pytest.raises(ValueError, match="checksum"):
        decode_payload(bytes(frame))


def test_payload_rejects_truncation():
    frame = encode_payload("group-07")

    with pytest.raises(ValueError):
        decode_payload(frame[:-1])


def test_payload_rejects_unknown_format():
    frame = bytearray(encode_payload("group-07"))
    frame[:4] = b"BAD!"

    with pytest.raises(ValueError):
        decode_payload(bytes(frame))


def test_payload_rejects_invalid_length():
    frame = bytearray(encode_payload("group-07"))
    frame[4:6] = struct.pack(">H", 4000)

    with pytest.raises(ValueError):
        decode_payload(bytes(frame))


@pytest.mark.parametrize("secret", ["", "x" * (MAX_SECRET_BYTES + 1)])
def test_payload_rejects_invalid_secret(secret):
    with pytest.raises(ValueError):
        encode_payload(secret)


def test_repetition_corrects_one_error_per_triplet():
    frame = encode_payload("group-07")
    bits = encode_bits(frame)

    # Exactly one error in every three-bit group.
    bits[::3] ^= 1

    recovered = decode_bits(bits)
    assert recovered == frame
    assert decode_payload(recovered) == "group-07"


def test_excessive_bit_errors_are_detected_by_checksum():
    frame = encode_payload("group-07")
    bits = encode_bits(frame)

    # Flip two copies of a bit inside the payload.
    # Majority voting now gives the wrong bit.
    payload_bit = 6 * 8
    offset = payload_bit * 3
    bits[offset:offset + 2] ^= 1

    with pytest.raises(ValueError, match="checksum"):
        decode_payload(decode_bits(bits))


# ---------- Placement and image blocks ----------

def test_placement_is_repeatable_and_has_no_duplicates():
    first = placement_order(100, "key-one")
    second = placement_order(100, "key-one")

    assert first == second
    assert sorted(first) == list(range(100))
    assert first != placement_order(100, "key-two")


@pytest.mark.parametrize("pixel_value", [0, 128, 255])
@pytest.mark.parametrize("bit", [0, 1])
def test_block_roundtrip_after_pixel_rounding(pixel_value, bit):
    block = np.full(
        (BLOCK_SIZE, BLOCK_SIZE, 3),
        pixel_value,
        dtype=np.uint8,
    )

    watermarked = embed_block(block, bit)

    assert watermarked.dtype == np.uint8
    assert watermarked.shape == block.shape
    assert decode_block(watermarked) == bit


# ---------- Real PDF integration ----------

def test_method_is_registered():
    assert isinstance(get_method("dwt-svd-v1"), DWTSVDWatermark)


@pytest.mark.parametrize("style", ["text", "blank", "dark", "color"])
def test_pdf_roundtrip(method, style):
    original = make_pdf(style=style)
    output = method.add_watermark(
        original,
        secret="group-07",
        key="test-placement-key",
        position="1",
    )

    assert output.startswith(b"%PDF-")
    assert method.read_secret(output, "test-placement-key") == "group-07"

    with fitz.open(stream=output, filetype="pdf") as document:
        assert document.page_count == 1
        assert not document.is_repaired


def test_unicode_secret_roundtrip(method, original_pdf):
    secret = "åäö秘密"
    output = method.add_watermark(
        original_pdf, secret, "test-key", "1"
    )

    assert method.read_secret(output, "test-key") == secret


def test_saved_file_roundtrip(method, original_pdf, tmp_path):
    output = method.add_watermark(
        original_pdf, "group-07", "test-key", "1"
    )
    path = tmp_path / "watermarked.pdf"
    path.write_bytes(output)

    assert method.read_secret(path, "test-key") == "group-07"


def test_wrong_key_returns_no_valid_watermark(method, original_pdf):
    output = method.add_watermark(
        original_pdf, "group-07", "correct-key", "1"
    )

    with pytest.raises(SecretNotFoundError):
        method.read_secret(output, "wrong-key")


def test_unwatermarked_pdf_is_rejected(method, original_pdf):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(original_pdf, "test-key")


def test_reader_finds_watermark_on_second_page(method):
    original = make_pdf(pages=3)
    output = method.add_watermark(
        original, "page-two", "test-key", "2"
    )

    assert method.read_secret(output, "test-key") == "page-two"

    with (
        fitz.open(stream=original, filetype="pdf") as before,
        fitz.open(stream=output, filetype="pdf") as after,
    ):
        assert after.page_count == before.page_count

        for index in range(3):
            assert after[index].rect == before[index].rect

        # Pages outside the selected page should render identically.
        for index in (0, 2):
            np.testing.assert_array_equal(
                render_rgb(before, index),
                render_rgb(after, index),
            )
            assert after[index].get_text() == before[index].get_text()


@pytest.mark.parametrize("position", ["0", "-1", "2", "abc", "1.5"])
def test_invalid_page_selection(method, original_pdf, position):
    with pytest.raises(ValueError):
        method.add_watermark(
            original_pdf, "secret", "test-key", position
        )


def test_default_position_is_first_page(method, original_pdf):
    output = method.add_watermark(
        original_pdf, "secret", "test-key"
    )

    assert method.read_secret(output, "test-key") == "secret"


def test_payload_exceeding_page_capacity_is_rejected(
    method, original_pdf
):
    with pytest.raises(ValueError, match="does not fit"):
        method.add_watermark(
            original_pdf, "x" * 1000, "test-key", "1"
        )


def test_tiny_page_is_not_applicable(method):
    tiny = make_pdf(style="blank", width=36, height=36)
    assert method.is_watermark_applicable(tiny, "1") is False


def test_page_count_limit(method):
    original = make_pdf(style="blank", pages=MAX_PAGES + 1)

    with pytest.raises(ValueError):
        method.add_watermark(
            original, "secret", "test-key", "1"
        )


def test_empty_key_is_rejected(method, original_pdf):
    with pytest.raises(ValueError):
        method.add_watermark(original_pdf, "secret", "", "1")


def test_identical_inputs_produce_identical_pdf(method, original_pdf):
    # Your current base-class contract requires determinism.
    first = method.add_watermark(
        original_pdf, "secret", "test-key", "1"
    )
    second = method.add_watermark(
        original_pdf, "secret", "test-key", "1"
    )

    assert first == second