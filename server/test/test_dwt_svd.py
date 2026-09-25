import importlib
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import fitz
import numpy as np
import pytest
from itsdangerous import URLSafeTimedSerializer

from dwt_svd_v2 import (
    MAX_PAGES,
    MAX_PAGE_PIXELS,
    PAYLOAD_BYTES,
    DWTSVDWatermarkV2 as DWTSVDWatermark,
    placement_order,
    encode_frame,
    decode_frame,
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
                    page.draw_rect(rectangle, color=color, fill=color)

            elif style != "blank":
                raise ValueError(f"Unknown style: {style}")

        return document.tobytes()


def render_rgb(document, page_index):
    pixmap = document[page_index].get_pixmap(
        dpi=144,
        colorspace=fitz.csRGB,
        alpha=False,
    )
    return np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(
        pixmap.height, pixmap.width, 3
    )


@pytest.fixture
def method():
    return DWTSVDWatermark()


@pytest.fixture
def original_pdf():
    return make_pdf()


# ---------- Authenticated payload format ----------


@pytest.mark.parametrize(
    "secret", ["group-09", "åäö秘密", "x" * PAYLOAD_BYTES, "å" * (PAYLOAD_BYTES // 2)]
)
def test_payload_roundtrip(secret):
    assert decode_frame(encode_frame(secret, "test-key"), "test-key") == secret


@pytest.mark.parametrize(
    "secret", ["", "x" * (PAYLOAD_BYTES + 1), "å" * (PAYLOAD_BYTES // 2 + 1)]
)
def test_payload_rejects_invalid_secret(secret):
    with pytest.raises(ValueError):
        encode_frame(secret, "test-key")


@pytest.mark.parametrize("extra", [-1, 1])
def test_payload_rejects_invalid_encoded_size(extra):
    frame = encode_frame("group-09", "test-key")
    malformed = frame[:-1] if extra == -1 else frame + b"\0"
    with pytest.raises(ValueError, match="frame size"):
        decode_frame(malformed, "test-key")


def test_payload_rejects_excessive_corruption():
    frame = bytearray(encode_frame("group-09", "test-key"))
    for index in range(30):
        frame[index] ^= 0xA5
    with pytest.raises(ValueError):
        decode_frame(bytes(frame), "test-key")


# ---------- Placement and image blocks ----------


def test_placement_is_repeatable_and_has_no_duplicates():
    first = placement_order(100, "key-one")
    second = placement_order(100, "key-one")

    assert first == second
    assert sorted(first) == list(range(100))
    assert first != placement_order(100, "key-two")


# ---------- Project document and recipient attribution ----------


def test_repository_pdf_roundtrip(method):
    source = Path(__file__).with_name("valid_test.pdf")
    output = method.add_watermark(source, "group-09", "test-key")
    assert method.read_secret(output, "test-key") == "group-09"


def test_assigned_pdf_roundtrip(method):
    # Keep the confidential course document out of the repository.
    # Example: TATOU_ASSIGNED_PDF=/path/to/document.pdf pytest ...
    configured = os.environ.get("TATOU_ASSIGNED_PDF")
    if not configured:
        pytest.skip("Set TATOU_ASSIGNED_PDF to test the assigned course PDF")
    source = Path(configured).expanduser()
    assert source.is_file(), "TATOU_ASSIGNED_PDF must point to an existing PDF"
    output = method.add_watermark(source, "group-09:retrieval-001", "test-key")
    assert method.read_secret(output, "test-key") == "group-09:retrieval-001"


def test_recipients_and_retrievals_have_distinct_watermarks(method, original_pdf):
    # The service supplies fresh identifiers; the algorithm remains deterministic.
    secrets = ["group-09:001", "group-08:001", "group-09:002"]
    outputs = [
        method.add_watermark(original_pdf, secret, "server-test-key")
        for secret in secrets
    ]
    assert len(set(outputs)) == len(secrets)
    for output, secret in zip(outputs, secrets):
        assert method.read_secret(output, "server-test-key") == secret


def test_reader_skips_oversized_page_before_watermarked_page(method, original_pdf):
    watermarked = method.add_watermark(original_pdf, "page-two", "test-key")
    # At 144 DPI this square exceeds the pixel limit without allocating a bitmap.
    side_points = int(MAX_PAGE_PIXELS**0.5) + 1
    with fitz.open() as combined:
        combined.new_page(width=side_points, height=side_points)
        with fitz.open(stream=watermarked, filetype="pdf") as marked:
            combined.insert_pdf(marked)
        output = combined.tobytes()
    assert method.read_secret(output, "test-key") == "page-two"


# ---------- Visual quality ----------


@pytest.mark.parametrize("style", ["text", "blank", "dark", "color"])
def test_pdf_roundtrip_and_visual_quality(method, style, record_property):
    original = make_pdf(style=style)
    output = method.add_watermark(original, "group-09", "test-key")
    assert method.read_secret(output, "test-key") == "group-09"
    with (
        fitz.open(stream=original, filetype="pdf") as before,
        fitz.open(stream=output, filetype="pdf") as after,
    ):
        assert after.page_count == 1
        assert not after.is_repaired
        assert after[0].rect == before[0].rect
        reference = render_rgb(before, 0).astype(np.float64)
        actual = render_rgb(after, 0).astype(np.float64)
    assert actual.shape == reference.shape
    mse = float(np.mean((actual - reference) ** 2))
    psnr = float("inf") if mse == 0 else float(10 * np.log10(255**2 / mse))
    record_property("psnr_db", psnr)
    record_property("output_size_bytes", len(output))
    record_property("size_ratio", len(output) / len(original))
    # Proposed project acceptance target, not a threshold specified by the course.
    # PSNR measures pixel distortion; it does not establish text accessibility.
    assert psnr >= 35.0, f"Selected-page PSNR is {psnr:.2f} dB; target is 35 dB"


# ---------- Robustness acceptance tests ----------
# These tests require exact recovery AFTER transforming the saved PDF. They may
# document the supported transformations without implying arbitrary robustness.


@pytest.fixture(scope="module")
def robustness_pdf():
    return DWTSVDWatermark().add_watermark(
        make_pdf(), "group-09", "robustness-test-key"
    )


def rebuild_raster_pdf(pdf, *, jpeg_quality=None, dpi=144):
    """Render and repackage each page, preserving its physical dimensions."""
    with fitz.open(stream=pdf, filetype="pdf") as source, fitz.open() as output:
        for page in source:
            pixmap = page.get_pixmap(dpi=dpi, colorspace=fitz.csRGB, alpha=False)
            replacement = output.new_page(
                width=page.rect.width, height=page.rect.height
            )
            if jpeg_quality is None:
                replacement.insert_image(replacement.rect, pixmap=pixmap)
            else:
                # JPEG encoding with jpg_quality requires PyMuPDF >= 1.22.0.
                replacement.insert_image(
                    replacement.rect,
                    stream=pixmap.tobytes("jpeg", jpg_quality=jpeg_quality),
                )
        return output.tobytes(garbage=4, deflate=True)


def test_lossless_raster_repackaging_preserves_secret(method, robustness_pdf):
    transformed = rebuild_raster_pdf(robustness_pdf)
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


@pytest.mark.parametrize("quality", [95, 85, 70])
def test_jpeg_recompression_preserves_secret(method, robustness_pdf, quality):
    transformed = rebuild_raster_pdf(robustness_pdf, jpeg_quality=quality)
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


def test_downsampling_preserves_secret(method, robustness_pdf):
    transformed = rebuild_raster_pdf(robustness_pdf, dpi=108)
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


@pytest.mark.parametrize("scale", [0.9, 1.1])
def test_page_resizing_preserves_secret(method, robustness_pdf, scale):
    with (
        fitz.open(stream=robustness_pdf, filetype="pdf") as source,
        fitz.open() as output,
    ):
        page = output.new_page(
            width=source[0].rect.width * scale,
            height=source[0].rect.height * scale,
        )
        page.show_pdf_page(page.rect, source, 0)
        transformed = output.tobytes()
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


def test_margin_cropping_preserves_secret(method, robustness_pdf):
    with fitz.open(stream=robustness_pdf, filetype="pdf") as document:
        page = document[0]
        bounds = page.rect
        # Remove four points from each edge, leaving the test's text intact.
        page.set_cropbox(fitz.Rect(4, 4, bounds.width - 4, bounds.height - 4))
        transformed = document.tobytes()
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


def test_quarter_turn_preserves_secret(method, robustness_pdf):
    with fitz.open(stream=robustness_pdf, filetype="pdf") as document:
        document[0].set_rotation(90)
        transformed = document.tobytes()
    assert method.read_secret(transformed, "robustness-test-key") == "group-09"


# ---------- HTTP integration with real watermarking and temporary files ----------


def test_api_creates_and_reads_dwt_svd_watermark(monkeypatch, tmp_path):
    # Only the database is mocked; authentication, services, registry, algorithm,
    # and file storage use the real application. This is not an RMAP test.
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "dwt-api-test-key")
    server = importlib.import_module("server")
    app = server.create_app()
    app.config["TESTING"] = True

    source = tmp_path / "files" / "1" / "report.pdf"
    source.parent.mkdir(parents=True)
    original = make_pdf()
    source.write_bytes(original)
    document = SimpleNamespace(id=7, name="report", path=str(source))

    connection = MagicMock()
    connection.execute.return_value.first.return_value = document
    connection.execute.return_value.scalar.return_value = 11
    engine = MagicMock()
    engine.connect.return_value.__enter__.return_value = connection
    engine.begin.return_value.__enter__.return_value = connection
    app.config["_ENGINE"] = engine

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps({"uid": 1, "login": "alice"})
    headers = {"Authorization": f"Bearer {token}"}
    client = app.test_client()
    listing = client.get("/api/get-watermarking-methods")
    assert listing.status_code == 200
    assert "dwt-svd-v2" in {m["name"] for m in listing.get_json()["methods"]}

    created = client.post(
        "/api/create-watermark/7",
        headers=headers,
        json={
            "method": "dwt-svd-v2",
            "position": "1",
            "secret": "group-09:001",
            "key": "test-key",
            "intended_for": "group-09",
        },
    )
    assert created.status_code == 201, created.get_json()
    result = created.get_json()
    # The download filename can differ from the random-link storage name.
    [stored] = list((source.parent / "watermarks").glob("*.pdf"))
    assert stored.is_file()
    assert stored.stat().st_size == result["size"]
    assert source.read_bytes() == original

    inserts = [
        call.args[1]
        for call in connection.execute.call_args_list
        if "INSERT INTO Versions" in str(call.args[0])
    ]
    assert len(inserts) == 1
    assert inserts[0]["method"] == "dwt-svd-v2"
    assert inserts[0]["secret"] == "group-09:001"
    assert inserts[0]["intended_for"] == "group-09"
    assert Path(inserts[0]["path"]) == stored
    assert inserts[0]["link"] == result["link"]

    # read-watermark reads an uploaded document, not a Versions row. Simulate
    # the generated PDF being uploaded as a new document owned by this user.
    leaked = source.parent / "leaked.pdf"
    leaked.write_bytes(stored.read_bytes())
    connection.execute.return_value.first.return_value = SimpleNamespace(
        id=8, name="leaked", path=str(leaked)
    )
    recovered = client.post(
        "/api/read-watermark/8",
        headers=headers,
        json={"method": "dwt-svd-v2", "position": "1", "key": "test-key"},
    )
    assert recovered.status_code == 201, recovered.get_json()
    assert recovered.get_json()["secret"] == "group-09:001"


# ---------- Real PDF integration ----------


def test_saved_file_roundtrip(method, original_pdf, tmp_path):
    output = method.add_watermark(original_pdf, "åäö秘密", "test-key")
    path = tmp_path / "watermarked.pdf"
    path.write_bytes(output)

    assert method.read_secret(path, "test-key") == "åäö秘密"


def test_wrong_key_returns_no_valid_watermark(method, original_pdf):
    output = method.add_watermark(original_pdf, "group-09", "correct-key", "1")

    with pytest.raises(SecretNotFoundError):
        method.read_secret(output, "wrong-key")


def test_unwatermarked_pdf_is_rejected(method, original_pdf):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(original_pdf, "test-key")


def test_reader_finds_watermark_on_second_page(method):
    original = make_pdf(pages=3)
    output = method.add_watermark(original, "page-two", "test-key", "2")

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
        method.add_watermark(original_pdf, "secret", "test-key", position)


def test_payload_exceeding_page_capacity_is_rejected(method, original_pdf):
    with pytest.raises(ValueError, match="does not fit"):
        method.add_watermark(original_pdf, "x" * 1000, "test-key", "1")


def test_tiny_page_is_not_applicable(method):
    tiny = make_pdf(style="blank", width=36, height=36)
    assert method.is_watermark_applicable(tiny, "1") is False


def test_page_count_limit(method):
    original = make_pdf(style="blank", pages=MAX_PAGES + 1)

    with pytest.raises(ValueError):
        method.add_watermark(original, "secret", "test-key", "1")


def test_empty_key_is_rejected(method, original_pdf):
    with pytest.raises(ValueError):
        method.add_watermark(original_pdf, "secret", "", "1")


def test_identical_inputs_produce_identical_pdf(method, original_pdf):
    # Your current base-class contract requires determinism.
    first = method.add_watermark(original_pdf, "secret", "test-key", "1")
    second = method.add_watermark(original_pdf, "secret", "test-key", "1")

    assert first == second


# ---------- V2 security, correction, and destructive transformations ----------


def test_v2_authentication_rejects_reencoded_forgery():
    from reedsolo import RSCodec
    from dwt_svd_v2 import PARITY_BYTES, decode_frame, encode_frame

    encoded = encode_frame("group-09", "owner-key")
    with pytest.raises(ValueError, match="authentication"):
        decode_frame(encoded, "wrong-key")
    body = bytearray(RSCodec(PARITY_BYTES).decode(encoded)[0])
    body[6] ^= 1
    # Recalculate ECC as an attacker could; the secret HMAC must still reject it.
    forged = bytes(RSCodec(PARITY_BYTES).encode(body))
    with pytest.raises(ValueError, match="authentication"):
        decode_frame(forged, "owner-key")


def test_v2_corrects_twelve_corrupted_bytes():
    from dwt_svd_v2 import decode_frame, encode_frame

    encoded = bytearray(encode_frame("group-09", "owner-key"))
    for index in range(0, 72, 6):
        encoded[index] ^= 0xA5
    assert decode_frame(bytes(encoded), "owner-key") == "group-09"


@pytest.mark.parametrize("turns", [1, 2, 3])
def test_flattened_rotation_preserves_secret(method, robustness_pdf, turns):
    with fitz.open(stream=robustness_pdf, filetype="pdf") as doc:
        doc[0].set_rotation(90 * turns)
        rotated = doc.tobytes()
    flattened = rebuild_raster_pdf(rotated)
    assert method.read_secret(flattened, "robustness-test-key") == "group-09"


@pytest.mark.parametrize("margins", [(4, 4, 4, 4), (7, 11, 3, 5)])
@pytest.mark.parametrize("turns", [0, 1, 3])
def test_flattened_crop_preserves_secret(method, robustness_pdf, margins, turns):
    left, top, right, bottom = margins
    with fitz.open(stream=robustness_pdf, filetype="pdf") as doc:
        bounds = doc[0].rect
        doc[0].set_cropbox(
            fitz.Rect(left, top, bounds.width - right, bounds.height - bottom)
        )
        doc[0].set_rotation(turns * 90)
        cropped = doc.tobytes()
    flattened = rebuild_raster_pdf(cropped)
    assert method.read_secret(flattened, "robustness-test-key") == "group-09"


def test_all_pages_survives_page_removal(method):
    source = make_pdf(pages=3)
    marked = method.add_watermark(source, "group-09", "key", position="all")
    with fitz.open(stream=marked, filetype="pdf") as doc:
        # Every page must independently contain the authenticated payload.
        for index in range(3):
            with fitz.open() as single:
                single.insert_pdf(doc, from_page=index, to_page=index)
                assert method.read_secret(single.tobytes(), "key") == "group-09"


def test_only_improved_dwt_svd_method_is_registered():
    from watermarking_utils import METHODS

    assert [name for name in METHODS if name.startswith("dwt-svd")] == ["dwt-svd-v2"]
    assert isinstance(get_method("dwt-svd-v2"), DWTSVDWatermark)


def test_repeated_regions_survive_removing_left_half(method):
    original = make_pdf(width=600, height=400)
    marked = method.add_watermark(original, "group-09", "key")
    with fitz.open(stream=marked, filetype="pdf") as doc:
        doc[0].set_cropbox(fitz.Rect(300, 0, 600, 400))
        cropped = doc.tobytes()
    # Flatten so recovery cannot use the removed half of the stored image.
    assert method.read_secret(rebuild_raster_pdf(cropped), "key") == "group-09"


def test_all_pages_checked_quickly_before_crop_search(monkeypatch, method):
    import dwt_svd_v2 as watermark

    # An earlier IMAGE page must be searched, not merely skipped as plain text.
    source = rebuild_raster_pdf(make_pdf(pages=2))
    real_read = watermark.read_image
    calls = []

    def quick_only(image, key, *, search_offsets=False):
        calls.append(search_offsets)
        assert not search_offsets, "crop search started before the marked page"
        return real_read(image, key, search_offsets=search_offsets)

    monkeypatch.setattr(watermark, "read_image", quick_only)
    output = method.add_watermark(source, "page-two", "key", "2")
    assert method.read_secret(output, "key") == "page-two"
    assert len(calls) >= 3


def test_text_only_pages_do_not_render_or_search(monkeypatch, method):
    import dwt_svd_v2 as watermark

    def unexpected(*args, **kwargs):
        pytest.fail("text-only pages must not render or search pixel grids")

    monkeypatch.setattr(watermark, "render_page", unexpected)
    monkeypatch.setattr(watermark, "read_image", unexpected)
    with pytest.raises(SecretNotFoundError):
        method.read_secret(make_pdf(pages=3), "key")


def test_each_grid_is_computed_once_for_all_rotations(monkeypatch):
    import dwt_svd_v2 as watermark

    offsets = []

    def grid_spy(gray, dy, dx):
        assert gray.ndim == 2  # Luminance conversion also happens outside the loop.
        offsets.append((dy, dx))
        return np.zeros((50, 37), dtype=np.uint8)

    monkeypatch.setattr(watermark, "bit_grid", grid_spy)
    image = np.zeros((800, 600, 3), dtype=np.uint8)
    for search in (False, True):
        with pytest.raises(SecretNotFoundError):
            watermark.read_image(image, "key", search_offsets=search)
    assert len(offsets) == len(set(offsets)) == 16 * 16
