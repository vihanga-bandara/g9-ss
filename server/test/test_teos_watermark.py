from pathlib import Path

import pymupdf
import pytest

from TeosRepeatedWatermark import TeosRepeatedWatermark
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)


pdf_path = Path(__file__).parent / "valid_test.pdf"
method = TeosRepeatedWatermark()


def test_read_secret_without_watermark_raises():
    with pytest.raises(SecretNotFoundError):
        method.read_secret(
            pdf=pdf_path,
            key="test-key",
        )


def test_read_secret_with_wrong_key_raises():
    watermarked_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="right_key",
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            pdf=watermarked_pdf,
            key="wrong_key",
        )


def test_watermark_survives_removed_page():
    watermarked_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
    )

    doc = None
    try:
        doc = pymupdf.open(
            stream=watermarked_pdf,
            filetype="pdf",
        )
        doc.delete_page(0)
        modified_pdf = doc.tobytes()
    finally:
        if doc is not None:
            doc.close()

    recovered = method.read_secret(
        pdf=modified_pdf,
        key="test-key",
    )

    assert recovered == "TEO_TEST"


def test_watermark_survives_single_page_extraction():
    watermarked_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
    )

    source_doc = None
    single_page_doc = None

    try:
        source_doc = pymupdf.open(
            stream=watermarked_pdf,
            filetype="pdf",
        )

        single_page_doc = pymupdf.open()

        single_page_doc.insert_pdf(
            source_doc,
            from_page=2,
            to_page=2,
        )

        single_page_pdf = single_page_doc.tobytes()

    finally:
        if single_page_doc is not None:
            single_page_doc.close()

        if source_doc is not None:
            source_doc.close()

    recovered = method.read_secret(
        pdf=single_page_pdf,
        key="test-key",
    )

    assert recovered == "TEO_TEST"


def test_conflicting_authenticated_watermarks_raise():
    first_watermark = method.add_watermark(
        pdf=pdf_path,
        secret="FIRST_SECRET",
        key="test-key",
    )

    second_watermark = method.add_watermark(
        pdf=first_watermark,
        secret="SECOND_SECRET",
        key="test-key",
    )

    with pytest.raises(WatermarkingError):
        method.read_secret(
            pdf=second_watermark,
            key="test-key",
        )


@pytest.mark.parametrize(
    "position",
    [
        None,
        "top-left",
        "top-right",
        "center",
        "bottom-left",
        "bottom-right",
    ],
)
def test_secret_positioning(position):
    result = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
        position=position,
    )

    recovered = method.read_secret(
        pdf=result,
        key="test-key",
    )

    assert recovered == "TEO_TEST"


@pytest.mark.parametrize(
    "position",
    [
        "top-right",
        "bottom-right",
    ],
)
def test_watermark_on_rotated_page(position):
    with pymupdf.open(pdf_path) as doc:
        page = doc.load_page(0)
        page.set_rotation(90)
        rotated_pdf = doc.tobytes(no_new_id=True)

    result = method.add_watermark(
        pdf=rotated_pdf,
        secret="TEO_TEST",
        key="test-key",
        position=position,
    )

    recovered = method.read_secret(
        pdf=result,
        key="test-key",
    )

    assert recovered == "TEO_TEST"


def test_empty_secret_rejected():
    with pytest.raises(WatermarkingError):
        method.add_watermark(
            pdf=pdf_path,
            secret="",
            key="test-key",
        )


def test_watermark_is_deterministic():
    first_result = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
        position="center",
    )

    second_result = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
        position="center",
    )

    assert first_result == second_result