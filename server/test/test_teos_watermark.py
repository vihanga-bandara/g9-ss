import pytest

from TeosRepeatedWatermark import TeosRepeatedWatermark
from pathlib import Path
from watermarking_method import InvalidKeyError
from watermarking_method import SecretNotFoundError
from watermarking_method import WatermarkingError
import pymupdf
pdf_path = Path(__file__).parent / "valid_test.pdf"
method = TeosRepeatedWatermark()
output_path = Path(__file__).parent / "teos_watermarked_test.pdf"



def test_teos_watermark_loop():
    result = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
    )
    output_path.write_bytes(result)

    recovered = method.read_secret(
        pdf=result,
        key="test-key",
    )
    assert recovered == "TEO_TEST"

def test_read_secret_without_watermark_raises():
    with pytest.raises(SecretNotFoundError):
        method.read_secret(
            pdf=pdf_path,
            key="test-key",
        )

def test_read_secret_with_wrong_key_raises():
    valid_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="right_key",
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            pdf=valid_pdf,
            key="wrong_key",
        )

def test_watermark_survives_removed_page():
    valid_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
    )
    doc = None
    try:
        doc = pymupdf.open(
            stream=valid_pdf,
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

def test_watermark_survival_if_rasterized():
    doc = None
    page = None
    valid_pdf = method.add_watermark(
        pdf=pdf_path,
        secret="TEO_TEST",
        key="test-key",
    )
    try:
        doc = pymupdf.open(
            stream=valid_pdf,
            filetype="pdf",
        )



    finally:
        if doc is not None:
            doc.close()



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

def test_empty_secret_rejected():
    with pytest.raises(WatermarkingError):
        method.add_watermark(
            pdf=pdf_path,
            secret="",
            key="test-key",
        )

