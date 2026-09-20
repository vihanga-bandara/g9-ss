from pathlib import Path

from watermarking_method import is_pdf_bytes


pdf_path = Path(__file__).parent / "valid_test.pdf"
pdf_bytes = pdf_path.read_bytes()


def test_rejects_non_pdf_bytes():
    data = b"hello"
    assert is_pdf_bytes(data) is False
def test_rejects_malformed_pdf():
    data2 = b"%PDF-this is not actually a PDF"
    assert is_pdf_bytes(data2) is False

def test_accepts_valid_pdf():
   assert is_pdf_bytes(pdf_bytes) is True