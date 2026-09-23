from pathlib import Path

from bash_bridge_append_eof import UnsafeBashBridgeAppendEOF


def test_command_injection_not_executed(tmp_path):
    # A real PDF, since load_pdf_bytes now parses the document
    pdf = tmp_path / "test.pdf"
    pdf.write_bytes((Path(__file__).parent / "valid_test.pdf").read_bytes())

    method = UnsafeBashBridgeAppendEOF()
    # If shell execution were possible, this would create the file below
    payload = '"; touch /tmp/tatou-pwned; #'

    result = method.add_watermark(
        pdf,
        payload,
        "",
    )

    # The payload should only be stored as text
    assert payload.encode() in result

    # Most important security assertion:
    assert not __import__("pathlib").Path("/tmp/tatou-pwned").exists()