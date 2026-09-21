from bash_bridge_append_eof import UnsafeBashBridgeAppendEOF
from pathlib import Path
pdf_path = Path(__file__).parent / "valid_test.pdf"

def test_command_injection_not_executed(tmp_path):
    # Copy a valid PDF into the temporary test directory
    pdf = tmp_path / "test.pdf"
    pdf.write_bytes(pdf_path.read_bytes())

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