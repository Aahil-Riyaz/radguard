"""Values check: files embedded inside attribute values, and encapsulated documents."""

from builder import el, fake_elf, fake_pe, image, item, part10, seq
from conftest import findings_for
from radguard.findings import Severity

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


def by_check(data):
    return {f.check: f for f in findings_for(data, "values.")}


def test_clean_file_has_no_value_findings():
    assert by_check(part10(image(8, 8) + el(0x00291010, "OB", bytes(64)))) == {}


def test_executable_deep_inside_a_sequence_is_located_precisely():
    nested = seq(0x00081140, item(el(0x00081150, "UI", "1.2")), item(el(0x00291010, "OB", fake_elf())))
    finding = by_check(part10(nested))["values.embedded-file"]
    assert finding.severity is Severity.CRITICAL
    assert "(0008,1140) item 2 > (0029,1010)" in finding.detail
    assert "0 bytes into" in finding.detail


def test_vendor_xml_in_a_private_attribute_is_only_low():
    finding = by_check(part10(el(0x00291010, "OB", b"<?xml version='1.0'?><vendor/>\x00\x00")))["values.embedded-file"]
    assert finding.severity is Severity.LOW


def document(content: bytes, mime: str | None = "application/pdf") -> bytes:
    out = el(0x00420011, "OB", content + b"\x00" * (len(content) % 2))
    if mime is not None:
        out += el(0x00420012, "LO", mime)
    return part10(out)


def test_honest_pdf_document_is_clean():
    assert by_check(document(PDF)) == {}


def test_document_carrying_an_executable():
    found = by_check(document(fake_pe()))
    assert found["values.document-payload"].severity is Severity.CRITICAL
    assert found["values.document-type-mismatch"].severity is Severity.HIGH


def test_document_whose_content_contradicts_its_mime_type():
    assert "values.document-type-mismatch" in by_check(document(PDF, mime="text/XML"))


def test_document_without_mime_type():
    assert by_check(document(PDF, mime=None))["values.document-type-missing"].severity is Severity.MEDIUM
