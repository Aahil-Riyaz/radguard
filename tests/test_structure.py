"""Structure check: hidden payloads, unexplained bytes, abused padding, anomaly mapping."""

import ast
from pathlib import Path

import pytest

from builder import DEFLATED_LE, IMPLICIT_LE, deflate, el, fake_elf, fake_pe, image, part10
from conftest import findings_for
from radguard.checks.structure import RULES
from radguard.findings import Severity


def by_check(data):
    return {f.check: f for f in findings_for(data, "structure.")}


def test_clean_file_has_no_structure_findings():
    assert by_check(part10(image(8, 8))) == {}


@pytest.mark.parametrize("payload,label", [(fake_pe(), "Windows PE"), (fake_elf(), "ELF")])
def test_executable_appended_after_dataset_is_critical(payload, label):
    base = part10(image(8, 8))
    found = by_check(base + payload)
    hidden = found["structure.hidden-payload"]
    assert hidden.severity is Severity.CRITICAL
    assert hidden.offset == len(base)
    assert label in hidden.title
    assert "parsing stopped because" in hidden.detail
    # The anomaly that stopped the parser is folded into the payload finding, not repeated.
    assert "structure.invalid-vr" not in found


def test_executable_after_deflate_stream_is_found():
    base = part10(deflate(image(8, 8)), ts=DEFLATED_LE)
    found = by_check(base + fake_pe())
    assert found["structure.hidden-payload"].offset == len(base)


def test_appended_bytes_in_implicit_file_are_not_claimed_by_bogus_elements():
    # In implicit VR there is no VR to validate, so appended bytes parse as an
    # element whose declared length overruns the file. That value must stay unexplained.
    base = part10(image(8, 8, implicit=True), ts=IMPLICIT_LE)
    tail = b"\x41\x41\x41\x41" + b"\xff\xff\xff\x7f" + bytes(64)
    found = by_check(base + tail)
    gap = found["structure.unexplained-bytes"]
    assert gap.offset == len(base) + 8


def test_random_trailing_bytes_are_unexplained_not_payload():
    found = by_check(part10(image(8, 8)) + bytes(range(256)) * 8)
    assert found["structure.unexplained-bytes"].severity is Severity.HIGH
    assert "structure.hidden-payload" not in found


def test_non_zero_trailing_padding():
    padding = el(0xFFFCFFFC, "OB", fake_pe(96))
    found = by_check(part10(image(8, 8) + padding))
    assert found["structure.nonzero-padding"].severity is Severity.CRITICAL
    assert by_check(part10(image(8, 8) + el(0xFFFCFFFC, "OB", bytes(64)))) == {}


def test_anomalies_become_findings_with_rationale():
    data = part10(el(0x00100020, "LO", "B") + el(0x00100010, "PN", "A"))
    finding = by_check(data)["structure.tag-order"]
    assert finding.severity is Severity.MEDIUM
    assert "readers" in finding.detail


def emitted_anomaly_codes() -> set[str]:
    """Every code the parser can emit, read from its syntax tree (independent of formatting)."""
    tree = ast.parse(Path(__file__).parents[1].joinpath("src/radguard/dicom/parser.py").read_text(encoding="utf-8"))
    codes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "note") or (
                    isinstance(func, ast.Name) and func.id == "Anomaly"):
                codes.add(node.args[0].value)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "code" for t in node.targets):
            codes |= {n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    return codes


def test_every_anomaly_code_the_parser_can_emit_has_a_rule():
    emitted = emitted_anomaly_codes()
    assert {"invalid-vr", "meta-group-length-mismatch", "group-length-mismatch", "suppressed"} <= emitted
    assert emitted - set(RULES) == set()
