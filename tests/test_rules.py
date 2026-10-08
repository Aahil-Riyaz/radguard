"""The rule catalog agrees with the checks, in both directions, and documents itself."""

import ast
import re
from pathlib import Path

import pytest

from radguard import rules
from radguard.checks import preamble, structure
from radguard.findings import Severity
from radguard.signatures import SIGNATURES

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [*(ROOT / "src/radguard/checks").glob("*.py"), ROOT / "src/radguard/scanner.py"]
ID = re.compile(r"(preamble|structure|pixels|values|private|scan)\.[a-z0-9-]+")


def literal_ids() -> set[str]:
    """Every string in the check sources that looks like a check id."""
    found = set()
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and ID.fullmatch(node.value):
                found.add(node.value)
    return found


def emittable_ids() -> set[str]:
    """Literal ids, plus the two families built at run time."""
    dynamic = {f"structure.{code}" for code in structure.RULES}
    dynamic |= {f"preamble.{preamble._CHECK_IDS.get(s.kind, s.kind)}" for s in SIGNATURES if s.kind != "pe"}
    return literal_ids() | dynamic


def test_every_id_a_check_can_emit_has_a_rule():
    assert emittable_ids() - set(rules.RULES) == set()


def test_every_rule_is_one_a_check_can_emit():
    assert set(rules.RULES) - emittable_ids() == set()


def test_the_literal_scan_is_not_vacuous():
    assert {"preamble.pe-polyglot", "pixels.slack", "private.opaque-blob", "scan.findings-suppressed"} <= literal_ids()


@pytest.mark.parametrize("rule", rules.RULES.values(), ids=lambda r: r.id)
def test_rule_is_well_formed(rule):
    assert rule.kind in rules.ADVICE and rule.precision in rules.PRECISIONS
    assert rule.title and not rule.title[0].islower() and not rule.title.endswith(".")
    assert rule.description.endswith(".") and not rule.description[0].islower()
    assert all(url.startswith("https://") for url in rule.references)
    assert all(n in rules.CWE_NAMES for n in rule.cwe) and len(set(rule.cwe)) == len(rule.cwe)
    assert len(rule.tags) <= 10  # GitHub reads at most 20 tags per rule


def test_structure_rules_take_severity_and_rationale_from_the_check():
    for code, (severity, title, why) in structure.RULES.items():
        rule = rules.RULES[f"structure.{code}"]
        assert (rule.severity, rule.title) == (severity, title)
        assert rule.description.lower().startswith(why.lower())


def test_names_and_anchors_are_unique():
    assert len({r.name for r in rules.RULES.values()}) == len(rules.RULES)
    assert len({r.anchor for r in rules.RULES.values()}) == len(rules.RULES)


def test_derived_identifiers():
    rule = rules.RULES["preamble.pe-polyglot"]
    assert rule.name == "PreamblePePolyglot"
    assert rule.anchor == "preamblepe-polyglot"
    assert rule.help_uri == "https://github.com/Aahil-Riyaz/radguard/blob/main/docs/rules.md#preamblepe-polyglot"
    assert rule.tags == ("security", "malware", "external/cwe/cwe-506", "external/cwe/cwe-436")


def test_preamble_rules_match_signature_severities():
    for sig in SIGNATURES:
        if sig.kind != "pe":
            rule = rules.RULES[f"preamble.{preamble._CHECK_IDS.get(sig.kind, sig.kind)}"]
            assert rule.severity is sig.severity
            assert rule.kind == ("malware" if sig.severity >= Severity.HIGH else "hidden-data")


def test_unknown_id_still_gets_a_rule():
    rule = rules.rule("future.check")
    assert rule.id == "future.check" and rule.severity is Severity.MEDIUM and rule.kind in rules.ADVICE
    assert rules.rule("preamble.pe-polyglot") is rules.RULES["preamble.pe-polyglot"]


def test_reference_document_is_current():
    path = ROOT / "docs/rules.md"
    assert path.read_text(encoding="utf-8") == rules.reference(), "regenerate: radguard rules --markdown"


def test_reference_has_a_heading_for_every_anchor():
    headings = re.findall(r"^### (\S+)$", rules.reference(), re.MULTILINE)
    assert sorted(headings) == sorted(rules.RULES)


def test_every_named_cwe_is_used():
    assert {n for r in rules.RULES.values() for n in r.cwe} == set(rules.CWE_NAMES)
