import json

from conftest import build_dicom, build_pe_polyglot
from radguard.cli import main


def test_json_report_and_exit_code(tmp_path, write_file, capsys):
    write_file("clean.dcm", build_dicom())
    write_file("evil", build_pe_polyglot())
    write_file("readme.txt", b"not dicom")

    assert main(["scan", str(tmp_path), "--format", "json"]) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["files"] == 3
    assert report["summary"]["dicom"] == 2
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["findings"]["critical"] == 1
    assert report["findings"][0]["check"] == "preamble.pe-polyglot"


def test_clean_tree_exits_zero(tmp_path, write_file, capsys):
    write_file("a.dcm", build_dicom())
    assert main(["scan", str(tmp_path)]) == 0
    assert "findings: none" in capsys.readouterr().out


def test_fail_on_threshold(tmp_path, write_file):
    write_file("pdf.dcm", build_dicom(b"%PDF-1.7"))  # medium
    assert main(["scan", str(tmp_path)]) == 0
    assert main(["scan", str(tmp_path), "--fail-on", "medium"]) == 1
