from builder import el, fake_pe, image, part10
from radguard.cli import main


def test_map_shows_structure_hidden_bytes_and_coverage(write_file, capsys):
    data = part10(image(4, 4) + el(0x00100010, "PN", "DOE^JANE")) + fake_pe()
    path = write_file("scan.dcm", data)
    assert main(["map", path]) == 0
    out = capsys.readouterr().out
    assert "(7FE0,0010) OB  PixelData" in out
    assert "?? UNEXPLAINED" in out and "Windows PE executable" in out
    assert "!! invalid-vr" in out
    assert "<redacted, 8 bytes>" in out and "DOE^JANE" not in out
    assert "% of bytes explained" in out


def test_map_can_show_phi_on_request(write_file, capsys):
    path = write_file("scan.dcm", part10(el(0x00100010, "PN", "DOE^JANE")))
    main(["map", path, "--show-phi"])
    assert "DOE^JANE" in capsys.readouterr().out


def test_map_rejects_non_dicom(write_file, capsys):
    assert main(["map", write_file("notes.txt", b"hello" * 40)]) == 2
