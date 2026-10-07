"""Exact-edge tests, written to kill surviving mutants (scripts/mutation_test.py).

Each test pins a boundary: the first value that must be treated one way and
the last that must be treated the other, a buffer exactly as long as a
header, a budget of exactly N. A test at a comfortable middle value passes
whether the code says < or <=; these do not.
"""

import struct

import pytest

from builder import (
    DEFLATED_LE, JPEG_BASELINE, PIXEL_DATA, deflate, el, encapsulated, even, fake_elf, fake_pe, image, item, j2k,
    jpeg, part10, rle_frame, seq, us,
)
from conftest import findings_for
from radguard import scanner, signatures
from radguard.carving import Budget, carve
from radguard.checks import codestream
from radguard.codecs import j2k_end, jpeg_end, rle_problem
from radguard.dicom import parse, values
from radguard.findings import Finding, Severity
from radguard.output import safe

MAGICS = sorted({m for s in signatures.SIGNATURES for m in s.scan_magics})
NO_EOI = "no EOI (FF D9) before the end of the frame"


def checks(data: bytes, prefix: str = "") -> dict[str, Finding]:
    return {f.check: f for f in findings_for(data, prefix)}


def element(data: bytes, tag: int):
    return next(e for e in parse(data).elements if e.tag == tag)


# -- output sanitiser: both sides of every range ------------------------------------------------

ESCAPED = [0x00, 0x08, 0x0A, 0x1B, 0x1F, 0x7F, 0x9B, 0x9F, 0x200B, 0x200F, 0x2028, 0x202E,
           0x2060, 0x2064, 0x2066, 0x2069, 0xFEFF]
KEPT = [0x09, 0x20, 0x7E, 0xA0, 0xE9, 0x200A, 0x2010, 0x2027, 0x202F, 0x205F, 0x2065, 0x206A, 0xFEFE, 0xFF00]


@pytest.mark.parametrize("code", ESCAPED, ids=[f"U+{c:04X}" for c in ESCAPED])
def test_unsafe_code_points_are_escaped(code):
    assert safe(chr(code)) == (f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}")


@pytest.mark.parametrize("code", KEPT, ids=[f"U+{c:04X}" for c in KEPT])
def test_neighbouring_code_points_are_kept(code):
    assert safe(chr(code)) == chr(code)


# -- carving budgets ----------------------------------------------------------------------------

def test_flood_threshold_is_exactly_the_fair_share():
    budget = Budget(max_candidates=len(MAGICS) * 2)  # share = 2 candidates per magic
    assert carve(b"MZ.." * 2, budget).exhausted == []
    assert [e.reason for e in carve(b"MZ.." * 3, budget).exhausted] == ["flood"]


def test_fair_share_is_never_zero():
    budget = Budget(max_candidates=1)  # 1 // len(MAGICS) would be 0
    assert carve(b"MZ..", budget).exhausted == []
    assert [e.reason for e in carve(b"MZ..MZ..", budget).exhausted] == ["flood"]


def test_match_at_the_very_first_byte():
    assert [m.offset for m in carve(fake_pe()).matches] == [0]


def test_match_limit_reports_only_a_real_excess():
    assert carve(fake_pe() * 2, Budget(max_matches=2)).exhausted == []
    index = carve(fake_pe() * 3, Budget(max_matches=2))
    assert len(index.matches) == 2 and [e.reason for e in index.exhausted] == ["matches"]


@pytest.mark.parametrize("a", MAGICS)
def test_no_scan_magic_prefixes_or_overlaps_another(a):
    # Pins the two carving lines marked "equivalent" for mutation testing: with no prefix
    # relations, alternation order cannot matter; with no one-byte overlaps, resuming the
    # search one or two bytes after a hit finds the same matches.
    for b in MAGICS:
        assert a == b or not b.startswith(a), (a, b)
        tail = a[1:]
        assert not (tail.startswith(b) or b.startswith(tail)), (a, b)


# -- signature validators: exact lengths and every accepted value ---------------------------------

def test_pe_header_may_end_exactly_at_the_end_of_the_buffer():
    data = bytearray(0x40 + 4)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:] = b"PE\x00\x00"
    assert signatures.pe_header(bytes(data), 0) == 0x40
    assert signatures.pe_header(bytes(data[:-1]), 0) is None


def elf(cls: int = 2, data: int = 1, e_type: int = 2) -> bytes:
    return b"\x7fELF" + bytes([cls, data, 1]) + bytes(9) + struct.pack("<H" if data == 1 else ">H", e_type)


@pytest.mark.parametrize("e_type,label", [(1, "relocatable object"), (2, "executable"), (3, "shared object"),
                                          (4, "core dump")])
def test_every_elf_type(e_type, label):
    assert signatures._elf(elf(e_type=e_type), 0) == f"64-bit {label}"


@pytest.mark.parametrize("header", [elf(e_type=0), elf(e_type=5), elf(cls=0), elf(cls=3), elf(data=3)],
                         ids=["type0", "type5", "class0", "class3", "data3"])
def test_impossible_elf_headers(header):
    assert signatures._elf(header, 0) is None


def test_big_endian_32_bit_elf_and_exact_length():
    header = elf(cls=1, data=2, e_type=3)
    assert len(header) == 18 and signatures._elf(header, 0) == "32-bit shared object"
    assert signatures._elf(header[:-1], 0) is None


@pytest.mark.parametrize("cpu,label", [(7, "x86"), (0x01000007, "x86_64"), (12, "ARM"), (0x0100000C, "ARM64"),
                                       (18, "PowerPC"), (0x01000012, "PowerPC64")])
def test_every_macho_cpu_in_both_byte_orders(cpu, label):
    assert signatures._macho(b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu), 0) == label
    assert signatures._macho(b"\xce\xfa\xed\xfe" + struct.pack("<I", cpu), 0) == label
    assert signatures._macho(b"\xfe\xed\xfa\xce" + struct.pack(">I", cpu), 0) == label


def test_macho_header_needs_eight_bytes():
    assert signatures._macho(b"\xcf\xfa\xed\xfe\x07\x00\x00", 0) is None


@pytest.mark.parametrize("major,ok", [(44, False), (45, True), (80, True), (81, False)])
def test_java_class_version_range(major, ok):
    result = signatures._fat_or_class(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, major), 0)
    assert (result is not None and "Java" in result) is ok


@pytest.mark.parametrize("count,ok", [(0, False), (1, True), (32, True), (33, False)])
def test_universal_binary_architecture_count(count, ok):
    assert (signatures._fat_or_class(b"\xca\xfe\xba\xbe" + struct.pack(">I", count), 0) is not None) is ok


def test_cafebabe_needs_eight_bytes():
    assert signatures._fat_or_class(b"\xca\xfe\xba\xbe\x00\x00\x00", 0) is None


def zip_header(version: int = 20, method: int = 8, name: bytes = b"a.bin") -> bytes:
    return b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", version, 0, method, 0, 0, 0, 0, 0, len(name), 0) + name


@pytest.mark.parametrize("method", sorted(signatures._ZIP_METHODS))
def test_every_zip_method(method):
    assert signatures._zip(zip_header(method=method), 0) is not None


@pytest.mark.parametrize("header,ok", [
    (zip_header(method=1), False), (zip_header(version=63), True), (zip_header(version=64), False),
    (zip_header(name=b"x"), True), (zip_header(name=b"x" * 1024), True), (zip_header(name=b"x" * 1025), False),
    (zip_header(name=b""), False),
], ids=["method1", "v63", "v64", "name1", "name1024", "name1025", "name0"])
def test_zip_field_limits(header, ok):
    assert (signatures._zip(header, 0) is not None) is ok


def test_zip_header_needs_thirty_bytes():
    assert signatures._zip(zip_header()[:29], 0) is None


@pytest.mark.parametrize("data,ok", [(b"{\\rtf1", True), (b"{\\rtf\\", True), (b"{\\rtf!", False), (b"{\\rtf", False)])
def test_rtf_control_word(data, ok):
    assert (signatures._rtf(data, 0) is not None) is ok


def test_printable_boundaries():
    assert signatures.printable(bytes([0x1F, 0x20, 0x7E, 0x7F])) == ". ~."
    assert signatures.printable(b"x" * 40) == "x" * 40
    assert signatures.printable(b"x" * 41) == "x" * 40 + "..."


# -- codec walkers: exact ends ------------------------------------------------------------------

def test_jpeg_marker_code_at_the_last_byte():
    assert jpeg_end(b"\xff\xd8\xff\xe0") == (None, NO_EOI)  # no length to read, and no crash


def test_jpeg_segment_ending_exactly_at_the_frame_end():
    assert jpeg_end(b"\xff\xd8\xff\xe0\x00\x04ab") == (None, NO_EOI)


def test_j2k_minimal_tile_part_is_valid():
    data = j2k(tile=b"")  # Psot = 14: SOT (12 bytes) + SOD (2 bytes), no data
    assert j2k_end(data) == (len(data), None)


def test_j2k_tile_part_header_exactly_complete_or_truncated():
    data = j2k()  # Psot = 18
    sot = data.index(b"\xff\x90")
    assert j2k_end(data[: sot + 12]) == (None, f"expected EOC (FF D9) at frame offset {sot + 18:#x}")
    assert j2k_end(data[: sot + 11]) == (None, f"expected EOC (FF D9) at frame offset {sot:#x}")


def test_j2k_last_tile_part_without_eoc():
    end, problem = j2k_end(j2k(psot_zero=True)[:-2])
    assert end is None and "no EOC" in problem


def test_j2k_header_segment_limits():
    main = b"\xff\x4f\xff\x51\x00\x02"  # SIZ with an empty body (length 2) is structurally fine
    assert j2k_end(main + b"\xff\x90\x00\x0a") == (None, "expected EOC (FF D9) at frame offset 0x6")
    assert "runs past" in j2k_end(main + b"\xff\x52\x00")[1]
    assert "invalid main header marker FF52" in j2k_end(main + b"\xff\x52\x00\x01" + bytes(4))[1]
    assert "invalid main header marker 1234" in j2k_end(main + b"\x12\x34\x00\x04\x00\x00")[1]


@pytest.mark.parametrize("count,ok", [(15, True), (16, False)])
def test_rle_segment_count_limit(count, ok):
    used = min(count, 15)
    frame = struct.pack("<16I", count, *[64 + 2 * i for i in range(used)], *[0] * (15 - used)) + bytes(40)
    assert (rle_problem(frame) is None) is ok


def test_rle_offset_must_lie_inside_the_frame():
    header = struct.pack("<16I", 1, 64, *[0] * 14)
    assert rle_problem(header) is not None  # offset == frame length
    assert rle_problem(header + b"\x00") is None


# -- codestream check ------------------------------------------------------------------------------

def raw_compressed(*fragments: bytes, frames: int | None = None, ts: str = JPEG_BASELINE, extra: bytes = b"") -> bytes:
    """Encapsulated image with fragments exactly as given (odd lengths only raise an anomaly)."""
    return part10(image(8, 8, frames=frames, extra=extra, pixel_element=encapsulated(*fragments)), ts=ts)


def pixel_element(data: bytes):
    return next(e for e in parse(data).elements if e.tag == PIXEL_DATA)


def test_offset_table_grouping_is_exact():
    a, b, c = even(jpeg()), even(jpeg()), even(jpeg())
    bot = struct.pack("<2I", 0, (8 + len(a)) + (8 + len(b)))
    data = part10(image(8, 8, frames=2, pixel_element=encapsulated(a, b, c, bot=bot)), ts=JPEG_BASELINE)
    groups = codestream._frames(data, pixel_element(data), "jpeg", 2)
    assert [[length for _, length in g] for g in groups] == [[len(a), len(b)], [len(c)]]


@pytest.mark.parametrize("frames", [0, -3])
def test_nonsense_frame_count_means_one(frames):
    assert checks(raw_compressed(even(jpeg()), frames=frames), "pixels.") == {}


def test_rle_fragments_without_start_markers_are_frames():
    data = raw_compressed(rle_frame(), rle_frame(), rle_frame(), frames=2, ts="1.2.840.10008.1.2.5")
    assert checks(data, "pixels.")["pixels.hidden-frames"].title == "1 undeclared frame(s)"


def test_frame_budget_boundary(monkeypatch):
    frame = even(jpeg())
    monkeypatch.setattr(codestream, "MAX_FRAME_BYTES", len(frame))
    assert "pixels.analysis-incomplete" not in checks(raw_compressed(frame), "pixels.")
    monkeypatch.setattr(codestream, "MAX_FRAME_BYTES", len(frame) - 1)
    data = raw_compressed(frame)
    assert checks(data, "pixels.")["pixels.analysis-incomplete"].offset == pixel_element(data).fragments[0][0]


@pytest.mark.parametrize("tail,flagged", [(b"\x00", False), (b"\x00\x00", True), (b"\x01", True)],
                         ids=["one-zero", "two-zeros", "one-nonzero"])
def test_single_zero_pad_byte_is_the_only_free_tail(tail, flagged):
    assert ("pixels.codestream-trailing-data" in checks(raw_compressed(jpeg() + tail), "pixels.")) is flagged


@pytest.mark.parametrize("n,severity", [(63, Severity.MEDIUM), (64, Severity.HIGH)])
def test_trailing_bytes_title_severity_and_offset(n, severity):
    frame = jpeg()
    data = raw_compressed(frame + bytes(range(1, n + 1)))  # no image, no executable
    finding = checks(data, "pixels.")["pixels.codestream-trailing-data"]
    assert finding.title == f"{n} bytes hidden after the end of a compressed frame"
    assert finding.severity is severity
    assert finding.offset == pixel_element(data).fragments[0][0] + len(frame)


def test_trailing_offset_in_a_later_fragment():
    frame = jpeg()
    data = raw_compressed(frame[:40], frame[40:] + b"\x01\x02\x03\x04")
    finding = checks(data, "pixels.")["pixels.codestream-trailing-data"]
    assert finding.offset == pixel_element(data).fragments[1][0] + len(frame) - 40


def test_second_image_position_and_payload_precedence():
    finding = checks(raw_compressed(jpeg() + b"\x00\x00" + jpeg()), "pixels.")["pixels.codestream-trailing-data"]
    assert "a second image starts 2 bytes after the end" in finding.detail
    both = checks(raw_compressed(jpeg() + jpeg() + fake_pe()), "pixels.")["pixels.codestream-trailing-data"]
    assert both.title.endswith("bytes hidden after the end of a compressed frame")


def test_nested_pixel_data_is_not_the_image_but_is_still_searched():
    icon = seq(0x00880200, item(us(0x00280010, 2) + el(PIXEL_DATA, "OB", fake_pe(96))))
    data = part10(image(8, 8, extra=icon, pixel_element=encapsulated(even(jpeg()))), ts=JPEG_BASELINE)
    found = checks(data)
    assert "pixels.codec-mismatch" not in found and "pixels.duplicate-pixel-data" not in found
    assert found["values.embedded-file"].severity is Severity.CRITICAL


# -- pixels ---------------------------------------------------------------------------------------

def manual_image(rows=4, cols=4, spp=None, bits=8, stored=None, frames=None, pixels=None) -> bytes:
    out = el(0x00080016, "UI", "1.2.840.10008.5.1.4.1.1.2")
    if spp is not None:
        out += us(0x00280002, spp)
    if frames is not None:
        out += el(0x00280008, "IS", str(frames))
    out += us(0x00280010, rows) + us(0x00280011, cols) + us(0x00280100, bits) + us(0x00280101, stored or bits)
    size = (rows * cols * (spp or 1) * (frames or 1) * bits + 7) // 8
    return part10(out + el(PIXEL_DATA, "OB", pixels if pixels is not None else bytes(size)))


def test_rgb_image_size_uses_samples_per_pixel():
    assert checks(manual_image(spp=3), "pixels.") == {}
    assert "pixels.truncated" in checks(manual_image(spp=3, pixels=bytes(16)), "pixels.")


def test_missing_samples_per_pixel_means_one():
    assert checks(manual_image(spp=None), "pixels.") == {}


def test_size_uses_bits_allocated_not_bits_stored():
    assert checks(manual_image(bits=16, stored=12), "pixels.") == {}  # the usual CT layout


def test_exactly_four_gibibytes_overflows():
    assert "pixels.size-overflow" in checks(manual_image(rows=32768, cols=32768, bits=32, pixels=bytes(16)), "pixels.")


def test_pad_byte_after_odd_sized_image():
    assert checks(manual_image(rows=3, cols=3, pixels=bytes(10)), "pixels.") == {}
    data = manual_image(rows=3, cols=3, pixels=bytes(12))
    slack = checks(data, "pixels.")["pixels.slack"]
    assert slack.offset == pixel_element(data).value_offset + 10
    assert slack.title == "2 bytes hidden after the last pixel"


def test_sub_byte_frames_never_divide_by_zero():
    data = manual_image(rows=1, cols=1, bits=1, frames=2, pixels=bytes(1) + b"hidden")
    assert checks(data, "pixels.")["pixels.slack"].title == "5 bytes hidden after the last pixel"


@pytest.mark.parametrize("extra,severity", [
    (bytes(4094), Severity.MEDIUM), (bytes(4096), Severity.HIGH),
    (bytes(range(128)) * 2, Severity.MEDIUM),  # 256 bytes at exactly 7.0 bits/byte
    (bytes(range(256)), Severity.HIGH),  # 256 bytes at 8.0 bits/byte
    (bytes(range(254)), Severity.MEDIUM),  # high entropy, but under 256 bytes
    (b"a" * 300, Severity.MEDIUM),  # 256 bytes or more, low entropy
], ids=["4094-zero", "4096-zero", "256-at-7.0", "256-at-8.0", "254-random", "300-low-entropy"])
def test_slack_severity_thresholds(extra, severity):
    frame = 128 * 64  # larger than any slack here, so no slack counts as a hidden frame
    data = manual_image(rows=128, cols=64, pixels=bytes(frame) + extra)
    assert checks(data, "pixels.")["pixels.slack"].severity is severity


def test_icon_image_pixel_data_is_not_a_second_image():
    icon = seq(0x00880200, item(us(0x00280010, 2) + us(0x00280011, 2) + el(PIXEL_DATA, "OB", bytes(4))))
    assert "pixels.duplicate-pixel-data" not in checks(part10(image(4, 4, extra=icon)), "pixels.")


def test_float_pixel_data_finding_points_at_the_float_element():
    data = part10(image(4, 4) + el(0x7FE00008, "OF", bytes(64)))
    assert checks(data, "pixels.")["pixels.multiple-representations"].offset == element(data, 0x7FE00008).offset


# -- preamble -------------------------------------------------------------------------------------

def test_preamble_findings_point_at_byte_zero_with_the_right_reference():
    elf_found = checks(part10(preamble=fake_elf()), "preamble.")["preamble.elf-polyglot"]
    assert elf_found.offset == 0 and elf_found.title.endswith("(polyglot)")
    assert "praetorian" in elf_found.references[0]
    zip_found = checks(part10(preamble=b"PK\x03\x04"), "preamble.")["preamble.zip"]
    assert not zip_found.title.endswith("(polyglot)") and "CVE-2019-11687" in zip_found.references[0]
    assert checks(part10(preamble=b"VENDOR"), "preamble.")["preamble.nonstandard"].offset == 0


def test_mz_header_reports_its_pointer():
    pre = bytearray(b"MZ".ljust(128, b"\x00"))
    struct.pack_into("<I", pre, 0x3C, 0x1234)
    finding = checks(part10(preamble=bytes(pre)), "preamble.")["preamble.mz-header"]
    assert "e_lfanew=0x1234" in finding.detail and finding.offset == 0


# -- structure ------------------------------------------------------------------------------------

@pytest.mark.parametrize("n,severity", [(15, Severity.LOW), (16, Severity.MEDIUM), (1023, Severity.MEDIUM),
                                        (1024, Severity.HIGH)])
def test_unexplained_bytes_severity_thresholds(n, severity):
    finding = checks(part10(image(4, 4)) + b"\x41" * n, "structure.")["structure.unexplained-bytes"]
    assert finding.severity is severity and finding.title.startswith(f"{n:,} bytes")


def test_findings_in_the_inflated_dataset_say_so():
    data = part10(deflate(image(4, 4) + b"\x41" * 20), ts=DEFLATED_LE)
    detail = checks(data, "structure.")["structure.unexplained-bytes"].detail
    assert detail.startswith("[offsets within the inflated dataset]")


# -- locations and values -------------------------------------------------------------------------

def test_value_text_boundaries():
    six = part10(el(0x00091010, "US", struct.pack("<6H", *range(6))))
    seven = part10(el(0x00091010, "US", struct.pack("<7H", *range(7))))
    assert not values.text(six, element(six, 0x00091010)).endswith("...")
    assert values.text(seven, element(seven, 0x00091010)).endswith("\\...")
    edge = part10(el(0x00081030, "LO", b" ~\x7f" + b"x" * 35))  # 38 characters + 2 quotes = width 40
    assert values.text(edge, element(edge, 0x00081030)) == '" ~.' + "x" * 35 + '"'
    over = part10(el(0x00081030, "LO", b"x" * 39))
    assert values.text(over, element(over, 0x00081030)).endswith("...")


# -- scanner ----------------------------------------------------------------------------------------

def test_smallest_part10_file_is_dicom(write_file):
    assert scanner.scan_file(write_file("min.dcm", bytes(128) + b"DICM")).is_dicom


def test_error_results_are_never_dicom(tmp_path):
    result = scanner.scan_file(str(tmp_path / "missing.dcm"))
    assert result.error and result.is_dicom is False


def test_read_limit_boundary(write_file, monkeypatch):
    data = part10(image(4, 4))
    path = write_file("a.dcm", data)
    monkeypatch.setattr(scanner, "READ_LIMIT", len(data))
    with scanner.open_dicom(path) as ctx:
        assert isinstance(ctx.buf, bytes)
    monkeypatch.setattr(scanner, "READ_LIMIT", len(data) - 1)
    with scanner.open_dicom(path) as ctx:
        assert not isinstance(ctx.buf, bytes)


def test_dicom_files_are_read_head_first_then_the_rest(write_file, monkeypatch):
    reads = []
    real = scanner._read
    monkeypatch.setattr(scanner, "_read", lambda fd, n: reads.append(n) or real(fd, n))
    data = part10(image(64, 64))
    scanner.scan_file(write_file("a.dcm", data))
    assert reads == [scanner.SNIFF_LEN, len(data) - scanner.SNIFF_LEN]


def test_suppressed_finding_count_is_exact(write_file):
    def noisy(ctx):
        return [Finding("test.noise", Severity.LOW, "noise", "", ctx.path) for _ in range(250)]

    result = scanner.scan_file(write_file("a.dcm", part10()), checks=[noisy])
    assert "suppressed 150 x test.noise" in result.findings[-1].detail


# -- round 2: survivors of the second mutation run ------------------------------------------------

ZIP_SPEC_METHODS = [0, 8, 9, 12, 14, 93, 95, 98, 99]  # stored, deflate, deflate64, bzip2, LZMA, zstd, xz, PPMd, AES


@pytest.mark.parametrize("method", ZIP_SPEC_METHODS)
def test_zip_methods_from_the_specification(method):
    # Written out from the ZIP specification, not read from the module, so a typo in the module fails.
    assert signatures._zip(zip_header(method=method), 0) is not None


def test_zip_local_header_of_exactly_thirty_bytes_validates():
    assert signatures._zip(zip_header()[:30], 0) is not None


def test_preamble_descriptions_start_at_byte_zero():
    vendor = checks(part10(preamble=b"VENDOR"), "preamble.")["preamble.nonstandard"]
    assert "first bytes 56 45 4e 44 4f 52" in vendor.detail
    pre = bytearray(b"MZ".ljust(128, b"\x00"))
    struct.pack_into("<I", pre, 0x3C, 0x1234)
    assert "first bytes 4d 5a" in checks(part10(preamble=bytes(pre)), "preamble.")["preamble.mz-header"].detail


def test_frame_count_comes_from_the_top_level_only():
    nested = seq(0x00081140, item(el(0x00280008, "IS", "5")))  # a referenced image's frame count
    data = part10(nested + image(8, 8, frames=2, pixel_element=encapsulated(even(jpeg()), even(jpeg()))),
                  ts=JPEG_BASELINE)
    assert checks(data, "pixels.") == {}


def test_frame_split_across_fragments_with_several_frames():
    frame = jpeg()
    data = raw_compressed(frame[:40], frame[40:] + b"\x00", even(jpeg()), frames=2)
    assert "pixels.hidden-frames" not in checks(data, "pixels.")


def test_codec_findings_point_at_the_first_fragment():
    data = raw_compressed(bytes.fromhex("00112233") * 8)
    finding = checks(data, "pixels.")["pixels.codec-mismatch"]
    assert finding.offset == pixel_element(data).fragments[0][0] and "first bytes 00 11 22 33" in finding.detail
    broken = raw_compressed(jpeg()[:-2] + b"\x00\x00")
    malformed = checks(broken, "pixels.")["pixels.malformed-codestream"]
    assert malformed.offset == pixel_element(broken).fragments[0][0] and malformed.detail.startswith("frame 1:")


def test_trailing_data_starting_exactly_at_a_fragment_boundary():
    frame = jpeg() + b"\x00"  # ends exactly at the end of the first fragment (with its pad byte)
    data = raw_compressed(frame[:-1], b"HIDDEN-DATA!")
    finding = checks(data, "pixels.")["pixels.codestream-trailing-data"]
    assert finding.offset == pixel_element(data).fragments[1][0]


def test_walk_error_and_note_results_are_not_dicom(tmp_path, monkeypatch):
    import os

    (tmp_path / "sub").mkdir()
    monkeypatch.setattr(os.path, "islink", lambda p: os.path.basename(p) == "sub")
    [note] = [r for r in scanner.scan_paths([str(tmp_path)]) if r.note]
    assert note.is_dicom is False
