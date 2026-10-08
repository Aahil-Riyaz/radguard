"""The catalog of everything RadGuard reports: one rule per check id.

A finding carries a check id such as "preamble.pe-polyglot". This module says
what each id means, why it matters, how far a finding can be trusted, and what
to do about it. SARIF output and the rule reference (docs/rules.md) are built
from it, and tests/test_rules.py proves the catalog and the checks agree in
both directions: every id a check can emit has a rule, and every rule is one a
check can emit.

Structural anomaly rules are derived from the structure check's own table, so
their severity and rationale cannot drift from what the check reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from radguard import __url__
from radguard.checks.structure import RULES as ANOMALIES
from radguard.findings import Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
REFERENCE_URL = f"{__url__}/blob/main/docs/rules.md"

# What a rule is evidence of, and what an analyst should do about a finding of that kind.
ADVICE = {
    "malware": "Quarantine the file and keep it away from anything that could run or extract the embedded content. "
               "Extract the payload at the reported offset for malware analysis, find out how the file entered the "
               "archive, and check other files from the same source. Re-saving the file in a viewer is not a fix: "
               "it may keep the payload, and it destroys evidence.",
    "hidden-data": "Extract the bytes at the reported offset (`radguard map` shows the file's layout) and identify "
                   "them. Conforming software never stores data where readers do not look, so the content is either "
                   "a writer bug or deliberately hidden.",
    "differential": "Different DICOM software can read this file differently, so no single viewer's rendering can "
                    "be trusted. Compare what the viewer, the PACS and any AI pipeline actually show; to normalise "
                    "the study, re-acquire it from the source, or rewrite it with a strict toolkit and scan it again.",
    "memory-safety": "Open the file only with current, sandboxed decoders: this is the input class behind decoder "
                     "memory-safety bugs. Quarantine it and trace its source, because crafted headers like this "
                     "rarely occur by accident.",
    "resource": "The file is built to exhaust the resources of software that processes it. Quarantine it, and check "
                "whether any system that ingested it (PACS, router, AI pipeline) slowed down or failed.",
    "incomplete": "Part of the file was not inspected, so the verdict for it is partial. Inspect the reported range "
                  "with other tools. A file that deliberately exhausts analysis budgets should be treated as hostile.",
    "conformance": "Usually a buggy or non-conforming writer rather than an attack. Note the producing software "
                   "(Implementation Class UID and Version Name in the File Meta Information) and report the defect "
                   "to its vendor if it recurs.",
}
PRECISIONS = ("very-high", "high", "medium", "low")  # GitHub code scanning's scale


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity  # the usual severity; a finding can be more or less severe in context
    title: str
    description: str  # what the finding means and why it matters
    kind: str  # a key of ADVICE
    cwe: tuple[int, ...] = ()
    precision: str = "high"  # how often a finding of this rule is a true positive
    references: tuple[str, ...] = ()

    @property
    def advice(self) -> str:
        return ADVICE[self.kind]

    @property
    def name(self) -> str:
        """PascalCase form of the id, for formats that want an identifier: PreamblePePolyglot."""
        return "".join(word.capitalize() for word in re.split(r"[.-]", self.id))

    @property
    def anchor(self) -> str:
        # GitHub's heading anchors: lower case, punctuation other than "-" and "_" removed.
        return re.sub(r"[^a-z0-9_-]", "", self.id.lower())

    @property
    def help_uri(self) -> str:
        return f"{REFERENCE_URL}#{self.anchor}"

    @property
    def tags(self) -> tuple[str, ...]:
        return ("security", self.kind, *(f"external/cwe/cwe-{n}" for n in self.cwe))


# The CWE entries rules refer to. A rule is "relevant" to its CWEs: the file exhibits, or is built to trigger,
# that weakness in the software that reads it.
CWE_NAMES = {
    125: "Out-of-bounds Read",
    130: "Improper Handling of Length Parameter Inconsistency",
    190: "Integer Overflow or Wraparound",
    409: "Improper Handling of Highly Compressed Data (Data Amplification)",
    436: "Interpretation Conflict",
    506: "Embedded Malicious Code",
    514: "Covert Channel",
    674: "Uncontrolled Recursion",
    770: "Allocation of Resources Without Limits or Throttling",
    787: "Out-of-bounds Write",
    1284: "Improper Validation of Specified Quantity in Input",
}


def cwe_uri(number: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


CVE_2019_11687 = "https://nvd.nist.gov/vuln/detail/CVE-2019-11687"
ELFDICOM = "https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/"
PS3_5_PRIVATE = "https://dicom.nema.org/medical/dicom/current/output/chtml/part05/sect_7.8.html"
PS3_5_ENCAPSULATION = "https://dicom.nema.org/medical/dicom/current/output/chtml/part05/sect_A.4.html"
PS3_10_PREAMBLE = "https://dicom.nema.org/medical/dicom/current/output/chtml/part10/chapter_7.html"
EMBEDDED, DIFFERENTIAL, COVERT, LENGTH = 506, 436, 514, 130

_PREAMBLE = "The 128-byte preamble is the first thing any non-DICOM program reads, and PS3.10 leaves it free for "


def _preamble(kind: str, severity: Severity, what: str, why: str, *refs: str) -> Rule:
    code = severity >= H  # formats that run or carry code, as opposed to documents
    return Rule(f"preamble.{kind}", severity, f"{what} in the preamble",
                f"{_PREAMBLE}application use, so it can make one file two formats at once. {why}",
                "malware" if code else "hidden-data", (EMBEDDED, DIFFERENTIAL) if code else (DIFFERENTIAL,),
                "very-high" if severity is C else "high", refs or (CVE_2019_11687,))


_EXPLICIT = (
    Rule("preamble.pe-polyglot", C, "Windows executable in the preamble (PE/DICOM polyglot)",
         "The preamble starts with an MZ header whose e_lfanew field points at a real PE signature further into "
         "the file, so the same bytes are a valid image and a runnable Windows program (CVE-2019-11687). Viewers "
         "display it normally, and because it is \"just a scan\" it often escapes malware inspection.",
         "malware", (EMBEDDED, DIFFERENTIAL), "very-high", (CVE_2019_11687,)),
    Rule("preamble.mz-header", H, "DOS/PE header in the preamble",
         "The preamble starts with an MZ header, but e_lfanew does not point at a PE signature, so the file is "
         "not runnable as it stands. No imaging software writes MZ into the preamble: this is usually a truncated "
         "or staged PE/DICOM polyglot.", "malware", (EMBEDDED,), "high", (CVE_2019_11687,)),
    _preamble("elf-polyglot", C, "ELF executable header",
              "An ELF header needs only its magic at byte 0, so the file runs on Linux-based devices while "
              "remaining a valid image (ELFDICOM).", ELFDICOM),
    _preamble("macho-polyglot", C, "Mach-O executable header",
              "The file can be loaded as a macOS executable while remaining a valid image."),
    _preamble("fat-or-class", H, "Mach-O universal binary or Java class header",
              "Both formats start with CA FE BA BE; either makes the file loadable as code."),
    _preamble("shebang", H, "Script interpreter line",
              "A file that starts with #!/ runs as a script on Unix-like systems once it is marked executable."),
    _preamble("zip", H, "ZIP container header",
              "Tools that identify files by their first bytes treat it as a ZIP-based container (JAR, APK, Office)."),
    _preamble("ole", H, "OLE compound file header",
              "The format of MSI installers and legacy Office documents, both of which can carry code."),
    _preamble("markup", H, "HTML, XML or SVG markup",
              "Browsers and content sniffers treat the file as markup, which runs script (HTML, SVG) when the "
              "file is opened or served from a web context."),
    _preamble("pdf", M, "PDF header",
              "PDF readers accept a header anywhere in the first kilobyte, so the file also opens as a document."),
    _preamble("rtf", M, "RTF header",
              "Word processors open the file as an RTF document, a format with a long history of exploited "
              "parser bugs."),
    _preamble("archive", M, "7z or RAR archive header",
              "Archive tools that identify files by their first bytes open it as an archive."),
    Rule("preamble.nonstandard", L, "Unrecognised non-zero preamble",
         f"{_PREAMBLE}application use, but nearly all software writes zeros or a TIFF header. Unrecognised "
         "content is not evidence of an attack on its own; it is worth identifying because it is what other "
         "programs see first.", "hidden-data", (), "medium", (PS3_10_PREAMBLE,)),

    Rule("structure.hidden-payload", C, "File hidden outside the DICOM structure",
         "Bytes the DICOM structure cannot account for contain a recognised file format, typically an executable "
         "appended after the dataset or left behind a broken element. DICOM readers never display these bytes; "
         "other programs can run or extract them. High rather than critical when the payload is an archive, "
         "a script or a document rather than an executable.",
         "malware", (EMBEDDED,)),
    Rule("structure.unexplained-bytes", M, "Bytes not accounted for by the DICOM structure",
         "Every byte of a conforming file belongs to the preamble, the magic, an element header or a value. "
         "These bytes belong to none of them, so no reader displays them. Severity grows with size: low under "
         "16 bytes, medium under 1 KiB, high above.", "hidden-data", (COVERT,), "very-high"),
    Rule("structure.nonzero-padding", M, "Data hidden in trailing padding",
         "(FFFC,FFFC) Data Set Trailing Padding has no meaning (PS3.10 7.2) and readers skip it unread, so "
         "non-zero content in it is invisible to every DICOM tool. High or critical when it contains a "
         "recognised file.", "hidden-data", (COVERT,), "very-high", (PS3_10_PREAMBLE,)),
    Rule("structure.analysis-incomplete", H, "Part of the file was not inspected",
         "A carving budget was reached. Either the file is larger than the inspection window (low), or it holds "
         "a flood of decoy signatures built to exhaust analysis (high). The range that was not inspected is "
         "reported, so it is never mistaken for clean.", "incomplete", (), "very-high"),

    Rule("pixels.duplicate-pixel-data", C, "Two images in one file",
         "The dataset has more than one Pixel Data element. Software that keeps the first copy and software that "
         "keeps the last display different images from the same file, so a radiologist's viewer and an AI "
         "pipeline can be shown different scans.", "differential", (DIFFERENTIAL,), "very-high"),
    Rule("pixels.multiple-representations", H, "Integer and floating-point pixel data in one file",
         "Pixel Data and (Double) Float Pixel Data are mutually exclusive; which one is displayed depends on the "
         "software.", "differential", (DIFFERENTIAL,), "very-high"),
    Rule("pixels.ambiguous-geometry", H, "Conflicting image dimensions",
         "Rows, Columns, Samples per Pixel, Number of Frames or Bits Allocated appears more than once with "
         "different values, so readers that keep different copies decode the same pixel bytes with different "
         "dimensions.", "differential", (DIFFERENTIAL,), "very-high"),
    Rule("pixels.encoding-mismatch", H, "Pixel Data encoding contradicts the transfer syntax",
         "Compressed transfer syntaxes require encapsulated Pixel Data and native ones require a single value. A "
         "mismatch sends decoders down different code paths for the same bytes.",
         "differential", (DIFFERENTIAL,), "very-high", (PS3_5_ENCAPSULATION,)),
    Rule("pixels.invalid-geometry", M, "Zero or negative image dimension",
         "The image header declares a zero or negative dimension (Number of Frames is text, so \"0\" or \"-5\" is "
         "easy to write). Decoders disagree on what, if anything, to render, and size arithmetic on such values "
         "is a classic source of decoder bugs.", "memory-safety", (1284,), "very-high"),
    Rule("pixels.size-overflow", H, "Image size overflows 32-bit arithmetic",
         "Rows x Columns x Samples x Frames x Bits needs 4 GiB or more. A decoder that computes the size in 32 "
         "bits allocates a small buffer and then writes the full image into it: a heap overflow.",
         "memory-safety", (190, 787), "very-high"),
    Rule("pixels.embedded-file", C, "File stored as image pixels",
         "The declared image area contains a recognised file format. Viewers render it as noise, and nothing that "
         "only displays images will notice. Severity follows what was found: critical for executables.",
         "malware", (EMBEDDED,)),
    Rule("pixels.truncated", H, "Pixel Data shorter than the image it describes",
         "Decoders that trust the header read past the end of the pixel buffer.",
         "memory-safety", (LENGTH, 125), "very-high"),
    Rule("pixels.slack", H, "Data after the last pixel",
         "Pixel Data is longer than the image the header describes. Viewers that honour the header never display "
         "the extra bytes, while lenient decoders (pydicom among them) return them as extra frames: hidden data, "
         "or a hidden image. Severity rises with size, entropy and recognised content.",
         "hidden-data", (COVERT, DIFFERENTIAL), "very-high"),
    Rule("pixels.hidden-frames", H, "More frames than declared",
         "Encapsulated Pixel Data holds more frames than Number of Frames declares; decoders that trust the header "
         "show fewer frames than decoders that walk the fragments.",
         "differential", (DIFFERENTIAL,), "high", (PS3_5_ENCAPSULATION,)),
    Rule("pixels.missing-frames", M, "Fewer frames than declared",
         "Encapsulated Pixel Data holds fewer frames than Number of Frames declares; decoders that trust the header "
         "look for frames that are not there.", "differential", (DIFFERENTIAL,), "high", (PS3_5_ENCAPSULATION,)),
    Rule("pixels.analysis-incomplete", L, "Frames beyond the inspection budget",
         "Compressed frames beyond the per-file reassembly budget were not inspected.",
         "incomplete", (), "very-high"),
    Rule("pixels.malformed-codestream", M, "Malformed compressed frame",
         "A JPEG, JPEG-LS, JPEG 2000 or RLE frame breaks its own format's structure. Malformed codestreams are the "
         "input class behind many image decoder memory-safety bugs.", "memory-safety", (), "high"),
    Rule("pixels.codec-mismatch", H, "Frame is not the codec its transfer syntax declares",
         "A frame does not start with its codec's start marker, so decoders either fail or, if they sniff the "
         "content, decode something else. Critical when the frame is an executable.",
         "differential", (DIFFERENTIAL,), "high"),
    Rule("pixels.codestream-trailing-data", H, "Data after the end of a compressed frame",
         "Decoders stop at a codestream's end marker, so bytes after it are never displayed: a second hidden "
         "image, or an executable. Medium for a few unexplained bytes, critical for an executable.",
         "hidden-data", (COVERT,), "high"),

    Rule("values.embedded-file", C, "File embedded in an attribute value",
         "A recognised file format sits inside an attribute value: a private blob, an unknown-VR value, an item "
         "deep in a sequence. Executables have no business in any attribute (critical), scripts are high and "
         "archives medium; documents and markup are routine vendor practice and reported as low for review.",
         "malware", (EMBEDDED,)),
    Rule("values.document-payload", C, "Executable inside an encapsulated document",
         "An Encapsulated Document (0042,0011), meant to hold a PDF, CDA or similar report, contains an "
         "executable.", "malware", (EMBEDDED,), "very-high"),
    Rule("values.document-type-missing", M, "Encapsulated document without a MIME type",
         "The document has no MIME Type of Encapsulated Document (0042,0012), so viewers must guess how to open "
         "it.", "differential", (DIFFERENTIAL,), "very-high"),
    Rule("values.document-type-mismatch", H, "Encapsulated document is not what it claims",
         "The declared MIME type and the content disagree: software that trusts the declared type and software "
         "that sniffs the content handle the document differently.", "differential", (DIFFERENTIAL,)),

    Rule("private.illegal-group", M, "Private element in a forbidden group",
         "Groups 0001, 0003, 0005, 0007 and FFFF may not carry private data (PS3.5 7.8.1); readers disagree on "
         "whether such elements are standard or private.", "differential", (DIFFERENTIAL,), "very-high",
         (PS3_5_PRIVATE,)),
    Rule("private.unusable-element", M, "Private element outside any reservable block",
         "Only Private Creators (gggg,0010-00FF) and private data elements (gggg,1000-FFFF) are defined, so no "
         "reader can interpret an element elsewhere in a private group, and every reader skips it.",
         "hidden-data", (COVERT,), "very-high", (PS3_5_PRIVATE,)),
    Rule("private.orphan-element", M, "Private data with no creator",
         "No Private Creator reserves the block this element sits in, so no software can attribute it and every "
         "tool ignores it.", "hidden-data", (COVERT,), "very-high", (PS3_5_PRIVATE,)),
    Rule("private.creator-invalid", L, "Malformed Private Creator",
         "A Private Creator is empty, not LO, too long or contains control characters, so readers that match "
         "creators by name cannot recognise the block.", "conformance", (), "very-high", (PS3_5_PRIVATE,)),
    Rule("private.duplicate-creator", L, "Private Creator reserves two blocks",
         "One creator name reserves two blocks of the same group; readers that look a creator up by name find one "
         "block or the other.", "differential", (DIFFERENTIAL,), "very-high", (PS3_5_PRIVATE,)),
    Rule("private.opaque-blob", M, "High-entropy private data of unknown format",
         "At least 4 KiB of private binary data at 7.5 bits/byte or more that matches no known format: that is "
         "how encrypted or compressed data looks, and nothing in the file explains it. Vendors do store "
         "proprietary compressed data, so this is a lead for review rather than proof.",
         "hidden-data", (), "medium"),
    Rule("private.compressed-payload", C, "File hidden inside compressed private data",
         "A zlib or gzip private value decompresses to data containing a recognised file format. Compression "
         "hides it from any signature search of the file itself.", "malware", (EMBEDDED,)),
    Rule("private.data-after-stream", M, "Data hidden after a compressed stream",
         "Bytes follow the end of a compressed private value. Decompressors stop at the end of the stream, so "
         "nothing that reads the value normally sees them.", "hidden-data", (COVERT,), "very-high"),
    Rule("private.decompression-bomb", H, "Compressed private data too large to inspect",
         "A compressed private value expands more than 1000:1, past the per-value limit or past the per-file "
         "budget. That is a decompression bomb aimed at tools that inflate private data, or data built to exceed "
         "analysis budgets; the part that was not inspected is not reported clean.",
         "resource", (409,), "high"),
    Rule("private.analysis-incomplete", H, "Compressed private data built to exhaust analysis",
         "The decompressed content of a private value floods the signature search with decoys, so part of it "
         "could not be inspected.", "incomplete", (), "very-high"),

    Rule("scan.findings-suppressed", M, "Finding flood suppressed",
         "One file produced more findings for one rule than the per-rule cap; the first ones are kept and the "
         "rest are counted. A file that trips the same rule thousands of times is usually built to flood the "
         "report.", "incomplete", (), "very-high"),
)

# Kind and CWE for each structural anomaly; severity, title and rationale come from the check itself.
_ANOMALY_KINDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "invalid-vr": ("differential", (DIFFERENTIAL,)),
    "length-overflow": ("memory-safety", (LENGTH, 125)),
    "truncated-header": ("conformance", ()),
    "odd-length": ("differential", (DIFFERENTIAL,)),
    "duplicate-tag": ("differential", (DIFFERENTIAL,)),
    "tag-order": ("differential", (DIFFERENTIAL,)),
    "meta-group-length-mismatch": ("differential", (DIFFERENTIAL, LENGTH)),
    "missing-meta-group-length": ("conformance", ()),
    "group-length-mismatch": ("differential", (DIFFERENTIAL, LENGTH)),
    "transfer-syntax-mismatch": ("differential", (DIFFERENTIAL,)),
    "missing-transfer-syntax": ("differential", (DIFFERENTIAL,)),
    "unknown-transfer-syntax": ("conformance", ()),
    "reserved-nonzero": ("hidden-data", (COVERT,)),
    "vr-mismatch": ("differential", (DIFFERENTIAL,)),
    "vr-length-mismatch": ("differential", (DIFFERENTIAL,)),
    "stray-delimiter": ("differential", (DIFFERENTIAL,)),
    "bad-sequence-item": ("differential", (DIFFERENTIAL,)),
    "missing-item-delimiter": ("differential", (DIFFERENTIAL,)),
    "missing-sequence-delimiter": ("differential", (DIFFERENTIAL,)),
    "unexpected-delimiter": ("differential", (DIFFERENTIAL,)),
    "delimiter-length": ("differential", (DIFFERENTIAL,)),
    "undefined-length-invalid": ("differential", (DIFFERENTIAL,)),
    "max-depth": ("resource", (674,)),
    "element-limit": ("resource", (770,)),
    "deflate-bomb": ("resource", (409,)),
    "deflate-truncated": ("differential", (DIFFERENTIAL,)),
    "deflate-error": ("differential", (DIFFERENTIAL,)),
    "unterminated-pixel-data": ("differential", (DIFFERENTIAL,)),
    "bad-fragment-item": ("differential", (DIFFERENTIAL,)),
    "undefined-fragment-length": ("differential", (DIFFERENTIAL,)),
    "bad-offset-table": ("differential", (DIFFERENTIAL,)),
    "no-part10-header": ("differential", (DIFFERENTIAL,)),
    "suppressed": ("incomplete", ()),
}


def _anomaly(code: str) -> Rule:
    severity, title, why = ANOMALIES[code]
    kind, cwe = _ANOMALY_KINDS[code]
    return Rule(f"structure.{code}", severity, title, why[0].upper() + why[1:] + ".", kind, cwe, "very-high")


RULES: dict[str, Rule] = {rule.id: rule for rule in (*_EXPLICIT, *map(_anomaly, ANOMALIES))}


_FAMILIES = {"preamble": "Preamble", "structure": "Structure", "pixels": "Pixel data", "values": "Attribute values",
             "private": "Private data", "scan": "Scan"}


def listing() -> str:
    """One line per rule, for `radguard rules`."""
    lines = [f"{str(r.severity):<9} {r.id:<44} {r.title}" for r in sorted(RULES.values(), key=lambda r: r.id)]
    return "\n".join(lines) + f"\n\n{len(RULES)} rules; reference: {REFERENCE_URL}\n"


def reference() -> str:
    """docs/rules.md: every rule with what it means and what to do. tests/test_rules.py keeps the file current."""
    out = ["# Rule reference", "",
           "<!-- Generated by `radguard rules --markdown`. tests/test_rules.py fails if this file is out of date. -->",
           "",
           f"RadGuard reports {len(RULES)} rules. Every finding names its rule, and SARIF reports link each result "
           "to its rule's section here. The severity shown is the usual one; a finding can be more or less "
           "severe in context, as each description says.", "",
           "| Kind | What to do |", "|---|---|"]
    out += [f"| {kind} | {advice} |" for kind, advice in ADVICE.items()]
    for family, heading in _FAMILIES.items():
        out += ["", f"## {heading}"]
        for r in sorted((r for r in RULES.values() if r.id.split(".")[0] == family), key=lambda r: r.id):
            facts = [f"severity **{r.severity}**", f"precision {r.precision}", f"kind {r.kind}"]
            facts += [f"[CWE-{n}]({cwe_uri(n)}) {CWE_NAMES[n]}" for n in r.cwe]
            out += ["", f"### {r.id}", "", f"**{r.title}**. " + ", ".join(facts) + ".", "", r.description]
            if r.references:
                out += ["", "References: " + ", ".join(f"<{url}>" for url in r.references)]
    return "\n".join(out) + "\n"


def rule(check_id: str) -> Rule:
    """The rule for `check_id`. An id missing from the catalog (a bug the tests guard against) still gets a
    descriptor rather than breaking a report."""
    return RULES.get(check_id) or Rule(check_id, M, check_id, "No description is available for this check.",
                                       "hidden-data", (), "medium")
