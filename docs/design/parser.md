# Design: a parser for auditing DICOM, not for reading it

**Status:** implemented (`src/radguard/dicom/`), 2026-10-05

## Problem

Every DICOM library is built to *read* files: when bytes are malformed it guesses, keeps going, and gives the caller a usable dataset. That is the right choice for a viewer and the wrong one for a security tool. An attacker lives in exactly the places where a reader guesses.

We verified this against pydicom 3.0.2, the library most Python imaging and AI pipelines load DICOM with. Each row is an executable test in [`tests/test_differential.py`](../../tests/test_differential.py):

| Crafted file | What pydicom does | Consequence |
|---|---|---|
| Two Pixel Data elements | Silently keeps the **last** one | A reader that keeps the first shows a different image ([figure](../img/two-scans-one-file.png)) |
| Pixel Data longer than Rows x Columns | Returns the extra bytes as **additional frames** | Attacker-chosen pixels reach the AI model while the header describes one image |
| Executable appended after the dataset | Parses it as **invented attributes**: `MZ` becomes group `0x5A4D` | The payload is invisible, and the dataset gains fields nobody wrote |
| Meta says Explicit VR, data is Implicit VR | Switches encoding with only a warning | Strict readers fail where pydicom succeeds |
| File Meta group length is wrong | Ignores it and scans by group | Readers that trust the length find a different dataset start |
| Duplicate Patient Name | Keeps the last | Different software shows different patients |

None of this is a pydicom bug. It is what a reader is supposed to do. RadGuard needs a parser that makes the opposite choices.

## Invariants

1. **Total byte accounting.** Every byte of the file is assigned exactly one class: preamble, magic, element header, value, padding or deflate stream. Bytes with no class are *unexplained*, and unexplained bytes are where payloads hide. Property tests check that `explained + unexplained == file size` for every input.
2. **Never raise on input.** Malformed structure becomes an `Anomaly(code, message, offset)` record. Only bugs raise.
3. **Bounded resources.** Nesting depth (32), element count (1M), inflated size (256 MiB), carving window (64 MiB per region) and signature candidates (4,096 per magic) are capped, so hostile files cannot exhaust the scanner.
4. **Zero copy.** Files are memory-mapped; headers are decoded with `struct.unpack_from` straight from the map; values are decoded only on demand.
5. **Determinism.** Parsing never depends on optional libraries. pydicom, when installed, only supplies display names.

## Recovery model: trust lengths, not content

When structure breaks, the parser raises an internal `_Desync` and unwinds to the nearest container whose **declared length** is still trustworthy, then resumes after it:

```
dataset
 +- (0008,1140) SQ  length 412        <- resync point: parsing resumes at its end
     +- Item  length 200              <- resync point
     |   +- (0010,0010) "zz" ...      <- invalid VR: raise _Desync
     +- Item  undefined length        <- NOT a resync point: its end is a delimiter
         +- ...                          hidden inside content we no longer trust
```

Defined lengths are the only structure that survives corrupt content. An undefined-length container depends on finding a delimiter inside bytes that are already untrusted, so it cannot be a resync point. If no trustworthy boundary exists, everything from the failure to the end of the file stays unexplained and goes to the carver.

The same principle governs overflow: an element whose declared length runs past its container does **not** get to claim those bytes. Its header is recorded and its "value" stays unexplained. Otherwise an attacker could append a payload, give the last element an enormous length, and have the payload accounted for as a legitimate value. The fuzz suite plants exactly this bug (a parser that trusts lengths) to prove the invariants catch it.

## Recognising sequences without a dictionary

Implicit-VR files do not say which elements are sequences, and private sequences are often re-encoded as `UN`. Rather than ship the 5,000-entry data dictionary, the parser recognises sequences **structurally**:

- an undefined length means a sequence (PS3.5 7.5), and an explicit `UN` of undefined length holds an implicit VR little endian sequence (PS3.5 6.2.2);
- a defined-length value that begins with an Item tag whose length fits is *probably* a sequence.

The second rule is a guess, so it is **tentative**: the parser snapshots its anomaly, element and region lists, parses the value as a sequence, and rolls everything back unless the parse is perfectly clean. A coincidental `FE FF 00 E0` at the start of a binary value costs nothing.

## Transfer syntax sniffing

The declared transfer syntax is checked against the first dataset element. If the declared encoding is implausible (invalid VR bytes, or a length that cannot fit) and another encoding is plausible, the parser follows the evidence and records `transfer-syntax-mismatch`. Lenient readers do the same silently; strict readers fail. The disagreement itself is the finding.

## Deflate

Deflated datasets (`1.2.840.10008.1.2.1.99`) are raw deflate streams. Inflation is capped (decompression bombs are reported, not followed). The inflated dataset is parsed in its own offset domain. Bytes after the end of the deflate stream are deliberately left unexplained: no reader looks at them.

## Anomaly to finding

The parser reports facts; `checks/structure.py` decides what they mean. Every anomaly code maps to a severity, a title and a one-line *why it matters*. A test fails if the parser can emit a code with no rule. When an anomaly made the parser stop, it is folded into the finding for the unexplained bytes that follow ("parsing stopped because ..."), so one root cause produces one finding.

## Known limitations

- ~~Values of well-formed elements are not carved.~~ Resolved on day 3: `carving.py` searches the whole buffer once, under a budget that is reported when exhausted, and `checks/values.py` attributes every match to the attribute that holds it.
- **Implicit VR has no VR to validate**, so appended bytes can parse as a few plausible short elements before failing. They are still flagged (tag order, length overflow), and whole-buffer carving finds embedded files regardless of how the bytes parse.
- **The inflated domain** is reported in findings and in `radguard map`, but is not included in the file-level coverage percentage.
