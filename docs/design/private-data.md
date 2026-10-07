# Design: private data elements

**Status:** implemented (`src/radguard/checks/private.py`), 2026-10-07

## Why private data matters

DICOM lets every vendor store its own attributes in odd-numbered groups (PS3.5 7.8). A **Private Creator** element `(gggg,00xx)` names the implementer and reserves block `xx`; that block's data lives at `(gggg,xx00-xxFF)`. Software that does not recognise a creator skips the entire block. Private data is therefore the part of a DICOM file that the fewest tools ever look at, which also makes it the most convenient place to hide something.

## What RadGuard checks

| Finding | Rule | Why it matters |
|---|---|---|
| `private.orphan-element` | Data element with no creator reserving its block (in the same dataset) | Nothing can attribute it, so every tool ignores it |
| `private.illegal-group` | Private data in groups 0001, 0003, 0005, 0007 or FFFF | Forbidden by PS3.5 7.8.1; readers disagree on how to treat it |
| `private.unusable-element` | `(gggg,0001-000F)` or `(gggg,0100-0FFF)` | Outside any reservable block; no reader can interpret it |
| `private.creator-invalid` | Empty creator, wrong VR, control characters, longer than 64 characters | Readers that match creators by value cannot recognise the block |
| `private.duplicate-creator` | Same creator ID reserving two blocks of one group | Lookup by name returns one block or the other |
| `private.opaque-blob` | 4 KiB or more at 7.5 bits/byte or above, matching no known dense format | How encrypted or compressed data looks, with nothing in the file explaining it |
| `private.compressed-payload` | An executable or container found *after decompressing* a zlib or gzip value | Compression hides it from every signature search of the file itself |
| `private.data-after-stream` | Bytes after the end of a compressed stream | Decompressors stop at the end of the stream, so normal readers never see them |
| `private.decompression-bomb` | Expansion beyond the per-value cap, the 1000:1 ratio, or the per-file budget | Bomb, or data built to exceed analysis budgets |
| `private.analysis-incomplete` | A signature flood inside decompressed data | Same rule as everywhere else: an exhausted budget is evidence |

Creator names also appear in finding locations and in `radguard map`, e.g. `(0029,1010) Private [SIEMENS CSA HEADER]`. Creator values are attacker-controlled, so they are reduced to printable ASCII before display.

## Looking inside compressed values

Signature search sees raw bytes, and an executable compressed with zlib is indistinguishable from noise. So private (and `UN`) values whose first bytes form a valid zlib header (RFC 1950: CM = 8, CINFO ≤ 7, header checksum divisible by 31) or a gzip header are inflated and searched with the same validated carving engine used for the file itself.

Inflating attacker data is the dangerous part. The guards:

- **Per value:** at most 64 MiB, and never more than 1000 times the compressed size.
- **Per file:** at most 256 MiB across all values. The budget is read when a scan starts, so it stays configurable.
- **Never unlimited.** Python's `zlib` treats `max_length=0` as *no limit*. When the remaining budget reaches zero, the value is reported as not inspected and is never passed to the inflater. A regression test pins this (`test_exhausted_file_budget_never_means_unlimited`).
- **No recursion.** Decompressed data is searched once and never decompressed again, so a nested bomb gains nothing.

## Evasion cases handled

- **A fake compression header.** Two bytes such as `78 9C` in front of encrypted data must not exempt it from the entropy check. If inflation fails, the value is judged as raw bytes.
- **A valid stream followed by hidden data.** A tiny real zlib stream followed by encrypted bytes inflates cleanly; the bytes after the end of the stream are reported separately.
- **Floods inside compressed data.** Decoy signatures inside a compressed value trip the same fair-share budget as anywhere else, and the exhaustion is reported.

## Known limitations

- Raw deflate (no zlib or gzip header) cannot be recognised reliably and is judged by entropy only.
- Vendor formats with known internal structure (for example Siemens CSA headers) are not yet parsed; a malformed CSA header is currently judged only by the generic rules.
- Entropy is estimated from the first 64 KiB of a value.
