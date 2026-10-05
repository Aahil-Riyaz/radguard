"""Transfer syntaxes: how a dataset is encoded on disk (PS3.5 section 10, PS3.6 Annex A)."""

from __future__ import annotations

from radguard.dicom.model import Syntax

IMPLICIT_LE = "1.2.840.10008.1.2"
EXPLICIT_LE = "1.2.840.10008.1.2.1"
DEFLATED_LE = "1.2.840.10008.1.2.1.99"
EXPLICIT_BE = "1.2.840.10008.1.2.2"

_NATIVE = {
    IMPLICIT_LE: Syntax(IMPLICIT_LE, "Implicit VR Little Endian", implicit=True),
    EXPLICIT_LE: Syntax(EXPLICIT_LE, "Explicit VR Little Endian"),
    DEFLATED_LE: Syntax(DEFLATED_LE, "Deflated Explicit VR Little Endian", deflated=True),
    EXPLICIT_BE: Syntax(EXPLICIT_BE, "Explicit VR Big Endian", little=False),
}

# Everything else in the 1.2.840.10008.1.2.x family is Explicit VR Little
# Endian with encapsulated (fragmented, usually compressed) Pixel Data.
_ENCAPSULATED = {
    "1.2.840.10008.1.2.1.98": "Encapsulated Uncompressed Explicit VR Little Endian",
    "1.2.840.10008.1.2.4.50": "JPEG Baseline",
    "1.2.840.10008.1.2.4.51": "JPEG Extended",
    "1.2.840.10008.1.2.4.57": "JPEG Lossless",
    "1.2.840.10008.1.2.4.70": "JPEG Lossless SV1",
    "1.2.840.10008.1.2.4.80": "JPEG-LS Lossless",
    "1.2.840.10008.1.2.4.81": "JPEG-LS Near-Lossless",
    "1.2.840.10008.1.2.4.90": "JPEG 2000 Lossless",
    "1.2.840.10008.1.2.4.91": "JPEG 2000",
    "1.2.840.10008.1.2.4.92": "JPEG 2000 Multi-component Lossless",
    "1.2.840.10008.1.2.4.93": "JPEG 2000 Multi-component",
    "1.2.840.10008.1.2.4.100": "MPEG2 Main Profile",
    "1.2.840.10008.1.2.4.101": "MPEG2 High Profile",
    "1.2.840.10008.1.2.4.102": "MPEG-4 AVC/H.264 High Profile",
    "1.2.840.10008.1.2.4.103": "MPEG-4 AVC/H.264 BD-compatible",
    "1.2.840.10008.1.2.4.104": "MPEG-4 AVC/H.264 2D Video",
    "1.2.840.10008.1.2.4.105": "MPEG-4 AVC/H.264 3D Video",
    "1.2.840.10008.1.2.4.106": "MPEG-4 AVC/H.264 Stereo",
    "1.2.840.10008.1.2.4.107": "HEVC/H.265 Main Profile",
    "1.2.840.10008.1.2.4.108": "HEVC/H.265 Main 10 Profile",
    "1.2.840.10008.1.2.4.201": "High-Throughput JPEG 2000 Lossless",
    "1.2.840.10008.1.2.4.202": "High-Throughput JPEG 2000 RPCL Lossless",
    "1.2.840.10008.1.2.4.203": "High-Throughput JPEG 2000",
    "1.2.840.10008.1.2.5": "RLE Lossless",
}


def lookup(uid: str | None) -> Syntax:
    if uid is None:
        return Syntax(None, "unknown (assumed Explicit VR Little Endian)", known=False)
    if uid in _NATIVE:
        return _NATIVE[uid]
    if uid.startswith("1.2.840.10008.1.2."):
        name = _ENCAPSULATED.get(uid, f"encapsulated transfer syntax {uid}")
        return Syntax(uid, name, encapsulated=True, known=uid in _ENCAPSULATED)
    return Syntax(uid, f"non-standard transfer syntax {uid}", known=False)
