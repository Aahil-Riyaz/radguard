"""A deliberately small data dictionary.

The parser does not need the full ~5,000-entry DICOM dictionary: sequences
are recognised structurally (undefined length, or a value that starts with an
Item tag). This table covers the attributes RadGuard reasons about plus common
ones that make `radguard map` readable. If pydicom is installed its dictionary
supplies *names only*, never parsing decisions, so parsing behaves identically
with or without it.
"""

from __future__ import annotations

from radguard.dicom.model import ITEM, ITEM_DELIM, SEQ_DELIM

# tag: (allowed VRs separated by "/", keyword). For implicit VR the last VR is used.
_TABLE: dict[int, tuple[str, str]] = {
    0x00020000: ("UL", "FileMetaInformationGroupLength"),
    0x00020001: ("OB", "FileMetaInformationVersion"),
    0x00020002: ("UI", "MediaStorageSOPClassUID"),
    0x00020003: ("UI", "MediaStorageSOPInstanceUID"),
    0x00020010: ("UI", "TransferSyntaxUID"),
    0x00020012: ("UI", "ImplementationClassUID"),
    0x00020013: ("SH", "ImplementationVersionName"),
    0x00020016: ("AE", "SourceApplicationEntityTitle"),
    0x00080005: ("CS", "SpecificCharacterSet"),
    0x00080008: ("CS", "ImageType"),
    0x00080016: ("UI", "SOPClassUID"),
    0x00080018: ("UI", "SOPInstanceUID"),
    0x00080020: ("DA", "StudyDate"),
    0x00080030: ("TM", "StudyTime"),
    0x00080050: ("SH", "AccessionNumber"),
    0x00080060: ("CS", "Modality"),
    0x00080070: ("LO", "Manufacturer"),
    0x00080080: ("LO", "InstitutionName"),
    0x00080090: ("PN", "ReferringPhysicianName"),
    0x00081030: ("LO", "StudyDescription"),
    0x0008103E: ("LO", "SeriesDescription"),
    0x00081090: ("LO", "ManufacturerModelName"),
    0x00081140: ("SQ", "ReferencedImageSequence"),
    0x00082112: ("SQ", "SourceImageSequence"),
    0x00100010: ("PN", "PatientName"),
    0x00100020: ("LO", "PatientID"),
    0x00100030: ("DA", "PatientBirthDate"),
    0x00100040: ("CS", "PatientSex"),
    0x00101000: ("LO", "OtherPatientIDs"),
    0x00101010: ("AS", "PatientAge"),
    0x00101040: ("LO", "PatientAddress"),
    0x00102154: ("SH", "PatientTelephoneNumbers"),
    0x00180015: ("CS", "BodyPartExamined"),
    0x00180050: ("DS", "SliceThickness"),
    0x00180060: ("DS", "KVP"),
    0x00181020: ("LO", "SoftwareVersions"),
    0x00181150: ("IS", "ExposureTime"),
    0x00181151: ("IS", "XRayTubeCurrent"),
    0x00181210: ("SH", "ConvolutionKernel"),
    0x0020000D: ("UI", "StudyInstanceUID"),
    0x0020000E: ("UI", "SeriesInstanceUID"),
    0x00200010: ("SH", "StudyID"),
    0x00200011: ("IS", "SeriesNumber"),
    0x00200013: ("IS", "InstanceNumber"),
    0x00200032: ("DS", "ImagePositionPatient"),
    0x00200037: ("DS", "ImageOrientationPatient"),
    0x00201041: ("DS", "SliceLocation"),
    0x00280002: ("US", "SamplesPerPixel"),
    0x00280004: ("CS", "PhotometricInterpretation"),
    0x00280008: ("IS", "NumberOfFrames"),
    0x00280010: ("US", "Rows"),
    0x00280011: ("US", "Columns"),
    0x00280030: ("DS", "PixelSpacing"),
    0x00280100: ("US", "BitsAllocated"),
    0x00280101: ("US", "BitsStored"),
    0x00280102: ("US", "HighBit"),
    0x00280103: ("US", "PixelRepresentation"),
    0x00281050: ("DS", "WindowCenter"),
    0x00281051: ("DS", "WindowWidth"),
    0x00281052: ("DS", "RescaleIntercept"),
    0x00281053: ("DS", "RescaleSlope"),
    0x00400275: ("SQ", "RequestAttributesSequence"),
    0x00420011: ("OB", "EncapsulatedDocument"),
    0x00880200: ("SQ", "IconImageSequence"),
    0x7FE00008: ("OF", "FloatPixelData"),
    0x7FE00009: ("OD", "DoubleFloatPixelData"),
    0x7FE00010: ("OB/OW", "PixelData"),
    0xFFFCFFFC: ("OB", "DataSetTrailingPadding"),
}

# Attributes RadGuard's own reasoning depends on. An explicit VR that disagrees
# with the standard here means dictionary-driven and header-driven parsers
# decode different values from the same bytes.
_CRITICAL = frozenset({
    0x00020000, 0x00020010, 0x00280002, 0x00280008, 0x00280010, 0x00280011,
    0x00280100, 0x00280101, 0x00280102, 0x00280103, 0x7FE00010,
})

# Attributes `radguard map` masks unless asked to show them.
PHI_TAGS = frozenset({
    0x00080050, 0x00080080, 0x00080090, 0x00100010, 0x00100020, 0x00100030,
    0x00101000, 0x00101040, 0x00102154,
})

_STRUCTURAL = {ITEM: "Item", ITEM_DELIM: "ItemDelimitationItem", SEQ_DELIM: "SequenceDelimitationItem"}

try:  # optional: better names in `radguard map`
    from pydicom.datadict import keyword_for_tag as _pydicom_keyword
except ImportError:  # pragma: no cover - exercised when pydicom is absent
    _pydicom_keyword = None


def vr(tag: int) -> str | None:
    """VR to assume for `tag` under an implicit-VR transfer syntax."""
    entry = _TABLE.get(tag)
    return entry[0].rsplit("/", 1)[-1] if entry else None


def allowed_vrs(tag: int) -> tuple[str, ...]:
    """VRs the standard permits for a critical attribute (empty if we do not police it)."""
    return tuple(_TABLE[tag][0].split("/")) if tag in _CRITICAL else ()


def keyword(tag: int) -> str:
    if tag in _TABLE:
        return _TABLE[tag][1]
    if tag in _STRUCTURAL:
        return _STRUCTURAL[tag]
    group, elem = tag >> 16, tag & 0xFFFF
    if group % 2:
        if elem == 0:
            return "PrivateGroupLength"
        return "PrivateCreator" if 0x0010 <= elem <= 0x00FF else "Private"
    if elem == 0:
        return "GroupLength"
    if _pydicom_keyword is not None:
        try:
            return _pydicom_keyword(tag) or "Unknown"
        except Exception:  # pydicom raises on malformed tags; names are cosmetic
            return "Unknown"
    return "Unknown"
