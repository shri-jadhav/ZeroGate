"""
ZeroGate Cloud — Data Loss Prevention (DLP) Package
"""

from dlp.verhoeff import validate_verhoeff, generate_verhoeff_checksum, generate_synthetic_aadhaar
from dlp.patterns import DetectorType, RawMatch
from dlp.redaction import mask_sensitive_value, redact_document_text
from dlp.scanner import DLPScanner, ScanResult, DLPFinding, Severity
from dlp.quarantine import process_file_upload, sanitize_filename, UploadPolicyError

__all__ = [
    "validate_verhoeff",
    "generate_verhoeff_checksum",
    "generate_synthetic_aadhaar",
    "DetectorType",
    "RawMatch",
    "mask_sensitive_value",
    "redact_document_text",
    "DLPScanner",
    "ScanResult",
    "DLPFinding",
    "Severity",
    "process_file_upload",
    "sanitize_filename",
    "UploadPolicyError",
]
