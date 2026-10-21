"""
ZeroGate Cloud — DLP Scanner Core Engine
Executes text and file scanning, aggregates findings into structured severity
reports, and determines policy decisions (ACCEPT, REJECT, QUARANTINE).
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass, asdict

from dlp.patterns import DetectorType, RawMatch, scan_all_patterns
from dlp.redaction import mask_sensitive_value, redact_document_text


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Severity and remediation mapping for each detector type
DETECTOR_METADATA: Dict[DetectorType, Dict[str, Any]] = {
    DetectorType.AADHAAR: {
        "severity": Severity.HIGH,
        "name": "Indian Aadhaar Identity Number",
        "remediation": "Do not transmit government identity numbers in unencrypted files. Mask all digits except the last 4 or use designated identity tokenization services."
    },
    DetectorType.PAN: {
        "severity": Severity.HIGH,
        "name": "Indian Permanent Account Number (PAN)",
        "remediation": "PAN is sensitive financial tax data. Redact middle characters or verify if data processing is covered under authorized statutory retention."
    },
    DetectorType.AWS_KEY: {
        "severity": Severity.CRITICAL,
        "name": "AWS IAM Access Key ID",
        "remediation": "Revoke and rotate this AWS access key immediately in AWS IAM Console. Migrate credentials to AWS IAM Roles or Secrets Manager."
    },
    DetectorType.AWS_SECRET: {
        "severity": Severity.CRITICAL,
        "name": "AWS Secret Access Key",
        "remediation": "High-risk credential exposure! Immediately deactivate the associated Access Key pair in AWS IAM and audit CloudTrail logs for unauthorized API calls."
    },
    DetectorType.GITHUB_TOKEN: {
        "severity": Severity.CRITICAL,
        "name": "GitHub Personal Access Token",
        "remediation": "Revoke this token immediately under GitHub Settings -> Developer settings -> Personal access tokens. Review audit logs for unauthorized repo access."
    },
    DetectorType.OPENAI_KEY: {
        "severity": Severity.CRITICAL,
        "name": "OpenAI API Secret Key",
        "remediation": "Revoke this API key in the OpenAI platform dashboard and generate a new key with restricted permissions."
    },
    DetectorType.GOOGLE_KEY: {
        "severity": Severity.HIGH,
        "name": "Google Cloud API Key",
        "remediation": "Restrict API key to specific HTTP referrers / IP addresses and authorized GCP APIs in Google Cloud Console."
    },
    DetectorType.ZEROGATE_TOKEN: {
        "severity": Severity.CRITICAL,
        "name": "ZeroGate Platform API Token",
        "remediation": "ZeroGate internal credential exposed! Rotate the token in the ZeroGate Keycloak/Identity management console."
    },
    DetectorType.GENERIC_API_KEY: {
        "severity": Severity.MEDIUM,
        "name": "Generic High-Entropy API Token",
        "remediation": "Store API tokens in environment variables or a secure secret manager (e.g., Vault, AWS Secrets Manager) rather than static files."
    },
}

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class DLPFinding:
    detector: str
    detector_name: str
    severity: str
    match_count: int
    masked_samples: List[str]
    remediation: str


@dataclass
class ScanResult:
    target_id: str
    is_sensitive: bool
    decision: str  # "ACCEPT", "REJECT", "QUARANTINE"
    max_severity: str
    total_findings_count: int
    findings: List[DLPFinding]
    scanned_bytes: int
    redacted_content: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "is_sensitive": self.is_sensitive,
            "decision": self.decision,
            "max_severity": self.max_severity,
            "total_findings_count": self.total_findings_count,
            "findings": [asdict(f) for f in self.findings],
            "scanned_bytes": self.scanned_bytes,
            "error": self.error,
        }


class DLPScanner:
    """ZeroGate Cloud DLP Inspection Engine."""

    def __init__(
        self,
        quarantine_threshold: Severity = Severity.HIGH,
        max_file_size_bytes: int = 5 * 1024 * 1024,
        excluded_detectors: Optional[Set[DetectorType]] = None,
    ):
        self.quarantine_threshold = quarantine_threshold
        self.max_file_size_bytes = max_file_size_bytes
        self.excluded_detectors = excluded_detectors or set()

    def scan_text(self, text: str, context_id: str = "inline_text") -> ScanResult:
        """Scans arbitrary text and returns structured findings and decision."""
        if not text:
            return ScanResult(
                target_id=context_id,
                is_sensitive=False,
                decision="ACCEPT",
                max_severity=Severity.INFO.value,
                total_findings_count=0,
                findings=[],
                scanned_bytes=0,
                redacted_content=text,
            )

        scanned_bytes = len(text.encode("utf-8", errors="replace"))

        # Run all detectors
        raw_matches = scan_all_patterns(text)

        # Filter out any excluded detectors
        if self.excluded_detectors:
            raw_matches = [m for m in raw_matches if m.detector not in self.excluded_detectors]

        if not raw_matches:
            return ScanResult(
                target_id=context_id,
                is_sensitive=False,
                decision="ACCEPT",
                max_severity=Severity.INFO.value,
                total_findings_count=0,
                findings=[],
                scanned_bytes=scanned_bytes,
                redacted_content=text,
            )

        # Aggregate matches by detector
        grouped: Dict[DetectorType, List[RawMatch]] = {}
        for m in raw_matches:
            grouped.setdefault(m.detector, []).append(m)

        findings: List[DLPFinding] = []
        max_sev = Severity.INFO

        for det_type, matches_list in grouped.items():
            meta = DETECTOR_METADATA.get(det_type, {
                "severity": Severity.MEDIUM,
                "name": det_type.value,
                "remediation": "Review sensitive content and redact as necessary."
            })
            sev: Severity = meta["severity"]
            if _SEVERITY_ORDER[sev] > _SEVERITY_ORDER[max_sev]:
                max_sev = sev

            # Masked sample values (deduped, max 3)
            samples = list(dict.fromkeys([mask_sensitive_value(det_type, m.raw_value) for m in matches_list]))[:3]

            findings.append(DLPFinding(
                detector=det_type.value,
                detector_name=meta["name"],
                severity=sev.value,
                match_count=len(matches_list),
                masked_samples=samples,
                remediation=meta["remediation"],
            ))

        # Determine decision
        if _SEVERITY_ORDER[max_sev] >= _SEVERITY_ORDER[self.quarantine_threshold]:
            decision = "QUARANTINE"
        elif _SEVERITY_ORDER[max_sev] >= _SEVERITY_ORDER[Severity.MEDIUM]:
            decision = "REJECT"
        else:
            decision = "ACCEPT"

        # Generate redacted content
        redacted = redact_document_text(text, raw_matches)

        return ScanResult(
            target_id=context_id,
            is_sensitive=True,
            decision=decision,
            max_severity=max_sev.value,
            total_findings_count=len(raw_matches),
            findings=findings,
            scanned_bytes=scanned_bytes,
            redacted_content=redacted,
        )

    def scan_file(self, file_path: Path) -> ScanResult:
        """Safely scans a file from disk with size checks and encoding fallbacks."""
        path = Path(file_path)
        if not path.exists():
            return ScanResult(
                target_id=str(path.name),
                is_sensitive=False,
                decision="REJECT",
                max_severity=Severity.INFO.value,
                total_findings_count=0,
                findings=[],
                scanned_bytes=0,
                error=f"File not found: {path.name}",
            )

        file_size = path.stat().st_size
        if file_size > self.max_file_size_bytes:
            return ScanResult(
                target_id=str(path.name),
                is_sensitive=False,
                decision="REJECT",
                max_severity=Severity.INFO.value,
                total_findings_count=0,
                findings=[],
                scanned_bytes=file_size,
                error=f"File size {file_size} exceeds maximum limit of {self.max_file_size_bytes} bytes",
            )

        try:
            # Attempt UTF-8 read
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return ScanResult(
                target_id=str(path.name),
                is_sensitive=False,
                decision="REJECT",
                max_severity=Severity.INFO.value,
                total_findings_count=0,
                findings=[],
                scanned_bytes=file_size,
                error=f"Failed to read file: {e}",
            )

        return self.scan_text(content, context_id=str(path.name))
