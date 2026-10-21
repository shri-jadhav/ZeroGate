"""
ZeroGate Cloud — Safe Upload & Quarantine Workflow
Safely processes incoming files, prevents path traversal, routes sensitive
content to an isolated quarantine repository with restricted permissions,
and emits structured audit records for all decisions.
"""

import os
import json
import time
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from dlp.scanner import DLPScanner, ScanResult


class UploadPolicyError(Exception):
    """Raised when an upload violates security policies (path traversal, size limits)."""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename against path traversal, null bytes, and dangerous characters.
    Extracts only the terminal basename.
    """
    if not filename:
        raise UploadPolicyError("Filename cannot be empty")

    # Reject null bytes
    if "\0" in filename:
        raise UploadPolicyError("Filename contains invalid null byte")

    # Extract pure filename, stripping both POSIX (/) and Windows (\) directory paths
    normalized = filename.replace("\\", "/")
    base = Path(normalized).name

    # Check for empty or traversal remnants
    if not base or base in (".", ".."):
        raise UploadPolicyError("Invalid filename path traversal attempt")

    # Strip characters that could be dangerous in shell or local filesystems
    cleaned = "".join(c for c in base if c.isalnum() or c in "._- ")
    if not cleaned:
        raise UploadPolicyError("Filename contains only invalid characters")

    return cleaned


def resolve_non_colliding_path(directory: Path, filename: str) -> Path:
    """Ensures incoming file does not overwrite existing files unexpectedly."""
    target = directory / filename
    if not target.exists():
        return target

    stem = target.stem
    suffix = target.suffix
    timestamp = int(time.time() * 1000)
    return directory / f"{stem}_{timestamp}{suffix}"


def process_file_upload(
    source_file_path: Path,
    trusted_destination_dir: Path,
    quarantine_dir: Path,
    audit_log_path: Path,
    scanner: Optional[DLPScanner] = None,
    max_size_bytes: int = 5 * 1024 * 1024,
) -> Dict[str, Any]:
    """
    Executes the secure upload pipeline:
    1. Validates source path & sanitizes filename against traversal
    2. Enforces bounded file size limit
    3. Scans content using DLPScanner
    4. Routes clean files to trusted_destination_dir
    5. Quarantines sensitive files to quarantine_dir with read-only permissions
    6. Logs an audit record for every decision
    """
    scanner = scanner or DLPScanner()
    trusted_destination_dir = Path(trusted_destination_dir)
    quarantine_dir = Path(quarantine_dir)
    audit_log_path = Path(audit_log_path)
    source_path = Path(source_file_path)

    trusted_destination_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Sanitize filename
    safe_name = sanitize_filename(source_path.name)

    # 2. Check existence & size limit
    if not source_path.exists():
        raise UploadPolicyError(f"Source file does not exist: {source_path}")

    file_size = source_path.stat().st_size
    if file_size > max_size_bytes:
        audit_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": "REJECT",
            "reason": f"File exceeds maximum allowed size ({file_size} > {max_size_bytes})",
            "filename": safe_name,
            "size_bytes": file_size,
        }
        _append_audit_log(audit_log_path, audit_entry)
        raise UploadPolicyError(audit_entry["reason"])

    # 3. Scan content
    scan_result: ScanResult = scanner.scan_file(source_path)

    # 4. Route based on scan decision
    final_destination: Optional[Path] = None
    action_decision = scan_result.decision

    if scan_result.decision == "ACCEPT":
        target_path = resolve_non_colliding_path(trusted_destination_dir, safe_name)
        shutil.copy2(source_path, target_path)
        final_destination = target_path
    elif scan_result.decision in ("QUARANTINE", "REJECT"):
        quarantine_target = resolve_non_colliding_path(quarantine_dir, safe_name)
        shutil.copy2(source_path, quarantine_target)
        final_destination = quarantine_target

        # Restrict permissions: read-only, non-executable (0o444 on POSIX, Read-Only flag on Windows)
        try:
            os.chmod(quarantine_target, 0o444)
        except Exception:
            pass

        # Write quarantine metadata artifact
        meta_file = quarantine_target.with_suffix(quarantine_target.suffix + ".quarantine.json")
        with open(meta_file, "w", encoding="utf-8") as mf:
            json.dump({
                "original_filename": safe_name,
                "quarantine_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "findings": [f.detector for f in scan_result.findings],
                "max_severity": scan_result.max_severity,
                "scanned_bytes": scan_result.scanned_bytes,
            }, mf, indent=2)

    # 5. Emit audit event
    audit_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action_decision,
        "filename": safe_name,
        "is_sensitive": scan_result.is_sensitive,
        "max_severity": scan_result.max_severity,
        "total_findings": scan_result.total_findings_count,
        "findings": [
            {
                "detector": f.detector,
                "detector_name": f.detector_name,
                "severity": f.severity,
                "match_count": f.match_count,
                "samples": f.masked_samples,
            }
            for f in scan_result.findings
        ],
        "destination": str(final_destination) if final_destination else None,
        "size_bytes": file_size,
    }
    _append_audit_log(audit_log_path, audit_entry)

    return {
        "filename": safe_name,
        "decision": action_decision,
        "is_sensitive": scan_result.is_sensitive,
        "destination": str(final_destination) if final_destination else None,
        "findings": audit_entry["findings"],
        "max_severity": scan_result.max_severity,
    }


def _append_audit_log(log_path: Path, entry: Dict[str, Any]) -> None:
    """Appends structured audit record (JSON Lines) to the audit log."""
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
