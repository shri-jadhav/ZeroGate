"""
ZeroGate Cloud — Read-Only S3 Bucket DLP Scanner (Phase 4)
Performs least-privilege, read-only inspection (ListObjectsV2 / GetObject)
of objects in a private AWS S3 bucket using the Phase 3 DLPScanner.
Guarantees zero raw PII or credentials are printed or logged.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import boto3

from dlp.scanner import DLPScanner, ScanResult


@dataclass
class S3ObjectScanReport:
    bucket: str
    key: str
    size_bytes: int
    scan_result: ScanResult

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns a redacted dictionary safe for logging and SIEM forwarding."""
        return {
            "bucket": self.bucket,
            "key": self.key,
            "size_bytes": self.size_bytes,
            "has_sensitive_data": self.scan_result.is_sensitive,
            "decision": self.scan_result.decision,
            "highest_severity": self.scan_result.max_severity,
            "total_matches": self.scan_result.total_findings_count,
            "findings": [
                {
                    "detector": f.detector,
                    "detector_name": f.detector_name,
                    "match_count": f.match_count,
                    "severity": f.severity,
                    "redacted_samples": f.masked_samples,
                    "remediation": f.remediation,
                }
                for f in self.scan_result.findings
            ],
        }


class S3ReadOnlyDLPScanner:
    """
    Narrowly scoped read-only S3 DLP scanner.
    Uses only s3:ListBucket (ListObjectsV2) and s3:GetObject.
    Never modifies bucket policies, deletes objects, or prints raw matched values.
    """

    def __init__(
        self,
        s3_client: Optional[Any] = None,
        scanner: Optional[DLPScanner] = None,
        region_name: str = "ap-south-1",
        wazuh_syslog_host: str = "127.0.0.1",
        wazuh_syslog_port: int = 514,
    ) -> None:
        self.s3 = s3_client or boto3.client("s3", region_name=region_name)
        self.scanner = scanner or DLPScanner()
        self.wazuh_syslog_host = wazuh_syslog_host
        self.wazuh_syslog_port = wazuh_syslog_port

    def scan_object(
        self,
        bucket: str,
        key: str,
        forward_to_wazuh: bool = True,
    ) -> S3ObjectScanReport:
        resp = self.s3.get_object(Bucket=bucket, Key=key)
        raw_bytes = resp["Body"].read()
        text_content = raw_bytes.decode("utf-8", errors="replace")

        scan_res = self.scanner.scan_text(
            text=text_content,
            context_id=f"s3://{bucket}/{key}",
        )
        report = S3ObjectScanReport(
            bucket=bucket,
            key=key,
            size_bytes=len(raw_bytes),
            scan_result=scan_res,
        )

        if forward_to_wazuh and scan_res.is_sensitive:
            self._emit_wazuh_syslog(report)

        return report

    def scan_bucket_prefix(
        self,
        bucket: str,
        prefix: str = "",
        max_keys: int = 50,
        forward_to_wazuh: bool = True,
    ) -> List[S3ObjectScanReport]:
        reports: List[S3ObjectScanReport] = []
        list_resp = self.s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_keys)
        for obj in list_resp.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            reports.append(self.scan_object(bucket=bucket, key=key, forward_to_wazuh=forward_to_wazuh))
        return reports

    def _emit_wazuh_syslog(self, report: S3ObjectScanReport) -> bool:
        detectors = ",".join(sorted({f.detector for f in report.scan_result.findings})) or "NONE"
        severity = report.scan_result.max_severity
        ts = time.strftime("%b %d %H:%M:%S")
        syslog_line = (
            f"{ts} zerogate-s3-dlp dlp: S3_DLP_MATCH "
            f"action=ALERT file=s3://{report.bucket}/{report.key} "
            f"detector={detectors} severity={severity} count={report.scan_result.total_findings_count}\n"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.0)
                sock.sendto(syslog_line.encode("utf-8"), (self.wazuh_syslog_host, self.wazuh_syslog_port))
            return True
        except OSError:
            return False
