"""
ZeroGate Cloud — DLP Scanner Unit & Integration Tests
Validates pattern matching, Verhoeff checksums, redaction, multi-match behavior,
and safe handling of malformed or oversized inputs.
"""

import pytest
from pathlib import Path
from dlp.verhoeff import validate_verhoeff, generate_synthetic_aadhaar
from dlp.patterns import DetectorType
from dlp.redaction import mask_sensitive_value, redact_document_text
from dlp.scanner import DLPScanner, Severity
from dlp.evaluation import evaluate_dlp_engine


class TestVerhoeffAadhaarValidation:
    """Verifies the Verhoeff dihedral group D5 checksum algorithm."""

    def test_valid_synthetic_aadhaar_generation_and_validation(self):
        aadhaar = generate_synthetic_aadhaar("23456789012")
        assert len(aadhaar) == 12
        assert validate_verhoeff(aadhaar) is True

    def test_invalid_aadhaar_checksum_rejected(self):
        valid = generate_synthetic_aadhaar("36925814703")
        # Flip the last digit
        corrupted = valid[:-1] + str((int(valid[-1]) + 1) % 10)
        assert validate_verhoeff(corrupted) is False

    def test_aadhaar_cannot_start_with_zero_or_one(self):
        with pytest.raises(ValueError):
            generate_synthetic_aadhaar("01234567890")
        with pytest.raises(ValueError):
            generate_synthetic_aadhaar("12345678901")


class TestDLPScannerPatterns:
    """Verifies DLP scanner pattern detection across Indian identities and secrets."""

    @pytest.fixture
    def scanner(self):
        return DLPScanner()

    def test_detect_synthetic_aadhaar_plain_and_formatted(self, scanner):
        a1 = generate_synthetic_aadhaar("44556677889")
        a2 = generate_synthetic_aadhaar("99887766554")
        text = f"Records: plain {a1} and formatted {a2[:4]}-{a2[4:8]}-{a2[8:]}."
        res = scanner.scan_text(text)
        assert res.is_sensitive is True
        assert res.decision == "QUARANTINE"
        assert res.max_severity == Severity.HIGH.value
        findings = [f for f in res.findings if f.detector == DetectorType.AADHAAR.value]
        assert len(findings) == 1
        assert findings[0].match_count == 2

    def test_detect_synthetic_pan(self, scanner):
        text = "Individual PAN: ABCPE1234F and Company PAN: AAACC5678K submitted."
        res = scanner.scan_text(text)
        assert res.is_sensitive is True
        pan_findings = [f for f in res.findings if f.detector == DetectorType.PAN.value]
        assert len(pan_findings) == 1
        assert pan_findings[0].match_count == 2

    def test_invalid_pan_not_detected(self, scanner):
        # 4th letter 'X' is invalid entity code
        text = "Order manifest part code: ABCXE1234F."
        res = scanner.scan_text(text)
        assert res.is_sensitive is False
        assert res.total_findings_count == 0

    def test_detect_api_keys_and_secrets(self, scanner):
        text = """
        aws_access_key = AKIAIOSFODNN7EXAMPLE
        gh_token = ghp_0123456789abcdef0123456789abcdef0123
        openai_key = sk-0123456789abcdef0123456789abcdef
        google_key = AIzaSyD0123456789abcdef0123456789abc
        zg_token = zg_live_0123456789abcdef0123456789abcdef
        """
        res = scanner.scan_text(text)
        assert res.is_sensitive is True
        assert res.decision == "QUARANTINE"
        assert res.max_severity == Severity.CRITICAL.value
        detectors = {f.detector for f in res.findings}
        assert DetectorType.AWS_KEY.value in detectors
        assert DetectorType.GITHUB_TOKEN.value in detectors
        assert DetectorType.OPENAI_KEY.value in detectors
        assert DetectorType.GOOGLE_KEY.value in detectors
        assert DetectorType.ZEROGATE_TOKEN.value in detectors

    def test_benign_text_produces_no_findings(self, scanner):
        text = """
        def compute_total(items):
            # Session UUID: 550e8400-e29b-41d4-a716-446655440000
            # Commit hash: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b
            return sum(i.price for i in items)
        """
        res = scanner.scan_text(text)
        assert res.is_sensitive is False
        assert res.decision == "ACCEPT"
        assert res.total_findings_count == 0


class TestDLPRedactionAndSafety:
    """Verifies that sensitive data is masked and never exposed in raw form."""

    def test_aadhaar_masking(self):
        aadhaar = generate_synthetic_aadhaar("23456789012")  # 234567890124
        masked = mask_sensitive_value(DetectorType.AADHAAR, aadhaar)
        assert masked == "XXXXXXXX0124"
        assert aadhaar not in masked

    def test_pan_masking(self):
        pan = "ABCPE1234F"
        masked = mask_sensitive_value(DetectorType.PAN, pan)
        assert masked == "ABCXXXXXXF"
        assert "1234" not in masked

    def test_api_key_masking(self):
        token = "zg_live_0123456789abcdef0123456789abcdef"
        masked = mask_sensitive_value(DetectorType.ZEROGATE_TOKEN, token)
        assert masked.startswith("zg_liv")
        assert "[REDACTED]" in masked
        assert token not in masked

    def test_redact_document_text(self):
        scanner = DLPScanner()
        pan = "AAACP9988K"
        text = f"Invoice for client tax ID {pan} finalized."
        res = scanner.scan_text(text)
        assert res.redacted_content is not None
        assert pan not in res.redacted_content
        assert "AAAXXXXXXK" in res.redacted_content


class TestDLPFileScanningAndLimits:
    """Verifies file scanning, size limits, and error handling."""

    def test_scan_file_clean(self, tmp_path):
        f = tmp_path / "clean_report.txt"
        f.write_text("All servers operational. CPU at 15%. No issues.", encoding="utf-8")
        scanner = DLPScanner()
        res = scanner.scan_file(f)
        assert res.decision == "ACCEPT"
        assert res.is_sensitive is False

    def test_scan_file_sensitive(self, tmp_path):
        aadhaar = generate_synthetic_aadhaar("77889900112")
        f = tmp_path / "payroll.csv"
        f.write_text(f"id,name,uid\n1,Alice,{aadhaar}\n", encoding="utf-8")
        scanner = DLPScanner()
        res = scanner.scan_file(f)
        assert res.decision == "QUARANTINE"
        assert res.is_sensitive is True

    def test_scan_oversized_file_rejected(self, tmp_path):
        f = tmp_path / "large_file.dat"
        f.write_text("A" * 1500, encoding="utf-8")
        scanner = DLPScanner(max_file_size_bytes=1000)
        res = scanner.scan_file(f)
        assert res.decision == "REJECT"
        assert "exceeds maximum limit" in res.error

    def test_scan_nonexistent_file(self, tmp_path):
        scanner = DLPScanner()
        res = scanner.scan_file(tmp_path / "ghost.txt")
        assert res.decision == "REJECT"
        assert "File not found" in res.error


class TestDLPEvaluationBenchmark:
    """Verifies that precision and recall meet PRD criteria (>90% Precision, >85% Recall)."""

    def test_benchmark_satisfies_prd_targets(self):
        scanner = DLPScanner()
        metrics = evaluate_dlp_engine(scanner)
        assert metrics["targets_met"]["precision_above_90"] is True, f"Precision was {metrics['precision']}"
        assert metrics["targets_met"]["recall_above_85"] is True, f"Recall was {metrics['recall']}"
        assert metrics["precision"] >= 0.90
        assert metrics["recall"] >= 0.85
