"""
ZeroGate Cloud — Safe Upload & Quarantine Workflow Tests
Verifies that clean files are stored safely, sensitive files are quarantined,
path traversal attacks are prevented, file overwrites are avoided, and audit
events are logged.
"""

import json
import pytest
from pathlib import Path
from dlp.quarantine import process_file_upload, sanitize_filename, UploadPolicyError
from dlp.verhoeff import generate_synthetic_aadhaar


class TestPathTraversalSanitization:
    """Verifies that malicious filenames and directory traversals are neutralized."""

    def test_strip_relative_path_traversal(self):
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
        assert sanitize_filename("subfolder/data.txt") == "data.txt"

    def test_null_bytes_rejected(self):
        with pytest.raises(UploadPolicyError):
            sanitize_filename("image.png\0.exe")

    def test_empty_or_dot_filenames_rejected(self):
        with pytest.raises(UploadPolicyError):
            sanitize_filename("..")
        with pytest.raises(UploadPolicyError):
            sanitize_filename("")


class TestUploadAndQuarantineWorkflow:
    """Verifies end-to-end file upload processing, routing, and audit records."""

    @pytest.fixture
    def setup_dirs(self, tmp_path):
        source_dir = tmp_path / "source"
        trusted_dir = tmp_path / "trusted"
        quarantine_dir = tmp_path / "quarantine"
        audit_log = tmp_path / "logs" / "dlp_audit.jsonl"
        source_dir.mkdir()
        trusted_dir.mkdir()
        quarantine_dir.mkdir()
        return {
            "source": source_dir,
            "trusted": trusted_dir,
            "quarantine": quarantine_dir,
            "audit": audit_log,
        }

    def test_clean_file_accepted_into_trusted_destination(self, setup_dirs):
        clean_file = setup_dirs["source"] / "project_roadmap.md"
        clean_file.write_text("# Project Roadmap\nQ1: Security hardening\nQ2: Audits", encoding="utf-8")

        result = process_file_upload(
            source_file_path=clean_file,
            trusted_destination_dir=setup_dirs["trusted"],
            quarantine_dir=setup_dirs["quarantine"],
            audit_log_path=setup_dirs["audit"],
        )

        assert result["decision"] == "ACCEPT"
        assert result["is_sensitive"] is False
        assert (setup_dirs["trusted"] / "project_roadmap.md").exists()
        assert not (setup_dirs["quarantine"] / "project_roadmap.md").exists()

        # Verify audit log entry
        assert setup_dirs["audit"].exists()
        with open(setup_dirs["audit"], "r", encoding="utf-8") as f:
            log_entries = [json.loads(line) for line in f]
        assert len(log_entries) == 1
        assert log_entries[0]["action"] == "ACCEPT"
        assert log_entries[0]["filename"] == "project_roadmap.md"

    def test_sensitive_file_quarantined_not_accepted(self, setup_dirs):
        aadhaar = generate_synthetic_aadhaar("33445566778")
        sens_file = setup_dirs["source"] / "customer_id.txt"
        sens_file.write_text(f"Customer Aadhaar: {aadhaar}\nToken: zg_live_abcdef1234567890abcdef1234567890", encoding="utf-8")

        result = process_file_upload(
            source_file_path=sens_file,
            trusted_destination_dir=setup_dirs["trusted"],
            quarantine_dir=setup_dirs["quarantine"],
            audit_log_path=setup_dirs["audit"],
        )

        assert result["decision"] == "QUARANTINE"
        assert result["is_sensitive"] is True
        # MUST NOT exist in trusted destination
        assert not (setup_dirs["trusted"] / "customer_id.txt").exists()
        # MUST exist in quarantine directory
        assert (setup_dirs["quarantine"] / "customer_id.txt").exists()
        # Quarantine metadata artifact exists
        assert (setup_dirs["quarantine"] / "customer_id.txt.quarantine.json").exists()

        # Verify audit log entry
        with open(setup_dirs["audit"], "r", encoding="utf-8") as f:
            entries = [json.loads(line) for line in f]
        assert len(entries) == 1
        assert entries[0]["action"] == "QUARANTINE"
        assert entries[0]["is_sensitive"] is True
        assert entries[0]["max_severity"] == "CRITICAL"
        # Ensure audit log does not leak the raw Aadhaar or raw token
        raw_log_text = json.dumps(entries[0])
        assert aadhaar not in raw_log_text
        assert "zg_live_abcdef1234567890abcdef1234567890" not in raw_log_text

    def test_avoid_overwriting_existing_files(self, setup_dirs):
        clean_1 = setup_dirs["source"] / "notes.txt"
        clean_1.write_text("Version 1 content", encoding="utf-8")

        process_file_upload(
            source_file_path=clean_1,
            trusted_destination_dir=setup_dirs["trusted"],
            quarantine_dir=setup_dirs["quarantine"],
            audit_log_path=setup_dirs["audit"],
        )

        # Upload a second file with same name
        clean_2 = setup_dirs["source"] / "notes.txt"
        clean_2.write_text("Version 2 content", encoding="utf-8")

        result_2 = process_file_upload(
            source_file_path=clean_2,
            trusted_destination_dir=setup_dirs["trusted"],
            quarantine_dir=setup_dirs["quarantine"],
            audit_log_path=setup_dirs["audit"],
        )

        # Both files should exist in trusted destination
        trusted_files = list(setup_dirs["trusted"].glob("notes*"))
        assert len(trusted_files) == 2
        # Original content preserved
        assert (setup_dirs["trusted"] / "notes.txt").read_text(encoding="utf-8") == "Version 1 content"
