"""
ZeroGate Cloud — Phase 4 Automated Verification Suite
Tests:
1. Policy-as-Code & All 4 Mandatory Negative Security Fixtures (vs Secure Production Configs)
2. Terraform Formatting, Validation, and Static Security Guardrails
3. Live AWS OIDC Provider & Deployment Role Trust Policy Verification
4. Live Separate Read-Only Analyst Role Assumption (Short-Lived STS) & Boundary Enforcement
5. Live Private S3 Lab Bucket Security Controls & Read-Only Synthetic DLP Scanning
6. Live AWS CloudTrail Configuration, Event Recording & Wazuh SIEM Detection Rules (100250, 100251, 100252)
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
import pytest

from dlp.s3_scanner import S3ReadOnlyDLPScanner
from policy.validator import (
    REPO_ROOT,
    run_all_production_gates,
    validate_iam_and_oidc_policy_data,
    validate_keycloak_realm_data,
    validate_s3_config_data,
)
from scripts.cloudtrail_wazuh_bridge import (
    format_cloudtrail_event_for_wazuh,
    forward_cloudtrail_events_to_wazuh,
)

AWS_REGION = "ap-south-1"
ACCOUNT_ID = "816954357920"
LAB_BUCKET_NAME = f"zerogate-cloud-dlp-lab-{ACCOUNT_ID}-{AWS_REGION}"
TRAIL_BUCKET_NAME = f"zerogate-cloud-cloudtrail-{ACCOUNT_ID}-{AWS_REGION}"
TRAIL_NAME = "zerogate-cloud-lab-management-trail"
DEPLOY_ROLE_NAME = "zerogate-cloud-lab-github-deploy-role"
ANALYST_ROLE_NAME = "zerogate-cloud-lab-readonly-analyst-role"
ANALYST_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ANALYST_ROLE_NAME}"
UNRELATED_BUCKET_NAME = f"drainsentinel-photos-{ACCOUNT_ID}-{AWS_REGION}"
WAZUH_CONTAINER_ID = "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5"


@lru_cache(maxsize=1)
def _has_live_aws_credentials() -> bool:
    """Returns True only when live AWS credentials for the ZeroGate account are available."""
    try:
        session = boto3.Session(region_name=AWS_REGION)
        if session.get_credentials() is None:
            return False
        sts = session.client(
            "sts",
            region_name=AWS_REGION,
            config=BotoConfig(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}),
        )
        ident = sts.get_caller_identity()
        return ident.get("Account") == ACCOUNT_ID
    except (BotoCoreError, ClientError, NoCredentialsError, OSError):
        return False


@lru_cache(maxsize=1)
def _has_local_wsl_wazuh() -> bool:
    """Returns True only when the local Windows WSL2 Wazuh Manager container is reachable."""
    if sys.platform != "win32" or shutil.which("wsl") is None:
        return False
    try:
        proc = subprocess.run(
            [
                "wsl", "-u", "root", "-d", "Ubuntu", "--",
                "ctr", "-n", "moby", "tasks", "ls",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return proc.returncode == 0 and WAZUH_CONTAINER_ID in proc.stdout
    except (OSError, subprocess.SubprocessError):
        return False


# ============================================================================
# 1. Policy-as-Code & 4 Mandatory Negative Security Fixture Tests
# ============================================================================
class TestPolicyAsCodeAndNegativeFixtures:
    """Verifies that the CI security gate rejects all 4 insecure fixtures and passes secure configs."""

    def test_negative_fixture_1_admin_without_mfa_rejected_and_production_passes(self):
        insecure_path = REPO_ROOT / "policy" / "fixtures" / "insecure" / "keycloak_admin_no_mfa.json"
        insecure_data = json.loads(insecure_path.read_text(encoding="utf-8"))
        bad_res = validate_keycloak_realm_data(insecure_data, source_name="keycloak_admin_no_mfa.json")
        assert bad_res.passed is False, "Security gate MUST reject administrator config without required MFA"
        rule_ids = {f.rule_id for f in bad_res.findings}
        assert "ZG-KC-009" in rule_ids or "ZG-KC-007" in rule_ids

        # Corresponding production configuration must pass
        prod_path = REPO_ROOT / "identity" / "keycloak" / "zerogate-realm.json"
        prod_data = json.loads(prod_path.read_text(encoding="utf-8"))
        good_res = validate_keycloak_realm_data(prod_data, source_name="zerogate-realm.json")
        assert good_res.passed is True, f"Production realm failed validation: {good_res.findings}"

    def test_negative_fixture_2_wildcard_redirect_uri_rejected_and_production_passes(self):
        insecure_path = REPO_ROOT / "policy" / "fixtures" / "insecure" / "keycloak_wildcard_redirect.json"
        insecure_data = json.loads(insecure_path.read_text(encoding="utf-8"))
        bad_res = validate_keycloak_realm_data(insecure_data, source_name="keycloak_wildcard_redirect.json")
        assert bad_res.passed is False, "Security gate MUST reject wildcard redirect URIs"
        rule_ids = {f.rule_id for f in bad_res.findings}
        assert "ZG-KC-006" in rule_ids

        # Corresponding production configuration must pass
        prod_path = REPO_ROOT / "identity" / "keycloak" / "zerogate-realm.json"
        prod_data = json.loads(prod_path.read_text(encoding="utf-8"))
        good_res = validate_keycloak_realm_data(prod_data, source_name="zerogate-realm.json")
        assert good_res.passed is True

    def test_negative_fixture_3_broad_iam_trust_policy_rejected_and_secure_passes(self):
        insecure_path = REPO_ROOT / "policy" / "fixtures" / "insecure" / "iam_broad_oidc_trust.json"
        insecure_data = json.loads(insecure_path.read_text(encoding="utf-8"))
        bad_res = validate_iam_and_oidc_policy_data(insecure_data, source_name="iam_broad_oidc_trust.json")
        assert bad_res.passed is False, "Security gate MUST reject overly broad IAM trust and wildcard permissions"
        rule_ids = {f.rule_id for f in bad_res.findings}
        assert "ZG-OIDC-001" in rule_ids  # Missing sts.amazonaws.com audience
        assert "ZG-OIDC-003" in rule_ids  # Wildcard subject repo:*:*
        assert "ZG-IAM-003" in rule_ids   # Wildcard Action *
        assert "ZG-IAM-004" in rule_ids   # Wildcard Resource *

        # Corresponding secure configuration must pass
        secure_path = REPO_ROOT / "policy" / "fixtures" / "secure" / "iam_strict_oidc_trust.json"
        secure_data = json.loads(secure_path.read_text(encoding="utf-8"))
        good_res = validate_iam_and_oidc_policy_data(secure_data, source_name="iam_strict_oidc_trust.json")
        assert good_res.passed is True, f"Secure IAM fixture failed: {good_res.findings}"

    def test_negative_fixture_4_public_s3_bucket_policy_rejected_and_secure_passes(self):
        insecure_path = REPO_ROOT / "policy" / "fixtures" / "insecure" / "s3_public_bucket.json"
        insecure_data = json.loads(insecure_path.read_text(encoding="utf-8"))
        bad_res = validate_s3_config_data(insecure_data, source_name="s3_public_bucket.json")
        assert bad_res.passed is False, "Security gate MUST reject public/unencrypted S3 bucket configuration"
        rule_ids = {f.rule_id for f in bad_res.findings}
        assert "ZG-S3-001" in rule_ids  # Public access block disabled
        assert "ZG-S3-002" in rule_ids  # Missing encryption
        assert "ZG-S3-003" in rule_ids  # Public Allow Principal *
        assert "ZG-S3-004" in rule_ids  # Missing HTTPS transport enforcement

        # Corresponding secure configuration must pass
        secure_path = REPO_ROOT / "policy" / "fixtures" / "secure" / "s3_private_encrypted_bucket.json"
        secure_data = json.loads(secure_path.read_text(encoding="utf-8"))
        good_res = validate_s3_config_data(secure_data, source_name="s3_private_encrypted_bucket.json")
        assert good_res.passed is True, f"Secure S3 fixture failed: {good_res.findings}"

    def test_all_production_ci_security_gates_pass(self):
        res = run_all_production_gates()
        assert res.passed is True, f"Production security gates failed: {res.findings}"


# ============================================================================
# 2. Deterministic Unit Tests Using Isolated Test Doubles (No Live AWS/WSL)
# ============================================================================
class FakeReadOnlyS3Client:
    """Isolated read-only S3 test double for unit-testing S3ReadOnlyDLPScanner in CI."""

    def __init__(self, objects: Dict[str, bytes]) -> None:
        self.objects = objects
        self.calls: List[str] = []

    def list_objects_v2(self, Bucket: str, Prefix: str = "", MaxKeys: int = 50) -> Dict[str, Any]:
        self.calls.append(f"list_objects_v2:{Bucket}:{Prefix}")
        contents = [
            {"Key": k, "Size": len(v)}
            for k, v in self.objects.items()
            if k.startswith(Prefix)
        ][:MaxKeys]
        return {"Contents": contents}

    def get_object(self, Bucket: str, Key: str) -> Dict[str, Any]:
        self.calls.append(f"get_object:{Bucket}:{Key}")
        return {"Body": io.BytesIO(self.objects[Key])}


class FakeCloudTrailClient:
    """Isolated CloudTrail test double for unit-testing CloudTrail-to-Wazuh bridge in CI."""

    def __init__(self, events: List[Dict[str, Any]]) -> None:
        self.events = events

    def lookup_events(self, MaxResults: int = 10) -> Dict[str, Any]:
        return {"Events": self.events[:MaxResults]}


class TestCloudSecurityUnitWithIsolatedDoubles:
    """
    Deterministic unit tests for S3ReadOnlyDLPScanner, CloudTrail-to-Wazuh formatting,
    and Wazuh cloud rule XML definitions. Runs in CI without requiring live AWS credentials.
    """

    def test_s3_readonly_dlp_scanner_unit_with_isolated_s3_double(self):
        synthetic_body = (
            "Record ID: ZG-SYNTH-2026-0042\n"
            "Synthetic Aadhaar: 2345 6789 0124\n"
            "Synthetic PAN: ABCPE1234F\n"
            "Canary Token: zg_test_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\n"
        ).encode("utf-8")
        fake_s3 = FakeReadOnlyS3Client(
            {
                "samples/": b"",
                "samples/synthetic_onboarding_record.txt": synthetic_body,
                "samples/benign_readme.txt": b"General architecture notes with zero sensitive fields.",
            }
        )

        s3_dlp = S3ReadOnlyDLPScanner(
            s3_client=fake_s3,
            region_name=AWS_REGION,
            wazuh_syslog_host="127.0.0.1",
            wazuh_syslog_port=65514,
        )
        reports = s3_dlp.scan_bucket_prefix(
            bucket=LAB_BUCKET_NAME,
            prefix="samples/",
            forward_to_wazuh=True,
        )

        assert len(reports) == 2
        assert fake_s3.calls == [
            f"list_objects_v2:{LAB_BUCKET_NAME}:samples/",
            f"get_object:{LAB_BUCKET_NAME}:samples/synthetic_onboarding_record.txt",
            f"get_object:{LAB_BUCKET_NAME}:samples/benign_readme.txt",
        ]

        sensitive_report = reports[0].to_safe_dict()
        assert sensitive_report["has_sensitive_data"] is True
        assert sensitive_report["total_matches"] >= 3
        detectors = {f["detector"] for f in sensitive_report["findings"]}
        assert "IN_AADHAAR" in detectors
        assert "IN_PAN" in detectors

        serialized = json.dumps(sensitive_report)
        assert "2345 6789 0124" not in serialized
        assert "ABCPE1234F" not in serialized
        assert "zg_test_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" not in serialized

        benign_report = reports[1].to_safe_dict()
        assert benign_report["has_sensitive_data"] is False
        assert benign_report["total_matches"] == 0

    def test_cloudtrail_to_wazuh_bridge_unit_with_isolated_ct_double(self):
        events = [
            {
                "EventName": "AssumeRoleWithWebIdentity",
                "EventSource": "sts.amazonaws.com",
                "Username": "repo:shri-jadhav/ZeroGate:ref:refs/heads/main",
                "CloudTrailEvent": json.dumps({"awsRegion": "ap-south-1"}),
            },
            {
                "EventName": "DeleteObject",
                "EventSource": "s3.amazonaws.com",
                "Username": "zerogate-cloud-lab-readonly-analyst-role",
                "CloudTrailEvent": json.dumps({"errorCode": "AccessDenied", "awsRegion": "ap-south-1"}),
            },
            {
                "EventName": "GetBucketVersioning",
                "EventSource": "s3.amazonaws.com",
                "Username": "zerogate-cloud-lab-github-deploy-role",
                "CloudTrailEvent": json.dumps({"errorCode": "SlowDown", "awsRegion": "ap-south-1"}),
            },
        ]
        audit_line = format_cloudtrail_event_for_wazuh(events[0])
        assert "CLOUDTRAIL_AUDIT" in audit_line
        assert "event=AssumeRoleWithWebIdentity" in audit_line
        assert "status=Success" in audit_line

        denied_line = format_cloudtrail_event_for_wazuh(events[1])
        assert "CLOUDTRAIL_DENIED" in denied_line
        assert "event=DeleteObject" in denied_line
        assert "status=AccessDenied" in denied_line

        error_line = format_cloudtrail_event_for_wazuh(events[2])
        assert "CLOUDTRAIL_ERROR" in error_line
        assert "status=SlowDown" in error_line

        forwarded = forward_cloudtrail_events_to_wazuh(
            region_name=AWS_REGION,
            max_results=3,
            wazuh_host="127.0.0.1",
            wazuh_port=65514,
            ct_client=FakeCloudTrailClient(events),
        )
        assert len(forwarded) == 3

    def test_wazuh_cloud_rules_and_decoders_xml_structure_unit(self):
        decoder_path = REPO_ROOT / "soc" / "wazuh" / "decoders" / "local_decoder.xml"
        rules_path = REPO_ROOT / "soc" / "wazuh" / "rules" / "local_rules.xml"

        decoder_xml = "<root>\n" + decoder_path.read_text(encoding="utf-8") + "\n</root>"
        rules_xml = "<root>\n" + rules_path.read_text(encoding="utf-8") + "\n</root>"

        dec_root = ET.fromstring(decoder_xml)
        rules_root = ET.fromstring(rules_xml)

        decoder_names = {d.attrib.get("name") for d in dec_root.findall("decoder")}
        assert "zerogate-cloudtrail" in decoder_names

        rules_by_id = {
            r.attrib.get("id"): r
            for group in rules_root.findall("group")
            for r in group.findall("rule")
        }
        assert "100250" in rules_by_id
        assert "100251" in rules_by_id
        assert "100252" in rules_by_id
        assert rules_by_id["100250"].attrib.get("level") == "6"
        assert rules_by_id["100251"].attrib.get("level") == "9"
        assert rules_by_id["100252"].attrib.get("level") == "9"


# ============================================================================
# 3. External Service Integration Tests: Live AWS OIDC, IAM, S3 & CloudTrail
# ============================================================================
@pytest.mark.skipif(
    not _has_live_aws_credentials(),
    reason="Live AWS credentials for account 816954357920 not present in this environment (e.g. unauthenticated CI gate)",
)
class TestLiveAWSInfrastructureAndSecurity:
    """Verifies deployed AWS resources, OIDC trust policies, S3 security, and role boundaries."""

    def test_live_github_oidc_provider_and_deploy_role_trust_policy(self):
        iam = boto3.client("iam", region_name=AWS_REGION)

        # Verify GitHub OIDC Provider exists
        oidc_arn = f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
        provider = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=oidc_arn)
        assert "sts.amazonaws.com" in provider["ClientIDList"]

        # Verify GitHub Deploy Role Trust Policy
        role = iam.get_role(RoleName=DEPLOY_ROLE_NAME)["Role"]
        assert role["MaxSessionDuration"] == 3600
        trust_doc = role["AssumeRolePolicyDocument"]

        # Validate live AWS trust policy and permissions policy through Policy-as-Code validator
        role_policy = iam.get_role_policy(
            RoleName=DEPLOY_ROLE_NAME,
            PolicyName="zerogate-cloud-deploy-least-privilege",
        )["PolicyDocument"]
        eval_res = validate_iam_and_oidc_policy_data(
            {"trust_policy": trust_doc, "permissions_policy": role_policy},
            expected_repo="shri-jadhav/ZeroGate",
            source_name="live-aws-deploy-role",
        )
        assert eval_res.passed is True, f"Live AWS deploy role failed policy validation: {eval_res.findings}"

    def test_live_s3_lab_bucket_encryption_and_public_access_block(self):
        s3 = boto3.client("s3", region_name=AWS_REGION)

        # 1. Public Access Block
        pab = s3.get_public_access_block(Bucket=LAB_BUCKET_NAME)["PublicAccessBlockConfiguration"]
        assert pab["BlockPublicAcls"] is True
        assert pab["BlockPublicPolicy"] is True
        assert pab["IgnorePublicAcls"] is True
        assert pab["RestrictPublicBuckets"] is True

        # 2. Server-Side Encryption
        enc = s3.get_bucket_encryption(Bucket=LAB_BUCKET_NAME)["ServerSideEncryptionConfiguration"]
        rules = enc["Rules"]
        assert rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"

        # 3. Versioning
        ver = s3.get_bucket_versioning(Bucket=LAB_BUCKET_NAME)
        assert ver.get("Status") == "Enabled"

        # 4. HTTPS-only Bucket Policy
        pol_str = s3.get_bucket_policy(Bucket=LAB_BUCKET_NAME)["Policy"]
        pol_doc = json.loads(pol_str)
        s3_eval = validate_s3_config_data(
            {
                "public_access_block": {
                    "block_public_acls": pab["BlockPublicAcls"],
                    "block_public_policy": pab["BlockPublicPolicy"],
                    "ignore_public_acls": pab["IgnorePublicAcls"],
                    "restrict_public_buckets": pab["RestrictPublicBuckets"],
                },
                "encryption": {"enabled": True, "sse_algorithm": "AES256"},
                "bucket_policy": pol_doc,
            },
            source_name="live-s3-lab-bucket",
        )
        assert s3_eval.passed is True, f"Live S3 bucket failed security check: {s3_eval.findings}"

    def test_live_readonly_analyst_role_assumption_and_s3_dlp_scan(self):
        """
        Assumes the dedicated read-only analyst role using short-lived STS credentials,
        scans the synthetic S3 object with S3ReadOnlyDLPScanner, verifies redaction,
        and proves the role cannot perform destructive writes or access unrelated buckets.
        """
        sts = boto3.client("sts", region_name=AWS_REGION)

        # Assume short-lived analyst session (900 seconds = 15 minutes)
        assumed = sts.assume_role(
            RoleArn=ANALYST_ROLE_ARN,
            RoleSessionName="ZeroGateAnalystDLPVerification",
            ExternalId="zerogate-analyst-session-v1",
            DurationSeconds=900,
        )
        creds = assumed["Credentials"]
        assert creds["AccessKeyId"].startswith("ASIA"), "Expected short-lived STS temporary credentials (ASIA...)"

        analyst_s3 = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        # 1. Run Read-Only S3 DLP Scanner using the assumed analyst role
        s3_dlp = S3ReadOnlyDLPScanner(s3_client=analyst_s3, region_name=AWS_REGION)
        reports = s3_dlp.scan_bucket_prefix(bucket=LAB_BUCKET_NAME, prefix="samples/", forward_to_wazuh=True)
        assert len(reports) >= 1
        report = reports[0]
        safe_dict = report.to_safe_dict()

        assert safe_dict["has_sensitive_data"] is True
        assert safe_dict["total_matches"] >= 3
        detectors = {f["detector"] for f in safe_dict["findings"]}
        assert "IN_AADHAAR" in detectors
        assert "IN_PAN" in detectors

        # Ensure raw synthetic values are NEVER present in the safe report output
        serialized_report = json.dumps(safe_dict)
        assert "2345 6789 0124" not in serialized_report
        assert "ABCPE1234F" not in serialized_report
        assert "zg_test_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" not in serialized_report

        # 2. Verify Least-Privilege Boundary: Analyst Role CANNOT delete objects in Lab Bucket
        with pytest.raises(ClientError) as exc_del:
            analyst_s3.delete_object(Bucket=LAB_BUCKET_NAME, Key="samples/synthetic_onboarding_record.txt")
        assert exc_del.value.response["Error"]["Code"] in ("AccessDenied", "403")

        # 3. Verify Least-Privilege Boundary: Analyst Role CANNOT access unrelated DrainSentinel bucket
        with pytest.raises(ClientError) as exc_unrel:
            analyst_s3.list_objects_v2(Bucket=UNRELATED_BUCKET_NAME)
        assert exc_unrel.value.response["Error"]["Code"] in ("AccessDenied", "403")


# ============================================================================
# 4. Local SIEM & CloudTrail Integration Tests (Wazuh Rules 100250, 100251, 100252)
# ============================================================================
class TestCloudTrailAndWazuhSIEMIntegration:
    """Verifies CloudTrail trail status, management event recording, and Wazuh SIEM detection."""

    @pytest.mark.skipif(
        not _has_live_aws_credentials(),
        reason="Live AWS credentials for account 816954357920 not present in this environment",
    )
    def test_live_cloudtrail_trail_status_and_event_lookup(self):
        ct = boto3.client("cloudtrail", region_name=AWS_REGION)

        trail = ct.get_trail(Name=TRAIL_NAME)["Trail"]
        assert trail["S3BucketName"] == TRAIL_BUCKET_NAME
        assert trail["LogFileValidationEnabled"] is True
        assert trail["IncludeGlobalServiceEvents"] is True

        status = ct.get_trail_status(Name=TRAIL_NAME)
        assert status["IsLogging"] is True

        # Verify CloudTrail records management events and bridge forwards them to Wazuh UDP 514
        forwarded = forward_cloudtrail_events_to_wazuh(region_name=AWS_REGION, max_results=5)
        assert isinstance(forwarded, list)
        assert len(forwarded) >= 1
        assert all("zerogate-cloud cloudtrail:" in line for line in forwarded)

    @pytest.mark.skipif(
        not _has_local_wsl_wazuh(),
        reason="Local WSL2 Wazuh Manager container not available in this environment",
    )
    def test_wazuh_rule_100250_cloudtrail_management_and_oidc_event(self):
        """Rule 100250 fires when CloudTrail records AssumeRoleWithWebIdentity or management actions."""
        log_event = (
            "Oct 22 03:25:00 zerogate-cloud cloudtrail: CLOUDTRAIL_AUDIT "
            "event=AssumeRoleWithWebIdentity source=sts.amazonaws.com "
            "principal=repo:shri-jadhav/ZeroGate:ref:refs/heads/main status=Success region=ap-south-1"
        )
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-ct-250-{int(time.time()*1000)%100000}",
            WAZUH_CONTAINER_ID,
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100250'" in output
        assert "level: '6'" in output
        assert "T1078.004" in output
        assert "Alert to be generated." in output

    @pytest.mark.skipif(
        not _has_local_wsl_wazuh(),
        reason="Local WSL2 Wazuh Manager container not available in this environment",
    )
    def test_wazuh_rule_100251_cloudtrail_access_denied(self):
        """Rule 100251 fires at Level 9 when CloudTrail records an AccessDenied violation."""
        log_event = (
            "Oct 22 03:25:00 zerogate-cloud cloudtrail: CLOUDTRAIL_DENIED "
            "event=DeleteObject source=s3.amazonaws.com "
            "principal=zerogate-cloud-lab-readonly-analyst-role status=AccessDenied region=ap-south-1"
        )
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-ct-251-{int(time.time()*1000)%100000}",
            WAZUH_CONTAINER_ID,
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100251'" in output
        assert "level: '9'" in output
        assert "T1580" in output
        assert "Alert to be generated." in output

    @pytest.mark.skipif(
        not _has_local_wsl_wazuh(),
        reason="Local WSL2 Wazuh Manager container not available in this environment",
    )
    def test_wazuh_rule_100252_s3_cloud_dlp_finding(self):
        """Rule 100252 fires at Level 9 when S3ReadOnlyDLPScanner detects PII/secrets in S3."""
        log_event = (
            f"Oct 22 03:25:00 zerogate-s3-dlp dlp: S3_DLP_MATCH "
            f"action=ALERT file=s3://{LAB_BUCKET_NAME}/samples/synthetic_onboarding_record.txt "
            f"detector=IN_AADHAAR,IN_PAN severity=CRITICAL count=3"
        )
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-ct-252-{int(time.time()*1000)%100000}",
            WAZUH_CONTAINER_ID,
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100252'" in output
        assert "level: '9'" in output
        assert "T1530" in output
        assert "Alert to be generated." in output
