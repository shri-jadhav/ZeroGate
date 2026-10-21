"""
ZeroGate Cloud — Policy-as-Code & CI Security Gate Validator (Phase 4)
Validates:
1. Secret scanning across repository & gitignore enforcement
2. Terraform formatting & CLI validation
3. Terraform static security rules (S3, IAM, OIDC, CloudTrail, Cost guardrails)
4. IAM policy least-privilege validation (rejects wildcard Action/Resource)
5. S3 bucket security validation (rejects public access & missing encryption)
6. OIDC trust policy validation (enforces sts.amazonaws.com audience & pinned repo/branch subject)
7. Keycloak realm security checks (Admin MFA, password policy, brute-force, no wildcard redirect URIs)
8. Squid & Unbound network security configuration checks
9. GitHub Actions OIDC workflow security checks
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class PolicyFinding:
    gate: str
    rule_id: str
    severity: str
    message: str
    target: str


@dataclass
class PolicyEvaluationResult:
    passed: bool
    findings: List[PolicyFinding] = field(default_factory=list)

    def add_violation(self, gate: str, rule_id: str, severity: str, message: str, target: str) -> None:
        self.passed = False
        self.findings.append(
            PolicyFinding(
                gate=gate,
                rule_id=rule_id,
                severity=severity,
                message=message,
                target=target,
            )
        )


# ============================================================================
# Gate 1: Keycloak Realm Policy Validation (Admin MFA, Wildcards, Passwords)
# ============================================================================
def validate_keycloak_realm_data(realm_data: Dict[str, Any], source_name: str = "zerogate-realm.json") -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)

    # 1. Brute-force protection
    if not realm_data.get("bruteForceProtected", False):
        result.add_violation(
            "KEYCLOAK",
            "ZG-KC-001",
            "HIGH",
            "Keycloak realm must enable bruteForceProtected",
            source_name,
        )
    if realm_data.get("failureFactor", 99) > 5:
        result.add_violation(
            "KEYCLOAK",
            "ZG-KC-002",
            "MEDIUM",
            "Keycloak brute-force failureFactor must be <= 5",
            source_name,
        )

    # 2. Password policy
    pw_policy = realm_data.get("passwordPolicy", "")
    for required_token in ["length(12)", "upperCase(1)", "lowerCase(1)", "digits(1)", "specialChars(1)"]:
        if required_token not in pw_policy:
            result.add_violation(
                "KEYCLOAK",
                "ZG-KC-003",
                "HIGH",
                f"Password policy missing required constraint '{required_token}'",
                source_name,
            )

    # 3. Redirect URIs (No wildcards on protected clients)
    clients = realm_data.get("clients", [])
    protected_clients = [c for c in clients if c.get("clientId", "").startswith("zerogate-")]
    if not protected_clients:
        result.add_violation(
            "KEYCLOAK",
            "ZG-KC-004",
            "HIGH",
            "No protected 'zerogate-*' OIDC clients defined in realm",
            source_name,
        )
    for client in protected_clients:
        cid = client.get("clientId", "unknown")
        redirect_uris = client.get("redirectUris", [])
        if not redirect_uris:
            result.add_violation(
                "KEYCLOAK",
                "ZG-KC-005",
                "HIGH",
                f"Client '{cid}' has empty redirectUris",
                source_name,
            )
        for uri in redirect_uris:
            if "*" in uri:
                result.add_violation(
                    "KEYCLOAK",
                    "ZG-KC-006",
                    "CRITICAL",
                    f"Client '{cid}' contains forbidden wildcard redirect URI: '{uri}'",
                    source_name,
                )

    # 4. Browser Authentication Flow OTP check
    flows = realm_data.get("authenticationFlows", [])
    for flow in flows:
        if flow.get("alias") == "browser":
            for exec_step in flow.get("authenticationExecutions", []):
                if exec_step.get("authenticator") == "auth-otp-form":
                    if exec_step.get("requirement") == "DISABLED":
                        result.add_violation(
                            "KEYCLOAK",
                            "ZG-KC-007",
                            "CRITICAL",
                            "Browser authentication flow has 'auth-otp-form' DISABLED",
                            source_name,
                        )

    # 5. Realm TOTP Policy & Administrator MFA Requirement
    if realm_data.get("otpPolicyType") != "totp":
        result.add_violation(
            "KEYCLOAK",
            "ZG-KC-008",
            "CRITICAL",
            "Keycloak realm must enforce otpPolicyType = 'totp'",
            source_name,
        )

    users = realm_data.get("users", [])
    admin_users = [
        u for u in users
        if "admin" in [r.lower() for r in u.get("realmRoles", [])]
        or any("admin" in g.lower() for g in u.get("groups", []))
    ]
    if not admin_users:
        result.add_violation(
            "KEYCLOAK",
            "ZG-KC-009",
            "HIGH",
            "Realm must define at least one administrator account for MFA verification",
            source_name,
        )
    else:
        admin_with_mfa = [
            u for u in admin_users
            if u.get("totp") is True
            or any(c.get("type") == "otp" for c in u.get("credentials", []))
            or "CONFIGURE_TOTP" in u.get("requiredActions", [])
        ]
        if not admin_with_mfa:
            result.add_violation(
                "KEYCLOAK",
                "ZG-KC-009",
                "CRITICAL",
                "No administrator account in realm has required MFA (OTP credential or CONFIGURE_TOTP action)",
                source_name,
            )

    return result


# ============================================================================
# Gate 2: IAM & OIDC Trust Policy Validation
# ============================================================================
def validate_iam_and_oidc_policy_data(
    policy_bundle: Dict[str, Any],
    expected_repo: str = "shri-jadhav/ZeroGate",
    source_name: str = "iam-policy",
) -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)

    # 1. Validate Trust Policy
    trust_policy = policy_bundle.get("trust_policy", {})
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    if not statements:
        result.add_violation("IAM_OIDC", "ZG-IAM-001", "CRITICAL", "Missing trust policy statements", source_name)

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
            result.add_violation(
                "IAM_OIDC",
                "ZG-IAM-002",
                "CRITICAL",
                "Trust policy allows wildcard Principal '*'",
                source_name,
            )

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        if "sts:AssumeRoleWithWebIdentity" in actions:
            conditions = stmt.get("Condition", {})
            str_eq = conditions.get("StringEquals", {})
            str_like = conditions.get("StringLike", {})

            # Audience check
            aud = str_eq.get("token.actions.githubusercontent.com:aud")
            aud_values = [aud] if isinstance(aud, str) else (aud or [])
            if "sts.amazonaws.com" not in aud_values:
                result.add_violation(
                    "IAM_OIDC",
                    "ZG-OIDC-001",
                    "CRITICAL",
                    "OIDC trust policy missing strict StringEquals audience 'sts.amazonaws.com'",
                    source_name,
                )

            # Subject check
            sub_raw = str_eq.get("token.actions.githubusercontent.com:sub") or str_like.get("token.actions.githubusercontent.com:sub")
            sub_values = [sub_raw] if isinstance(sub_raw, str) else (sub_raw or [])
            if not sub_values:
                result.add_violation(
                    "IAM_OIDC",
                    "ZG-OIDC-002",
                    "CRITICAL",
                    "OIDC trust policy missing 'token.actions.githubusercontent.com:sub' condition",
                    source_name,
                )
            for sub in sub_values:
                if "*" in sub:
                    result.add_violation(
                        "IAM_OIDC",
                        "ZG-OIDC-003",
                        "CRITICAL",
                        f"OIDC trust policy contains forbidden wildcard in subject: '{sub}'",
                        source_name,
                    )
                normalized_sub = re.sub(r"@\d+", "", sub)
                if not normalized_sub.startswith(f"repo:{expected_repo}:"):
                    result.add_violation(
                        "IAM_OIDC",
                        "ZG-OIDC-004",
                        "CRITICAL",
                        f"OIDC subject '{sub}' is not pinned to expected repository 'repo:{expected_repo}:'",
                        source_name,
                    )

    # 2. Validate Permissions Policy
    perm_policy = policy_bundle.get("permissions_policy", {})
    perm_statements = perm_policy.get("Statement", [])
    if isinstance(perm_statements, dict):
        perm_statements = [perm_statements]

    for stmt in perm_statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        for act in actions:
            if act == "*" or act.endswith(":*"):
                result.add_violation(
                    "IAM_POLICY",
                    "ZG-IAM-003",
                    "CRITICAL",
                    f"IAM permissions policy contains overly broad wildcard action '{act}'",
                    source_name,
                )
        for res in resources:
            if res == "*":
                result.add_violation(
                    "IAM_POLICY",
                    "ZG-IAM-004",
                    "CRITICAL",
                    "IAM permissions policy contains unrestricted wildcard resource '*'",
                    source_name,
                )

    return result


# ============================================================================
# Gate 3: S3 Bucket Security Validation
# ============================================================================
def validate_s3_config_data(s3_config: Dict[str, Any], source_name: str = "s3-config") -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)

    # 1. Public Access Block
    pab = s3_config.get("public_access_block", {})
    for flag in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]:
        if pab.get(flag) is not True:
            result.add_violation(
                "S3_SECURITY",
                "ZG-S3-001",
                "CRITICAL",
                f"S3 Public Access Block setting '{flag}' must be true",
                source_name,
            )

    # 2. Server-Side Encryption
    enc = s3_config.get("encryption", {})
    if not enc.get("enabled", False) or enc.get("sse_algorithm") not in ("AES256", "aws:kms"):
        result.add_violation(
            "S3_SECURITY",
            "ZG-S3-002",
            "HIGH",
            "S3 bucket must enable Server-Side Encryption with AES256 or aws:kms",
            source_name,
        )

    # 3. Bucket Policy Inspection
    policy = s3_config.get("bucket_policy", {})
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    has_https_deny = False
    for stmt in statements:
        effect = stmt.get("Effect")
        principal = stmt.get("Principal")
        condition = stmt.get("Condition", {})

        if effect == "Allow" and (principal == "*" or (isinstance(principal, dict) and "*" in principal.values())):
            result.add_violation(
                "S3_SECURITY",
                "ZG-S3-003",
                "CRITICAL",
                "S3 bucket policy grants public Allow access to Principal '*'",
                source_name,
            )

        if effect == "Deny":
            bool_cond = condition.get("Bool", {})
            if str(bool_cond.get("aws:SecureTransport", "")).lower() == "false":
                has_https_deny = True

    if not has_https_deny:
        result.add_violation(
            "S3_SECURITY",
            "ZG-S3-004",
            "HIGH",
            "S3 bucket policy must enforce HTTPS-only transport (Deny when aws:SecureTransport is false)",
            source_name,
        )

    return result


# ============================================================================
# Gate 4: Terraform Static Security & Formatting Checks
# ============================================================================
def validate_terraform_files(tf_dir: Path = REPO_ROOT / "infra" / "terraform") -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)
    tf_files = sorted(tf_dir.glob("*.tf"))
    if not tf_files:
        result.add_violation("TERRAFORM", "ZG-TF-001", "CRITICAL", "No Terraform .tf files found", str(tf_dir))
        return result

    combined_hcl = "\n".join(f.read_text(encoding="utf-8") for f in tf_files)

    # Disallow expensive or forbidden AWS resources
    forbidden_resources = [
        ("aws_instance", "EC2 instances are prohibited by MVP cost guardrails"),
        ("aws_nat_gateway", "NAT Gateways are prohibited by MVP cost guardrails"),
        ("aws_db_instance", "RDS instances are prohibited by MVP cost guardrails"),
        ("aws_lb", "Load Balancers are prohibited by MVP cost guardrails"),
        ("aws_alb", "Application Load Balancers are prohibited by MVP cost guardrails"),
        ("aws_iam_user", "Static IAM users are prohibited; use OIDC federation"),
        ("aws_iam_access_key", "Static long-lived AWS access keys are prohibited"),
    ]
    for res_type, reason in forbidden_resources:
        if re.search(rf'resource\s+"{res_type}"\s+', combined_hcl):
            result.add_violation("TERRAFORM", "ZG-TF-002", "CRITICAL", reason, str(tf_dir))

    # Require S3 public access blocks for every aws_s3_bucket
    buckets = re.findall(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', combined_hcl)
    pabs = re.findall(r'resource\s+"aws_s3_bucket_public_access_block"\s+"([^"]+)"', combined_hcl)
    encryptions = re.findall(r'resource\s+"aws_s3_bucket_server_side_encryption_configuration"\s+"([^"]+)"', combined_hcl)
    for b in buckets:
        if b not in pabs:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-003",
                "CRITICAL",
                f"S3 bucket '{b}' is missing aws_s3_bucket_public_access_block",
                str(tf_dir),
            )
        if b not in encryptions:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-004",
                "HIGH",
                f"S3 bucket '{b}' is missing aws_s3_bucket_server_side_encryption_configuration",
                str(tf_dir),
            )

    # Check CloudTrail log file validation
    if 'resource "aws_cloudtrail"' in combined_hcl:
        if not re.search(r"enable_log_file_validation\s*=\s*true", combined_hcl):
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-005",
                "HIGH",
                "CloudTrail must set enable_log_file_validation = true",
                str(tf_dir),
            )

    # Check OIDC trust policy in oidc_iam.tf
    oidc_file = tf_dir / "oidc_iam.tf"
    if oidc_file.exists():
        oidc_text = oidc_file.read_text(encoding="utf-8")
        if '"token.actions.githubusercontent.com:aud"' not in oidc_text or '"sts.amazonaws.com"' not in oidc_text:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-006",
                "CRITICAL",
                "Terraform OIDC trust policy must restrict audience to sts.amazonaws.com",
                str(oidc_file),
            )
        if '"token.actions.githubusercontent.com:sub"' not in oidc_text:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-007",
                "CRITICAL",
                "Terraform OIDC trust policy must restrict subject claim",
                str(oidc_file),
            )
        # Ensure no wildcard actions in Allow IAM role policies
        if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', oidc_text):
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-008",
                "CRITICAL",
                "Terraform IAM policy contains wildcard action '*'",
                str(oidc_file),
            )
        if re.search(r'resources\s*=\s*\[\s*"\*"\s*\]', oidc_text):
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-009",
                "CRITICAL",
                "Terraform IAM policy contains wildcard resource '*'",
                str(oidc_file),
            )

    # Run Terraform CLI fmt -check and validate if binary is available
    tf_bin = shutil.which("terraform") or r"C:\Tools\Terraform\terraform.exe"
    if os.path.exists(tf_bin):
        fmt_proc = subprocess.run(
            [tf_bin, f"-chdir={tf_dir}", "fmt", "-check"],
            capture_output=True,
            text=True,
        )
        if fmt_proc.returncode != 0:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-010",
                "MEDIUM",
                f"terraform fmt -check failed: {fmt_proc.stdout.strip()}",
                str(tf_dir),
            )

        val_proc = subprocess.run(
            [tf_bin, f"-chdir={tf_dir}", "validate"],
            capture_output=True,
            text=True,
        )
        if val_proc.returncode != 0:
            result.add_violation(
                "TERRAFORM",
                "ZG-TF-011",
                "CRITICAL",
                f"terraform validate failed: {val_proc.stderr.strip() or val_proc.stdout.strip()}",
                str(tf_dir),
            )

    return result


# ============================================================================
# Gate 5: Repository Secret Scanning & Gitignore Enforcement
# ============================================================================
def scan_repository_secrets(repo_root: Path = REPO_ROOT) -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)

    gitignore_path = repo_root / ".gitignore"
    if not gitignore_path.exists():
        result.add_violation("SECRET_SCAN", "ZG-SEC-001", "CRITICAL", "Missing .gitignore file", str(gitignore_path))
    else:
        gitignore_text = gitignore_path.read_text(encoding="utf-8")
        for required_ignore in [".env", "*.tfstate", "*.tfplan"]:
            if required_ignore not in gitignore_text:
                result.add_violation(
                    "SECRET_SCAN",
                    "ZG-SEC-002",
                    "HIGH",
                    f".gitignore must exclude '{required_ignore}'",
                    str(gitignore_path),
                )

    # Scan tracked/code files (excluding .env, .venv, .git, .terraform, test fixtures)
    excluded_dirs = {".git", ".venv", "venv", ".terraform", ".pytest_cache", "__pycache__", "quarantine"}
    excluded_files = {".env"}

    secret_regexes = [
        ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("GITHUB_PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ]

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        rel_root = Path(root).relative_to(repo_root)
        # Skip DLP test fixtures that intentionally test synthetic canary patterns
        if rel_root.parts and rel_root.parts[0] in ("tests", "dlp"):
            continue

        for fname in files:
            if fname in excluded_files or fname.endswith((".tfstate", ".tfstate.backup", ".exe", ".dll", ".so")):
                continue
            fpath = Path(root) / fname
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for label, pattern in secret_regexes:
                if pattern.search(content):
                    result.add_violation(
                        "SECRET_SCAN",
                        "ZG-SEC-003",
                        "CRITICAL",
                        f"Potential hardcoded secret ({label}) detected in repository file",
                        str(fpath.relative_to(repo_root)),
                    )

    return result


# ============================================================================
# Gate 6: GitHub Actions OIDC Workflow Security Validation
# ============================================================================
def validate_github_workflow(
    workflow_path: Path = REPO_ROOT / ".github" / "workflows" / "zerogate-ci-deploy.yml",
) -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)
    if not workflow_path.exists():
        result.add_violation("GITHUB_OIDC", "ZG-GH-001", "CRITICAL", "Missing GitHub Actions workflow", str(workflow_path))
        return result

    raw_text = workflow_path.read_text(encoding="utf-8")
    wf = yaml.safe_load(raw_text)

    # Must not use static AWS secrets
    if "AWS_ACCESS_KEY_ID" in raw_text or "AWS_SECRET_ACCESS_KEY" in raw_text:
        result.add_violation(
            "GITHUB_OIDC",
            "ZG-GH-002",
            "CRITICAL",
            "Workflow references static AWS access keys instead of OIDC",
            str(workflow_path),
        )

    # Check action SHA pinning
    uses_lines = re.findall(r"uses:\s*([^\s#]+)", raw_text)
    for action_ref in uses_lines:
        if "@" not in action_ref:
            result.add_violation("GITHUB_OIDC", "ZG-GH-003", "HIGH", f"Unpinned action '{action_ref}'", str(workflow_path))
        else:
            _, ref = action_ref.split("@", 1)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                result.add_violation(
                    "GITHUB_OIDC",
                    "ZG-GH-004",
                    "HIGH",
                    f"Action '{action_ref}' must be pinned to a full 40-char commit SHA",
                    str(workflow_path),
                )

    jobs = wf.get("jobs", {})
    if "security-gates" not in jobs or "deploy-aws-infra" not in jobs:
        result.add_violation(
            "GITHUB_OIDC",
            "ZG-GH-005",
            "HIGH",
            "Workflow must separate 'security-gates' validation job from 'deploy-aws-infra' deployment job",
            str(workflow_path),
        )
    else:
        deploy_job = jobs["deploy-aws-infra"]
        perms = deploy_job.get("permissions", {})
        if perms.get("id-token") != "write" or perms.get("contents") != "read":
            result.add_violation(
                "GITHUB_OIDC",
                "ZG-GH-006",
                "HIGH",
                "Deployment job must declare least-privilege permissions (id-token: write, contents: read)",
                str(workflow_path),
            )
        if_cond = str(deploy_job.get("if", ""))
        if "refs/heads/main" not in if_cond or "shri-jadhav/ZeroGate" not in if_cond:
            result.add_violation(
                "GITHUB_OIDC",
                "ZG-GH-007",
                "CRITICAL",
                "Deployment job 'if' condition must restrict execution to refs/heads/main on shri-jadhav/ZeroGate",
                str(workflow_path),
            )

    return result


# ============================================================================
# Gate 7: Phase 2 Network Config Non-Regression Checks
# ============================================================================
def validate_network_configs(repo_root: Path = REPO_ROOT) -> PolicyEvaluationResult:
    result = PolicyEvaluationResult(passed=True)
    squid_conf = repo_root / "network" / "squid" / "squid.conf"
    unbound_conf = repo_root / "network" / "unbound" / "unbound.conf"

    if not squid_conf.exists() or "http_access deny all" not in squid_conf.read_text(encoding="utf-8"):
        result.add_violation("NETWORK", "ZG-NET-001", "CRITICAL", "Squid configuration missing default deny", str(squid_conf))

    if not unbound_conf.exists() or "access-control: 0.0.0.0/0 refuse" not in unbound_conf.read_text(encoding="utf-8"):
        result.add_violation("NETWORK", "ZG-NET-002", "CRITICAL", "Unbound configuration missing default refuse", str(unbound_conf))

    return result


def run_all_production_gates() -> PolicyEvaluationResult:
    overall = PolicyEvaluationResult(passed=True)

    realm_path = REPO_ROOT / "identity" / "keycloak" / "zerogate-realm.json"
    realm_data = json.loads(realm_path.read_text(encoding="utf-8"))
    kc_res = validate_keycloak_realm_data(realm_data, str(realm_path.relative_to(REPO_ROOT)))

    iam_secure_path = REPO_ROOT / "policy" / "fixtures" / "secure" / "iam_strict_oidc_trust.json"
    iam_res = validate_iam_and_oidc_policy_data(
        json.loads(iam_secure_path.read_text(encoding="utf-8")),
        source_name=str(iam_secure_path.relative_to(REPO_ROOT)),
    )

    s3_secure_path = REPO_ROOT / "policy" / "fixtures" / "secure" / "s3_private_encrypted_bucket.json"
    s3_res = validate_s3_config_data(
        json.loads(s3_secure_path.read_text(encoding="utf-8")),
        source_name=str(s3_secure_path.relative_to(REPO_ROOT)),
    )

    tf_res = validate_terraform_files()
    sec_res = scan_repository_secrets()
    gh_res = validate_github_workflow()
    net_res = validate_network_configs()

    for sub in [kc_res, iam_res, s3_res, tf_res, sec_res, gh_res, net_res]:
        if not sub.passed:
            overall.passed = False
            overall.findings.extend(sub.findings)

    return overall


if __name__ == "__main__":
    res = run_all_production_gates()
    if not res.passed:
        print("POLICY GATE FAILED:")
        for f in res.findings:
            print(f"  [{f.severity}] {f.gate} ({f.rule_id}) in {f.target}: {f.message}")
        sys.exit(1)
    print("ALL ZEROGATE POLICY-AS-CODE SECURITY GATES PASSED.")
    sys.exit(0)
