"""
ZeroGate Cloud - Core Platform Security & Access Control Test Suite
Phase 1: Automated Verification of Keycloak OIDC, Access Proxies, and Role Matrix
"""

import json
import socket
import re
import base64
from urllib.parse import urljoin
import pytest
import requests
import pyotp
from bs4 import BeautifulSoup
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
REALM_FILE = WORKSPACE_ROOT / "identity" / "keycloak" / "zerogate-realm.json"
GRAFANA_PROXY_CFG = WORKSPACE_ROOT / "access" / "proxy" / "grafana-proxy.cfg"
GITEA_PROXY_CFG = WORKSPACE_ROOT / "access" / "proxy" / "gitea-proxy.cfg"

KEYCLOAK_URL = "http://localhost:8080"
GRAFANA_PROXY_URL = "http://localhost:4180"
GITEA_PROXY_URL = "http://localhost:4181"
REALM = "zerogate"

TEST_PASSWORD = "ZeroGate@2026Pass!"


# ==============================================================================
# Helper: Interactive OIDC Proxy Login Simulation
# ==============================================================================
def execute_proxy_login(proxy_url: str, username: str, password: str = TEST_PASSWORD) -> int:
    """
    Simulates a complete browser session through oauth2-proxy:
    1. GET /oauth2/start -> 302 to Keycloak auth
    2. Submit Keycloak login form (username + password)
    3. Follow redirect to oauth2-proxy /oauth2/callback?code=...
    4. Follow final redirect to application upstream (or catch 403 Forbidden)
    Returns the final HTTP status code (200 = Allowed, 403 = Denied by Proxy).
    """
    session = requests.Session()

    # Step 1: Start login via proxy
    r1 = session.get(f"{proxy_url}/oauth2/start", allow_redirects=True, timeout=5)
    for c in session.cookies:
        c.secure = False

    soup = BeautifulSoup(r1.text, "html.parser")
    form = soup.find("form", id="kc-form-login")
    if not form:
        return r1.status_code

    action_url = form["action"]

    # Step 2: Submit credentials to Keycloak
    r2 = session.post(
        action_url,
        data={"username": username, "password": password, "credentialId": ""},
        allow_redirects=False,
        timeout=5,
    )
    callback_url = r2.headers.get("Location")
    if not callback_url:
        return r2.status_code

    for c in session.cookies:
        c.secure = False

    # Step 3: Follow redirect to oauth2-proxy callback
    r3 = session.get(callback_url, allow_redirects=False, timeout=5)
    if r3.status_code == 302:
        # User is authorized, oauth2-proxy redirects to upstream /
        for c in session.cookies:
            c.secure = False
        r4 = session.get(f"{proxy_url}/", allow_redirects=True, timeout=5)
        return r4.status_code

    # If role is not allowed, oauth2-proxy directly returns 403 Forbidden
    return r3.status_code


# ==============================================================================
# Test Scenario 7: Network & Backend Port Isolation
# ==============================================================================
def test_backend_port_isolation():
    """
    Verify that protected backend services (Grafana, Gitea, Postgres)
    do NOT expose unauthenticated host ports bypassing the proxy.
    """
    backend_ports = [
        (3000, "Internal Grafana Backend"),
        (5432, "Internal Keycloak PostgreSQL"),
    ]

    for port, name in backend_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex(("127.0.0.1", port))
            assert result != 0, f"SECURITY VIOLATION: {name} is directly reachable on host port {port}!"


# ==============================================================================
# Test Scenario 1: Unauthenticated Requests Redirected / Denied
# ==============================================================================
def test_unauthenticated_requests_redirected_to_idp():
    """
    Verify that unauthenticated requests to protected applications
    are intercepted by oauth2-proxy and redirected to Keycloak authentication.
    """
    # Grafana Proxy
    resp_grafana = requests.get(f"{GRAFANA_PROXY_URL}/", allow_redirects=False, timeout=5)
    assert resp_grafana.status_code in [302, 403, 401], (
        f"Expected redirect or challenge from Grafana proxy, got {resp_grafana.status_code}"
    )
    if resp_grafana.status_code == 302:
        loc = resp_grafana.headers.get("Location", "")
        assert "/realms/zerogate/protocol/openid-connect/auth" in loc or "/oauth2/start" in loc

    # Gitea Proxy
    resp_gitea = requests.get(f"{GITEA_PROXY_URL}/", allow_redirects=False, timeout=5)
    assert resp_gitea.status_code in [302, 403, 401], (
        f"Expected redirect or challenge from Gitea proxy, got {resp_gitea.status_code}"
    )
    if resp_gitea.status_code == 302:
        loc = resp_gitea.headers.get("Location", "")
        assert "/realms/zerogate/protocol/openid-connect/auth" in loc or "/oauth2/start" in loc


# ==============================================================================
# Test Scenario 9: Redirect URIs Contain No Wildcards
# ==============================================================================
def test_redirect_uris_contain_no_wildcards():
    """
    Ensure all OIDC client redirect URIs and web origins are explicit exact
    matches with NO wildcards ('*') to prevent open-redirect vulnerabilities.
    """
    assert REALM_FILE.exists(), f"Realm configuration file missing at {REALM_FILE}"
    with open(REALM_FILE, "r", encoding="utf-8") as f:
        realm_data = json.load(f)

    clients = realm_data.get("clients", [])
    assert len(clients) >= 2, "Expected at least 2 OIDC clients"

    for client in clients:
        client_id = client.get("clientId")
        redirect_uris = client.get("redirectUris", [])
        web_origins = client.get("webOrigins", [])

        for uri in redirect_uris:
            assert "*" not in uri, (
                f"SECURITY VIOLATION: Wildcard detected in redirectUri for client {client_id}: {uri}"
            )
            assert uri.startswith("http://") or uri.startswith("https://")

        for origin in web_origins:
            assert "*" not in origin, (
                f"SECURITY VIOLATION: Wildcard detected in webOrigin for client {client_id}: {origin}"
            )


# ==============================================================================
# Keycloak Security Policies: Dedicated Realm, Brute Force & Password Policy
# ==============================================================================
def test_keycloak_realm_security_configuration():
    """
    Verify Keycloak realm is configured with brute-force protection,
    strict password policy, and TOTP MFA policy.
    """
    with open(REALM_FILE, "r", encoding="utf-8") as f:
        realm_data = json.load(f)

    assert realm_data.get("realm") == "zerogate", "Dedicated realm must be named 'zerogate'"
    assert realm_data.get("bruteForceProtected") is True, "Brute force protection must be enabled"
    assert realm_data.get("failureFactor", 0) <= 5, "Brute force failure factor should be <= 5"

    pw_policy = realm_data.get("passwordPolicy", "")
    assert "length(12)" in pw_policy, "Password policy must enforce minimum length 12"
    assert "upperCase" in pw_policy, "Password policy must enforce uppercase letters"
    assert "lowerCase" in pw_policy, "Password policy must enforce lowercase letters"
    assert "digits" in pw_policy, "Password policy must enforce digits"
    assert "specialChars" in pw_policy, "Password policy must enforce special characters"

    otp_policy = realm_data.get("otpPolicyType", "")
    assert otp_policy == "totp", "MFA policy must be TOTP"
    assert realm_data.get("otpPolicyDigits") == 6, "TOTP must use 6 digits"
    assert realm_data.get("otpPolicyPeriod") == 30, "TOTP interval must be 30 seconds"


# ==============================================================================
# Keycloak OIDC Discovery & Endpoint Reachability
# ==============================================================================
def test_keycloak_oidc_discovery():
    """
    Verify Keycloak OIDC discovery endpoint returns valid configuration metadata.
    """
    discovery_url = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
    resp = requests.get(discovery_url, timeout=5)
    assert resp.status_code == 200, f"Discovery endpoint returned {resp.status_code}"

    doc = resp.json()
    assert doc.get("issuer") == f"{KEYCLOAK_URL}/realms/{REALM}"
    assert "authorization_endpoint" in doc
    assert "token_endpoint" in doc
    assert "jwks_uri" in doc
    assert "userinfo_endpoint" in doc


# ==============================================================================
# Test Scenario 8: Keycloak MFA Enrollment & Login Flow
# ==============================================================================
def test_keycloak_mfa_enrollment_and_challenge_flow():
    """
    Verify Keycloak MFA enrollment and login flow end-to-end:
    - User with MFA configured is prompted for OTP second factor
    - Submitting an invalid OTP code (000000) fails authentication (no redirect)
    - Submitting a valid TOTP code generated via pyotp completes authentication
    """
    # 1. Verify TOTP policy parameters in Realm
    with open(REALM_FILE, "r", encoding="utf-8") as f:
        realm_data = json.load(f)
    assert realm_data.get("otpPolicyType") == "totp"
    assert realm_data.get("otpPolicyDigits") == 6
    assert realm_data.get("otpPolicyPeriod") == 30

    # 2. Test interactive MFA challenge for enrolled MFA user (mfa_enroll_user)
    session = requests.Session()
    r1 = session.get(f"{GRAFANA_PROXY_URL}/oauth2/start", allow_redirects=True, timeout=5)
    for c in session.cookies:
        c.secure = False

    soup1 = BeautifulSoup(r1.text, "html.parser")
    form1 = soup1.find("form", id="kc-form-login")
    assert form1 is not None, "Login form not presented by Keycloak"
    action1 = form1["action"]

    # Submit password
    r2 = session.post(
        action1,
        data={"username": "mfa_enroll_user", "password": TEST_PASSWORD, "credentialId": ""},
        allow_redirects=True,
        timeout=5,
    )
    for c in session.cookies:
        c.secure = False

    soup2 = BeautifulSoup(r2.text, "html.parser")
    otp_form = soup2.find("form")
    assert otp_form is not None, "Expected MFA OTP challenge form after password entry"
    otp_action = otp_form["action"]

    # Test 1: Submit WRONG OTP code
    r_bad = session.post(otp_action, data={"otp": "000000"}, allow_redirects=False, timeout=5)
    assert r_bad.status_code != 302, "MFA bypass! Invalid OTP code was accepted with redirect"

    # Test 2: Submit VALID dynamic TOTP code
    totp = pyotp.TOTP("JV2EKNKENUZGQM3KOVCFMZ2IJF4WUMLT")
    valid_code = totp.now()

    cur_url = otp_action
    r_good = session.post(otp_action, data={"otp": valid_code}, allow_redirects=False, timeout=5)
    assert r_good.status_code == 302, f"Valid TOTP code rejected! Status: {r_good.status_code}"


# ==============================================================================
# Role Claims & Token Claims Mapping (Least Privilege)
# ==============================================================================
def test_user_roles_token_claims():
    """
    Authenticate synthetic accounts and verify exact role claim mappings
    in issued tokens according to least privilege.
    """
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"

    test_matrix = {
        "alice_emp": {"expected_role": "employee", "denied_roles": ["analyst", "admin", "auditor"]},
        "bob_analyst": {"expected_role": "analyst", "denied_roles": ["admin", "auditor"]},
        "carol_admin": {"expected_role": "admin", "denied_roles": []},
        "dave_auditor": {"expected_role": "auditor", "denied_roles": ["employee", "analyst", "admin"]},
    }

    for username, role_spec in test_matrix.items():
        resp = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "zerogate-cli-test",
                "username": username,
                "password": TEST_PASSWORD,
            },
            timeout=5,
        )
        assert resp.status_code == 200, f"Failed to authenticate user {username}: {resp.text}"
        tokens = resp.json()
        access_token = tokens["access_token"]

        # Decode JWT payload
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))

        realm_roles = payload.get("realm_access", {}).get("roles", [])
        custom_roles = payload.get("roles", [])
        all_roles = set(realm_roles + custom_roles)

        expected = role_spec["expected_role"]
        assert expected in all_roles, (
            f"User {username} is missing expected role '{expected}'! Found: {all_roles}"
        )

        for denied in role_spec["denied_roles"]:
            assert denied not in all_roles, (
                f"SECURITY VIOLATION: User {username} granted unauthorized role '{denied}'!"
            )


# ==============================================================================
# Test Scenario 3, 4, 5, 6: End-to-End Access Matrix Enforcement
# ==============================================================================
def test_access_matrix_full_end_to_end_proxy_enforcement():
    """
    Test the full end-to-end user experience through the identity-aware proxies
    for every role against the PRD Access Matrix:

    | Role      | Grafana / App A | Gitea / App B |
    |-----------|-----------------|---------------|
    | Employee  | Allowed (200)   | Denied (403)  |
    | Analyst   | Allowed (200)   | Allowed (200) |
    | Admin     | Allowed (200)   | Allowed (200) |
    | Auditor   | Denied (403)    | Allowed (200) |
    | No Role   | Denied (403)    | Denied (403)  |
    """
    # 1. Employee: Grafana = Allowed, Gitea = Denied
    assert execute_proxy_login(GRAFANA_PROXY_URL, "alice_emp") == 200, "Employee should be allowed into Grafana"
    assert execute_proxy_login(GITEA_PROXY_URL, "alice_emp") == 403, "Employee MUST be denied access to Gitea"

    # 2. Analyst: Grafana = Allowed, Gitea = Allowed
    assert execute_proxy_login(GRAFANA_PROXY_URL, "bob_analyst") == 200, "Analyst should be allowed into Grafana"
    assert execute_proxy_login(GITEA_PROXY_URL, "bob_analyst") == 200, "Analyst should be allowed into Gitea"

    # 3. Admin: Grafana = Allowed, Gitea = Allowed
    assert execute_proxy_login(GRAFANA_PROXY_URL, "carol_admin") == 200, "Admin should be allowed into Grafana"
    assert execute_proxy_login(GITEA_PROXY_URL, "carol_admin") == 200, "Admin should be allowed into Gitea"

    # 4. Auditor: Grafana = Denied, Gitea = Allowed (Read-only mapped)
    assert execute_proxy_login(GRAFANA_PROXY_URL, "dave_auditor") == 403, "Auditor MUST be denied access to Grafana"
    assert execute_proxy_login(GITEA_PROXY_URL, "dave_auditor") == 200, "Auditor should be allowed into Gitea"

    # 5. Invalid Role / Missing Claim: Grafana = Denied, Gitea = Denied
    assert execute_proxy_login(GRAFANA_PROXY_URL, "eve_norole") == 403, "eve_norole MUST be denied on Grafana"
    assert execute_proxy_login(GITEA_PROXY_URL, "eve_norole") == 403, "eve_norole MUST be denied on Gitea"


# ==============================================================================
# Test Scenario 6: Invalid Role / Missing Claim Token Inspection
# ==============================================================================
def test_invalid_role_missing_claim_rejected():
    """
    Verify that a user without any assigned role (eve_norole)
    has neither Grafana nor Gitea proxy permissions.
    """
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    resp = requests.post(
        token_url,
        data={
            "grant_type": "password",
            "client_id": "zerogate-cli-test",
            "username": "eve_norole",
            "password": TEST_PASSWORD,
        },
        timeout=5,
    )
    assert resp.status_code == 200, f"User eve_norole authentication failed: {resp.text}"
    tokens = resp.json()

    payload_b64 = tokens["access_token"].split(".")[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))

    assigned_roles = payload.get("realm_access", {}).get("roles", [])
    custom_roles = payload.get("roles", [])
    all_roles = set(assigned_roles + custom_roles)

    for role in ["employee", "analyst", "admin", "auditor"]:
        assert role not in all_roles, f"eve_norole should have no roles, but has '{role}'"


# ==============================================================================
# Test Scenario 10: Service Health Checks
# ==============================================================================
def test_service_health_checks():
    """
    Verify healthcheck endpoints for Keycloak and access proxies.
    """
    # Keycloak Realm Readiness
    kc_realm = requests.get(f"{KEYCLOAK_URL}/realms/{REALM}", timeout=5)
    assert kc_realm.status_code == 200, f"Keycloak realm check failed: {kc_realm.status_code}"

    # Grafana Proxy Ping
    graf_ping = requests.get(f"{GRAFANA_PROXY_URL}/ping", timeout=5)
    assert graf_ping.status_code == 200, f"Grafana proxy ping failed: {graf_ping.status_code}"

    # Gitea Proxy Ping
    gitea_ping = requests.get(f"{GITEA_PROXY_URL}/ping", timeout=5)
    assert gitea_ping.status_code == 200, f"Gitea proxy ping failed: {gitea_ping.status_code}"
