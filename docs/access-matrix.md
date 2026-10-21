# ZeroGate Cloud — Role & Access Control Matrix

## 1. ZeroGate Role Matrix

ZeroGate Cloud implements strict role-based access control (RBAC) across protected internal applications. Authentication alone does not confer access; authorization claims are enforced at both the proxy ingress layer and the application layer.

| Role | Grafana (App A) | Gitea (App B) | Enforcement Level |
|---|---|---|---|
| **Employee** | **Allowed** | **Denied** | Proxy Layer (`oauth2-proxy-gitea` blocks with HTTP 403) |
| **Analyst** | **Allowed** | **Allowed** | Proxy Layer (Both proxies grant access) |
| **Admin** | **Allowed** | **Allowed** | Proxy Layer (Both proxies grant access) |
| **Auditor** | **Denied** | **Read-only where supported** | Proxy Layer blocks Grafana (HTTP 403); Gitea proxy allows session with read-only application profile |
| **No Role / Invalid** | **Denied** | **Denied** | Proxy Layer (Both proxies reject with HTTP 403) |

---

## 2. Test Account Catalog

Synthetic test accounts seeded in the reproducible `identity/keycloak/zerogate-realm.json` configuration:

| Username | Initial Password | Group | Realm Roles | Expected Behavior |
|---|---|---|---|---|
| `alice_emp` | `ZeroGate@2026Pass!` | `/Employees` | `employee` | Accesses Grafana; Blocked from Gitea (403) |
| `bob_analyst` | `ZeroGate@2026Pass!` | `/Analysts` | `analyst` | Accesses both Grafana and Gitea |
| `carol_admin` | `ZeroGate@2026Pass!` | `/Admins` | `admin` | Full administrator on both applications |
| `dave_auditor` | `ZeroGate@2026Pass!` | `/Auditors` | `auditor` | Blocked from Grafana (403); Allowed read-only access to Gitea |
| `eve_norole` | `ZeroGate@2026Pass!` | None | None | Blocked from both applications (403) |
| `mfa_enroll_user`| `ZeroGate@2026Pass!` | `/Employees` | `employee` | Required action `CONFIGURE_TOTP` triggered on login |

---

## 3. Proxy Configuration Specifications

### Grafana Proxy (`access/proxy/grafana-proxy.cfg`)
```ini
provider = "keycloak-oidc"
client_id = "zerogate-grafana"
redirect_url = "http://localhost:4180/oauth2/callback"
code_challenge_method = "S256"
allowed_roles = [
    "employee",
    "analyst",
    "admin"
]
```

### Gitea Proxy (`access/proxy/gitea-proxy.cfg`)
```ini
provider = "keycloak-oidc"
client_id = "zerogate-gitea"
redirect_url = "http://localhost:4181/oauth2/callback"
code_challenge_method = "S256"
allowed_roles = [
    "analyst",
    "admin",
    "auditor"
]
```

---

## 4. Keycloak Realm Security Policies

- **Realm**: `zerogate` (Dedicated realm isolated from `master`)
- **Brute Force Protection**:
  - `bruteForceProtected: true`
  - `failureFactor: 5` attempts
  - `waitIncrementSeconds: 60` seconds
  - `maxFailureWaitSeconds: 900` seconds (15-minute temporary lockout)
- **Password Policy**:
  - Minimum Length: 12 characters (`length(12)`)
  - Uppercase: At least 1 (`upperCase(1)`)
  - Lowercase: At least 1 (`lowerCase(1)`)
  - Digits: At least 1 (`digits(1)`)
  - Special Characters: At least 1 (`specialChars(1)`)
  - Prohibit Username: Cannot match username (`notUsername`)
  - Password History: Cannot reuse last 3 passwords (`passwordHistory(3)`)
- **Multi-Factor Authentication (MFA)**:
  - Policy Type: Time-Based One-Time Password (`totp`)
  - Hash Algorithm: `HmacSHA1`
  - Digits: 6 digits
  - Period: 30 seconds
  - Supported Authenticators: FreeOTP, Google Authenticator, Microsoft Authenticator
- **OIDC Client Redirect Integrity**:
  - Exact redirect URIs configured. Wildcards (`*`) strictly disallowed across all client definitions.

---

## 5. Phase 4 AWS Cloud IAM Roles & Trust Boundaries

| AWS IAM Role | Trust Principal & Conditions | Permitted Actions & Scope | Explicitly Denied / Out-of-Scope |
|---|---|---|---|
| `zerogate-cloud-lab-github-deploy-role` | Federated: `token.actions.githubusercontent.com`<br/>`aud == sts.amazonaws.com`<br/>`sub == repo:shri-jadhav/ZeroGate:ref:refs/heads/main` (or `environment:production`)<br/>Max Session: `3600s` (1h) | Scoped management of `zerogate-cloud-*` S3 buckets, CloudTrail trail, monthly budget, and read-only inspection of `zerogate-cloud-*` IAM roles | Unrelated S3 buckets (`drainsentinel-*`), EC2/RDS/NAT creation, IAM privilege escalation, wildcard `*` actions/resources |
| `zerogate-cloud-lab-readonly-analyst-role` | Conditional Keycloak OIDC (`enable_keycloak_oidc`) + Controlled Lab Principal with `sts:ExternalId == zerogate-analyst-session-v1`<br/>Max Session: `3600s` (1h) | Read-only DLP inspection (`s3:GetObject`, `s3:ListBucket`, metadata reads) on `zerogate-cloud-dlp-lab-816954357920-ap-south-1` and read-only status on `zerogate-cloud-lab-management-trail` | `s3:DeleteObject`, `s3:PutObject`, `s3:PutBucketPolicy`, IAM changes, and any access to unrelated S3 buckets (`AccessDenied` verified) |

