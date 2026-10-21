# ZeroGate Cloud — Phase 2: Network Security, SIEM & Threat Detection Report

## 1. Executive Summary & Architecture Overview

Phase 2 builds the Network Security and Threat Detection foundation of the ZeroGate Cloud platform, complementing the Phase 1 Identity and Zero Trust Access Proxy layer. All components operate strictly within the local containerized environment without external cloud dependencies or billing risks.

### Architecture Diagram

```mermaid
flowchart TD
    subgraph ZeroGate_Client_Network ["ZeroGate Client & Egress Flow"]
        Client["Workstation / Container"]
    end

    subgraph Network_Security_Layer ["Network Security Layer (zerogate-network-sec)"]
        Squid["Squid Forward Proxy\n(Port 3128)\nExplicit Destination Allow-List\nDefault Deny & SSRF Guard"]
        Unbound["Unbound DNS Resolver\n(Port 1053 / Port 53)\nDNSSEC Validation\nNXDOMAIN Blocklist"]
    end

    subgraph Threat_Destinations ["Destination Assessment"]
        AllowedExt["Approved Destinations\n(*.github.com, *.docker.io,\n*.python.org, example.com)"]
        BlockedThreat["Denied / Malicious Egress\n(C2 servers, *.test blocklist,\nCloud Metadata: 169.254.169.254)"]
    end

    subgraph SOC_SIEM_Layer ["SOC SIEM & Analytics Layer"]
        Wazuh["Wazuh SIEM Manager (v4.14.9)\nSyslog Listener (UDP 514)\nwazuh-analysisd Detection Engine"]
        Rules["Custom ZeroGate Rules\nRule 100220: Squid Egress Denial\nRule 100221: DNS Tunneling Detection\nRule 100230: Keycloak Auth Failures"]
        Dashboard["Wazuh Dashboard\nReal-time Alerting & Telemetry"]
    end

    Client -->|HTTP/HTTPS CONNECT Proxy| Squid
    Client -->|DNS Resolution (UDP/TCP)| Unbound

    Squid -->|Allowed Domains| AllowedExt
    Squid -.->|403 Forbidden| BlockedThreat

    Unbound -->|Valid Signed Domains| AllowedExt
    Unbound -.->|NXDOMAIN / SERVFAIL| BlockedThreat

    Squid -->|Syslog / Structured Logs| Wazuh
    Unbound -->|Query Audit Logs| Wazuh
    Wazuh --> Rules
    Rules --> Dashboard
```

---

## 2. Component Specifications

### 2.1 Squid Forward Proxy
- **Container**: `zerogate-squid` (`ubuntu/squid:5.2-22.04_beta`)
- **Port**: `127.0.0.1:3128`
- **Configuration Files**:
  - `network/squid/squid.conf`: Hardened ACL and logging rules.
  - `network/squid/allowed_domains.txt`: Strict destination domain allow-list.
- **Security Policies**:
  - **Client Access Control**: Rejects any non-local client (`http_access deny !localnet !localhost`).
  - **Port Hardening**: Restricts HTTP to port 80 and HTTPS CONNECT to port 443 (`http_access deny CONNECT !SSL_ports`).
  - **SSRF & Cloud Metadata Prevention**:
    - Denies access to Cloud Metadata Service (`169.254.169.254/32`).
    - Denies access to Loopback (`127.0.0.0/8`, `::1`) to prevent lateral proxy abuse.
    - Denies direct access to RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
    - Denies access to Link-Local ranges (`169.254.0.0/16`, `fe80::/10`).
  - **Default Deny**: All unapproved domains return `HTTP 403 Forbidden`.
  - **Audit Logging**: Emits structured access logs tagged with `TCP_DENIED/403` or `TCP_TUNNEL/200` including timestamps, client IPs, destination URLs, and HTTP methods.

### 2.2 Unbound DNS Resolver
- **Container**: `zerogate-unbound` (`mvance/unbound:latest` running Unbound 1.22.0)
- **Port**: `127.0.0.1:1053` (mapped to internal UDP/TCP port 53)
- **Configuration Files**:
  - `network/unbound/unbound.conf`: Root anchor validation, ACLs, and query logging.
  - `network/unbound/blocklist.conf`: Threat intelligence local zone blocklist.
- **Security Policies**:
  - **Access Control**: Explicitly allows loopback and internal Docker subnets; enforces default refuse (`access-control: 0.0.0.0/0 refuse`, `access-control: ::0/0 refuse`).
  - **DNSSEC Validation**: Enforces cryptographic signature verification using the root trust anchor (`module-config: "validator iterator"`). Domains with authentic signatures return `NOERROR` with the `AD` flag; domains with broken/tampered signatures (e.g. `dnssec-failed.org`) return `SERVFAIL`.
  - **Threat Intelligence Blocklists**: Synthetic C2, phishing, and malware domains (`malicious.test`, `evil-c2.test`, `tunnel.attacker.com`) immediately return `NXDOMAIN` (RCODE 3).
  - **Query Logging**: Query and reply logging enabled with detailed client IP, query type, and domain names for SIEM correlation.

### 2.3 Wazuh SIEM & Detection Engine
- **Manager**: Wazuh 4.14.9 Manager container (`wazuh-analysisd`, `wazuh-remoted`, `wazuh-logcollector`, `wazuh-apid`).
- **Log Ingestion**: Live Syslog listener over UDP port 514 (`127.0.0.1:514` mapped to manager).
- **Custom Decoders**: `soc/wazuh/decoders/local_decoder.xml`
  - `zerogate-squid`: Extracts action, status code, duration, client IP, protocol, and URL.
  - `zerogate-keycloak`: Extracts event type, realm ID, client ID, username, and client IP.
- **Custom Rules**: `soc/wazuh/rules/local_rules.xml`
  - **Rule 100220** (Level 7): Squid forward proxy access denial to unapproved destination (`TCP_DENIED`).
    - MITRE ATT&CK: **T1071.001** (Web Protocols), **T1090** (Proxy).
  - **Rule 100221** (Level 8): DNS tunneling indicator (anomalous subdomain label with >= 25 alphanumeric characters).
    - MITRE ATT&CK: **T1071.004** (DNS), **T1048.003** (Exfiltration Over Unencrypted Non-C2 Protocol).
  - **Rule 100222** (Level 10): Correlated high-volume DNS tunneling alert (frequency threshold).
  - **Rule 100230** (Level 6): Keycloak authentication failure detection (`LOGIN_ERROR`).
    - MITRE ATT&CK: **T1110** (Brute Force).

---

## 3. Test & Verification Results

The automated regression and security test suites were executed via `pytest`:
- **Phase 1 Test Suite** (`tests/test_zerogate_platform.py`): **10 / 10 PASSED**
- **Phase 2 Test Suite** (`tests/test_phase2_security.py`): **17 / 17 PASSED**
- **Total Workspace Verification**: **27 / 27 PASSED (100% SUCCESS RATE)**

| Scenario ID | Test Name | Target Component | Expected Result | Verified Result | Status |
|:---|:---|:---|:---|:---|:---|
| SC-01 | `test_squid_allowed_destination_succeeds` | Squid Proxy | HTTP 200 OK for `example.com` | HTTP 200 OK | **PASS** |
| SC-02 | `test_squid_denied_destination_returns_403` | Squid Proxy | HTTP 403 for unauthorized destination | HTTP 403 Forbidden | **PASS** |
| SC-03 | `test_squid_blocks_non_ssl_connect_ports` | Squid Proxy | Refuses CONNECT to port 22 | Connection refused / dropped | **PASS** |
| SC-04a | `test_squid_blocks_cloud_metadata_service` | Squid Proxy | HTTP 403 for `169.254.169.254` | HTTP 403 Forbidden | **PASS** |
| SC-04b | `test_squid_blocks_loopback_destination_ssrf` | Squid Proxy | HTTP 403 for `127.0.0.1` | HTTP 403 Forbidden | **PASS** |
| SC-04c | `test_squid_blocks_private_rfc1918_egress` | Squid Proxy | HTTP 403 for `10.0.0.1` | HTTP 403 Forbidden | **PASS** |
| SC-05 | `test_unbound_normal_resolution_succeeds` | Unbound DNS | Resolves `example.com` with NOERROR | `['104.20.23.154', '...']` | **PASS** |
| SC-06 | `test_unbound_blocklist_returns_nxdomain` | Unbound DNS | Blocklist queries return NXDOMAIN | `NXDOMAIN` (RCODE 3) | **PASS** |
| SC-07a | `test_unbound_dnssec_validation_flags` | Unbound DNS | AD flag set on signed query | `flags: qr rd ra ad` | **PASS** |
| SC-07b | `test_unbound_dnssec_broken_domain_servfail` | Unbound DNS | Broken DNSSEC returns SERVFAIL | `SERVFAIL` (RCODE 2) | **PASS** |
| SC-08 | `test_unbound_access_control_refuse_policy` | Unbound DNS | `access-control: 0.0.0.0/0 refuse` active | Enforced in configuration | **PASS** |
| SC-09 | `test_wazuh_syslog_listener_active` | Wazuh SIEM | UDP 514 receives syslog packets | Successfully sent & ingested | **PASS** |
| SC-10a | `test_wazuh_rule_100220_squid_denial` | Wazuh SIEM | Rule 100220 fires on `TCP_DENIED` | Fired: Rule 100220 (Level 7) | **PASS** |
| SC-10b | `test_wazuh_rule_100220_benign_traffic_no_alert`| Wazuh SIEM | Benign proxy traffic generates no alert | Fired: None (0 false pos) | **PASS** |
| SC-10c | `test_wazuh_rule_100221_dns_tunneling` | Wazuh SIEM | Rule 100221 fires on long label | Fired: Rule 100221 (Level 8) | **PASS** |
| SC-10d | `test_wazuh_rule_100221_benign_dns_no_alert` | Wazuh SIEM | Benign short DNS generates no alert | Fired: Rule 500101 (Level 0) | **PASS** |
| SC-10e | `test_wazuh_rule_100230_keycloak_login_error` | Wazuh SIEM | Rule 100230 fires on `LOGIN_ERROR` | Fired: Rule 100230 (Level 6) | **PASS** |
| SC-11 | Phase 1 Platform Regression | Core Platform | 10/10 Phase 1 tests pass | 10/10 passed without errors | **PASS** |

---

## 4. Phase 3 Handoff & Readiness

Phase 2 Network Security and SIEM Detection capabilities are verified and production-ready for the lab environment.
The project is prepared for **Phase 3: Data Loss Prevention (DLP)**:
- Outbound egress proxy (Squid) is established and can inspect request sizes, headers, and destination routing.
- Central SIEM (Wazuh) is actively ingesting syslog and alerts on anomalous exfiltration patterns (such as DNS tunneling).
- Internal code repository (Gitea) and metrics/observability platform (Grafana) remain strictly isolated and protected behind Zero Trust authentication proxies.
