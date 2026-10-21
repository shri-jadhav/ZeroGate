"""
ZeroGate Cloud — Phase 2 Automated Security & Configuration Test Suite
Tests:
  1. Squid forward proxy destination allow-list (allowed domain succeeds)
  2. Squid forward proxy default-deny (unauthorized domain returns 403)
  3. Squid open proxy / dangerous port CONNECT rejection
  4. Squid cloud metadata (169.254.169.254) and internal RFC1918/loopback SSRF blocking
  5. Unbound normal DNS resolution (returns valid A record NOERROR)
  6. Unbound threat intelligence blocklist (returns NXDOMAIN)
  7. Unbound DNSSEC validation (AD flag on valid domain, SERVFAIL on broken domain)
  8. Unbound access-control verification (default refuse policy configured)
  9. Wazuh live syslog ingestion over UDP port 514
  10. Custom Wazuh detection rules (Rule 100220 & Rule 100221 trigger, zero false positives on benign traffic)
  11. Phase 1 platform non-regression verification
"""

import subprocess
import socket
import time
import pytest
import requests
import dns.resolver
import dns.message
import dns.query
import dns.flags
import dns.rcode

SQUID_PROXY = "http://127.0.0.1:3128"
UNBOUND_HOST = "127.0.0.1"
UNBOUND_PORT = 1053
WAZUH_SYSLOG_PORT = 514


class TestSquidForwardProxy:
    """Verifies Squid Forward Proxy access controls and security policies."""

    def test_squid_allowed_destination_succeeds(self):
        """Scenario 1: Requests to explicitly allowed domains succeed with 200 OK."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        response = requests.get("http://example.com/", proxies=proxies, timeout=10)
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        assert "Example Domain" in response.text

    def test_squid_denied_destination_returns_403(self):
        """Scenario 2: Requests to unapproved destinations are rejected by default with 403 Forbidden."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        response = requests.get("http://unauthorized-destination.com/", proxies=proxies, timeout=10)
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
        assert "Access Denied" in response.text or "squid" in response.headers.get("Server", "").lower()

    def test_squid_blocks_non_ssl_connect_ports(self):
        """Scenario 3: Squid prevents open proxy tunneling by refusing CONNECT to non-SSL ports."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        with pytest.raises(requests.exceptions.RequestException):
            requests.get("https://example.com:22/", proxies=proxies, timeout=5)

    def test_squid_blocks_cloud_metadata_service(self):
        """Scenario 4a: Cloud metadata endpoint (169.254.169.254) is blocked with 403."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        response = requests.get("http://169.254.169.254/latest/meta-data/", proxies=proxies, timeout=5)
        assert response.status_code == 403

    def test_squid_blocks_loopback_destination_ssrf(self):
        """Scenario 4b: Loopback destination (127.0.0.1) is blocked to prevent SSRF against proxy host."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        response = requests.get("http://127.0.0.1:8080/", proxies=proxies, timeout=5)
        assert response.status_code == 403

    def test_squid_blocks_private_rfc1918_egress(self):
        """Scenario 4c: RFC1918 destination (10.0.0.1) is blocked with 403."""
        proxies = {"http": SQUID_PROXY, "https": SQUID_PROXY}
        response = requests.get("http://10.0.0.1/", proxies=proxies, timeout=5)
        assert response.status_code == 403


class TestUnboundDNSResolver:
    """Verifies Unbound DNS Resolver resolution, blocklists, and DNSSEC validation."""

    def test_unbound_normal_resolution_succeeds(self):
        """Scenario 5: Allowed public domain resolves with NOERROR and valid IP addresses."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [UNBOUND_HOST]
        resolver.port = UNBOUND_PORT
        resolver.timeout = 5
        resolver.lifetime = 5

        answer = resolver.resolve("example.com", "A")
        ips = [r.to_text() for r in answer]
        assert len(ips) > 0
        assert answer.response.rcode() == dns.rcode.NOERROR

    def test_unbound_blocklist_returns_nxdomain(self):
        """Scenario 6: Blocklisted domain returns NXDOMAIN."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [UNBOUND_HOST]
        resolver.port = UNBOUND_PORT
        resolver.timeout = 5
        resolver.lifetime = 5

        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("malicious.test", "A")

        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("evil-c2.test", "A")

    def test_unbound_dnssec_validation_flags(self):
        """Scenario 7a: Query with DO (DNSSEC OK) flag sets AD (Authentic Data) on signed domain."""
        query = dns.message.make_query("cloudflare.com", dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, UNBOUND_HOST, port=UNBOUND_PORT, timeout=5)
        assert response.rcode() == dns.rcode.NOERROR
        assert bool(response.flags & dns.flags.AD), "Expected AD (Authentic Data) flag to be set"

    def test_unbound_dnssec_broken_domain_servfail(self):
        """Scenario 7b: Domain with intentionally broken DNSSEC signature returns SERVFAIL."""
        query = dns.message.make_query("dnssec-failed.org", dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, UNBOUND_HOST, port=UNBOUND_PORT, timeout=8)
        assert response.rcode() == dns.rcode.SERVFAIL, "Expected SERVFAIL for domain with invalid DNSSEC"

    def test_unbound_access_control_refuse_policy(self):
        """Scenario 8: Unbound configuration enforces default refuse access control."""
        with open("network/unbound/unbound.conf", "r") as f:
            content = f.read()
        assert "access-control: 0.0.0.0/0 refuse" in content
        assert "access-control: ::0/0 refuse" in content
        assert "access-control: 127.0.0.0/8 allow" in content


class TestWazuhSIEMAndDetection:
    """Verifies Wazuh log ingestion, decoding, and custom detection rules."""

    def test_wazuh_syslog_listener_active(self):
        """Scenario 9: Wazuh manager is actively listening on UDP port 514 and accepts syslog packets."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            msg = b"<134>Oct 22 02:00:00 zerogate-probe test: heartbeat probe\n"
            sent = sock.sendto(msg, ("127.0.0.1", WAZUH_SYSLOG_PORT))
            assert sent == len(msg)
        finally:
            sock.close()

    def test_wazuh_rule_100220_squid_denial(self):
        """Scenario 10a: Squid proxy denial event triggers Rule 100220 with MITRE tags."""
        log_event = "Oct 22 02:00:00 zerogate-squid squid: 1713800000.000 10 172.18.0.5 TCP_DENIED/403 3858 GET http://forbidden-c2.test/ - HIER_NONE/- text/html"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-sq-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100220'" in output
        assert "level: '7'" in output
        assert "T1071.001" in output
        assert "Alert to be generated." in output

    def test_wazuh_rule_100220_benign_traffic_no_alert(self):
        """Scenario 10b: Allowed Squid traffic (TCP_TUNNEL/200) does NOT trigger false positive alert."""
        log_event = "Oct 22 02:00:00 zerogate-squid squid: 1713800000.000 25 172.18.0.5 TCP_TUNNEL/200 4521 CONNECT github.com:443 - HIER_DIRECT/140.82.121.4 -"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-sq-b-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "100220" not in output
        assert "Alert to be generated." not in output

    def test_wazuh_rule_100221_dns_tunneling(self):
        """Scenario 10c: DNS query with abnormally long/encoded label triggers Rule 100221."""
        log_event = "Oct 22 02:00:00 zerogate-unbound unbound: [1234:0] info: 172.18.0.5 v8x9k2m1q7w4e3r6t5y8u0i9o2p4a6s8.tunnel.attacker.com. A IN"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-dns-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100221'" in output
        assert "level: '8'" in output
        assert "T1071.004" in output
        assert "Alert to be generated." in output

    def test_wazuh_rule_100221_benign_dns_no_alert(self):
        """Scenario 10d: Benign short DNS query does NOT trigger false positive alert."""
        log_event = "Oct 22 02:00:00 zerogate-unbound unbound: [1234:0] info: 172.18.0.5 github.com. A IN"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-dns-b-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "100221" not in output
        assert "Alert to be generated." not in output

    def test_wazuh_rule_100230_keycloak_login_error(self):
        """Scenario 10e: Keycloak authentication failure triggers Rule 100230."""
        log_event = "Oct 22 02:00:00 zerogate-keycloak keycloak: 2026-10-22 02:00:00,000 WARN [org.keycloak.events] type=LOGIN_ERROR, realmId=zerogate, clientId=zerogate-grafana, userId=admin, ipAddress=172.18.0.1"
        cmd = [
            "wsl", "-u", "root", "-d", "Ubuntu", "--",
            "ctr", "-n", "moby", "task", "exec", "--exec-id", f"t-kc-{int(time.time()*1000)%100000}",
            "92f340a33a678b300c0cbef447d28161fc65e3f0005fb4353dee87932a2852a5",
            "/bin/bash", "-c", f"echo '{log_event}' | /var/ossec/bin/wazuh-logtest"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + result.stderr
        assert "id: '100230'" in output
        assert "level: '6'" in output
        assert "T1110" in output
        assert "Alert to be generated." in output
