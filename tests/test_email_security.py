"""
ZeroGate Cloud — Email Security Checker Tests
Uses mocked DNS responses to test SPF, DMARC, and DKIM inspection, syntax validation,
policy strength categorization, scoring, and remediation recommendations.
"""

import pytest
import dns.resolver
import dns.exception
from email.checker import EmailSecurityChecker
from email.models import PolicyLevel


class MockTXTRecord:
    def __init__(self, text: str):
        self.strings = [text.encode("utf-8")]


class MockDNSResolver:
    """Mock DNS resolver returning configured TXT responses per domain."""
    def __init__(self, record_map=None, exception_map=None):
        self.record_map = record_map or {}
        self.exception_map = exception_map or {}

    def resolve(self, qname, rdtype="TXT"):
        qname_str = str(qname).rstrip(".").lower()
        if qname_str in self.exception_map:
            raise self.exception_map[qname_str]
        if qname_str in self.record_map:
            texts = self.record_map[qname_str]
            return [MockTXTRecord(t) for t in texts]
        raise dns.resolver.NXDOMAIN()


class TestEmailSecurityCheckerSPF:
    """Verifies SPF inspection, mechanism analysis, and qualifiers."""

    def test_strong_spf_with_hard_fail(self):
        records = {"secure-corp.com": ["v=spf1 ip4:198.51.100.1 include:_spf.google.com -all"]}
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_spf("secure-corp.com")

        assert res.has_spf is True
        assert res.policy_level == PolicyLevel.STRONG
        assert res.qualifier == "-all"
        assert res.score == 30
        assert len(res.issues) == 0

    def test_moderate_spf_with_soft_fail(self):
        records = {"soft-corp.com": ["v=spf1 include:mailgun.org ~all"]}
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_spf("soft-corp.com")

        assert res.has_spf is True
        assert res.policy_level == PolicyLevel.MODERATE
        assert res.qualifier == "~all"
        assert res.score == 20
        assert any("SoftFail" in i for i in res.issues)
        assert any("Transition '~all' to '-all'" in r for r in res.remediation)

    def test_dangerous_spf_with_pass_all(self):
        records = {"open-relay.com": ["v=spf1 +all"]}
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_spf("open-relay.com")

        assert res.has_spf is True
        assert res.policy_level == PolicyLevel.WEAK
        assert res.score == 0
        assert any("CRITICAL: SPF specifies '+all'" in i for i in res.issues)

    def test_multiple_spf_records_penalized(self):
        records = {
            "duplicate-spf.com": [
                "v=spf1 include:spf1.com -all",
                "v=spf1 include:spf2.com ~all"
            ]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_spf("duplicate-spf.com")

        assert res.has_multiple_records is True
        assert res.policy_level == PolicyLevel.INVALID
        assert any("RFC 7208 forbids multiple" in i for i in res.issues)

    def test_missing_spf_record(self):
        checker = EmailSecurityChecker(resolver=MockDNSResolver({}))
        res = checker.check_spf("nosuchdomain.com")

        assert res.has_spf is False
        assert res.policy_level == PolicyLevel.MISSING
        assert res.score == 0
        assert any("No SPF" in i for i in res.issues)


class TestEmailSecurityCheckerDMARC:
    """Verifies DMARC policy discovery, enforcement evaluation, and reporting tags."""

    def test_strong_dmarc_policy_reject(self):
        records = {
            "_dmarc.bank.com": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@bank.com; ruf=mailto:forensics@bank.com"]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dmarc("bank.com")

        assert res.has_dmarc is True
        assert res.policy == "reject"
        assert res.policy_level == PolicyLevel.STRONG
        assert res.score == 40
        assert res.percentage == 100
        assert res.rua == "mailto:dmarc@bank.com"

    def test_moderate_dmarc_policy_quarantine(self):
        records = {
            "_dmarc.staging.com": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@staging.com"]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dmarc("staging.com")

        assert res.policy == "quarantine"
        assert res.policy_level == PolicyLevel.MODERATE
        assert res.score == 30

    def test_weak_dmarc_policy_none_not_dns_failure(self):
        """Important requirement: p=none is weak monitoring, NOT a DNS failure!"""
        records = {
            "_dmarc.monitor-only.com": ["v=DMARC1; p=none; rua=mailto:dmarc@monitor-only.com"]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dmarc("monitor-only.com")

        assert res.has_dmarc is True
        assert res.is_valid_syntax is True
        assert res.policy == "none"
        assert res.policy_level == PolicyLevel.WEAK
        assert res.score == 15
        assert any("monitoring only" in i for i in res.issues)
        assert any("p=none" in r for r in res.remediation)

    def test_missing_rua_reporting_tag(self):
        records = {
            "_dmarc.no-reporting.com": ["v=DMARC1; p=reject"]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dmarc("no-reporting.com")

        assert res.rua is None
        assert any("No aggregate report URI" in i for i in res.issues)

    def test_dmarc_dns_timeout(self):
        checker = EmailSecurityChecker(resolver=MockDNSResolver(exception_map={"_dmarc.timeout.com": dns.exception.Timeout()}))
        res = checker.check_dmarc("timeout.com")

        assert res.has_dmarc is False
        assert any("timed out" in i for i in res.issues)


class TestEmailSecurityCheckerDKIM:
    """Verifies DKIM selector resolution and key syntax checks."""

    def test_valid_dkim_selector_lookup(self):
        records = {
            "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1..."]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dkim("example.com", selector="google")

        assert res.has_dkim is True
        assert res.selector == "google"
        assert res.public_key_present is True
        assert res.policy_level == PolicyLevel.STRONG
        assert res.score == 30

    def test_dkim_revoked_or_empty_key(self):
        records = {
            "oldkey._domainkey.example.com": ["v=DKIM1; k=rsa; p="]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        res = checker.check_dkim("example.com", selector="oldkey")

        assert res.has_dkim is True
        assert res.public_key_present is False
        assert res.policy_level == PolicyLevel.INVALID
        assert res.score == 0
        assert any("empty 'p=' tag" in i for i in res.issues)

    def test_missing_dkim_selector_returns_warning(self):
        checker = EmailSecurityChecker(resolver=MockDNSResolver({}))
        res = checker.check_dkim("example.com", selector="")
        assert res.has_dkim is False
        assert any("No DKIM selector provided" in i for i in res.issues)


class TestDomainOverallAssessment:
    """Verifies combined domain evaluation, rating calculations, and structured output."""

    def test_excellent_domain_security_rating(self):
        records = {
            "top-tier.com": ["v=spf1 ip4:1.2.3.4 -all"],
            "_dmarc.top-tier.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@top-tier.com"],
            "k1._domainkey.top-tier.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."]
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        report = checker.check_domain("top-tier.com", dkim_selector="k1")

        assert report.overall_score == 100  # 30 (SPF) + 40 (DMARC) + 30 (DKIM)
        assert report.rating == "EXCELLENT"
        assert "DNS record presence and syntax only" in report.limitations_disclaimer

    def test_weak_domain_security_rating(self):
        records = {
            "vulnerable.com": ["v=spf1 +all"],
            "_dmarc.vulnerable.com": ["v=DMARC1; p=none"],
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        report = checker.check_domain("vulnerable.com")

        # Scaled: SPF=0, DMARC=15 -> scaled to (15/40)*60 = 22
        assert report.rating in ("POOR", "CRITICAL")
        assert len(report.recommendations) > 0

    def test_structured_dict_output(self):
        records = {
            "sample.com": ["v=spf1 -all"],
            "_dmarc.sample.com": ["v=DMARC1; p=reject; rua=mailto:d@sample.com"],
        }
        checker = EmailSecurityChecker(resolver=MockDNSResolver(records))
        rep = checker.check_domain("sample.com")
        d = rep.to_dict()

        assert d["domain"] == "sample.com"
        assert "spf" in d
        assert "dmarc" in d
        assert "overall_score" in d
        assert "disclaimer" in d
