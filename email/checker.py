"""
ZeroGate Cloud — Email Security Checker (SPF, DKIM, DMARC)
Queries DNS records using dnspython, detects misconfigurations, analyzes
policy enforcement levels, computes security scores, and generates actionable
remediation guidance.
"""

import re
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.exception

from email.models import (
    PolicyLevel,
    SPFAnalysis,
    DMARCAnalysis,
    DKIMAnalysis,
    DomainSecurityReport,
)


class EmailSecurityChecker:
    """DNS-based SPF, DKIM, and DMARC Email Security Assessment Engine."""

    def __init__(self, resolver: Optional[dns.resolver.Resolver] = None, timeout: float = 4.0):
        if resolver is not None:
            self.resolver = resolver
        else:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout

    def check_spf(self, domain: str) -> SPFAnalysis:
        """Inspects SPF records for the specified domain."""
        domain = domain.strip().lower()
        analysis = SPFAnalysis()

        try:
            answers = self.resolver.resolve(domain, "TXT")
            spf_candidates = []
            for rdata in answers:
                txt_string = "".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                                     for part in rdata.strings)
                if txt_string.startswith("v=spf1 ") or txt_string == "v=spf1":
                    spf_candidates.append(txt_string)

            analysis.all_records = spf_candidates

            if not spf_candidates:
                analysis.has_spf = False
                analysis.policy_level = PolicyLevel.MISSING
                analysis.issues.append("No SPF (v=spf1) record discovered for domain.")
                analysis.remediation.append(
                    f"Publish an SPF TXT record for {domain} designating authorized mail sending IPs and services (e.g. 'v=spf1 mx ~all')."
                )
                analysis.score = 0
                return analysis

            if len(spf_candidates) > 1:
                analysis.has_multiple_records = True
                analysis.issues.append(
                    f"Found {len(spf_candidates)} SPF records. RFC 7208 forbids multiple SPF records; mail receivers will return PermError."
                )
                analysis.remediation.append("Consolidate all authorized sending servers into a single v=spf1 TXT record.")

            # Analyze primary record
            primary = spf_candidates[0]
            analysis.record = primary
            analysis.has_spf = True
            analysis.is_valid_syntax = True

            tokens = primary.split()
            analysis.mechanisms = tokens[1:]

            # Check qualifier on 'all'
            all_tokens = [t for t in tokens if t.endswith("all") or t == "all"]
            if all_tokens:
                qual = all_tokens[0]
                analysis.qualifier = qual
                if qual in ("-all",):
                    analysis.policy_level = PolicyLevel.STRONG
                    analysis.score = 30
                elif qual in ("~all",):
                    analysis.policy_level = PolicyLevel.MODERATE
                    analysis.score = 20
                    analysis.issues.append("SPF specifies SoftFail (~all). Consider transitioning to hard fail (-all) once all authorized sending sources are verified.")
                    analysis.remediation.append("Transition '~all' to '-all' to enforce strict sender rejection.")
                elif qual in ("?all",):
                    analysis.policy_level = PolicyLevel.WEAK
                    analysis.score = 10
                    analysis.issues.append("SPF specifies Neutral (?all), which offers no spoofing protection.")
                    analysis.remediation.append("Replace '?all' with '~all' or '-all' to prevent domain spoofing.")
                elif qual in ("+all", "all"):
                    analysis.policy_level = PolicyLevel.WEAK
                    analysis.score = 0
                    analysis.issues.append("CRITICAL: SPF specifies '+all' (Pass all), allowing any server in the world to spoof email from this domain.")
                    analysis.remediation.append("Immediately remove '+all' and replace with '-all' or '~all'.")
            else:
                analysis.policy_level = PolicyLevel.WEAK
                analysis.score = 5
                analysis.issues.append("SPF record does not include an 'all' mechanism. Undefined fallback behavior.")
                analysis.remediation.append("Add '~all' or '-all' at the end of the SPF record.")

            # Penalize multiple records
            if analysis.has_multiple_records:
                analysis.score = min(analysis.score, 5)
                analysis.policy_level = PolicyLevel.INVALID

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            analysis.has_spf = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append(f"No SPF (v=spf1) record discovered for {domain} (domain does not exist or has no TXT records).")
            analysis.remediation.append(f"Create an SPF record at root domain '{domain}'.")
            analysis.score = 0
        except dns.exception.Timeout:
            analysis.has_spf = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append("DNS resolution timed out while querying SPF.")
            analysis.score = 0
        except Exception as e:
            analysis.has_spf = False
            analysis.policy_level = PolicyLevel.INVALID
            analysis.issues.append(f"Unexpected error querying SPF: {e}")
            analysis.score = 0

        return analysis

    def check_dmarc(self, domain: str) -> DMARCAnalysis:
        """Inspects DMARC records for the specified domain at _dmarc.<domain>."""
        domain = domain.strip().lower()
        dmarc_host = f"_dmarc.{domain}"
        analysis = DMARCAnalysis()

        try:
            answers = self.resolver.resolve(dmarc_host, "TXT")
            dmarc_candidates = []
            for rdata in answers:
                txt_string = "".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                                     for part in rdata.strings)
                if txt_string.startswith("v=DMARC1"):
                    dmarc_candidates.append(txt_string)

            analysis.all_records = dmarc_candidates

            if not dmarc_candidates:
                analysis.has_dmarc = False
                analysis.policy_level = PolicyLevel.MISSING
                analysis.issues.append(f"No DMARC record discovered at {dmarc_host}.")
                analysis.remediation.append(
                    f"Publish a DMARC TXT record at '{dmarc_host}' (e.g., 'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}')."
                )
                analysis.score = 0
                return analysis

            if len(dmarc_candidates) > 1:
                analysis.has_multiple_records = True
                analysis.issues.append(
                    f"Found {len(dmarc_candidates)} DMARC records. RFC 7489 forbids multiple DMARC records."
                )
                analysis.remediation.append("Delete duplicate DMARC records, leaving only a single authoritative policy.")

            primary = dmarc_candidates[0]
            analysis.record = primary
            analysis.has_dmarc = True
            analysis.is_valid_syntax = True

            # Parse DMARC tags
            tag_matches = re.findall(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)", primary)
            tags = {k.strip().lower(): v.strip() for k, v in tag_matches}

            policy = tags.get("p", "").lower()
            analysis.policy = policy
            analysis.subdomain_policy = tags.get("sp", "").lower() or None
            analysis.rua = tags.get("rua", None)
            analysis.ruf = tags.get("ruf", None)

            # Evaluate percentage tag
            pct_val = tags.get("pct", "100")
            try:
                analysis.percentage = int(pct_val)
            except ValueError:
                analysis.percentage = 100
                analysis.issues.append(f"Invalid pct tag value '{pct_val}'. Defaulting to 100%.")

            if analysis.percentage < 100:
                analysis.issues.append(f"DMARC policy enforcement is diluted: pct={analysis.percentage}% (only applies to {analysis.percentage}% of mail).")
                analysis.remediation.append("Increase pct to 100% for full policy coverage once confidence in alignment is established.")

            # Policy evaluation
            if policy == "reject":
                analysis.policy_level = PolicyLevel.STRONG
                analysis.score = 40
            elif policy == "quarantine":
                analysis.policy_level = PolicyLevel.MODERATE
                analysis.score = 30
                analysis.issues.append("Policy is 'quarantine'. Spam will be routed to junk/quarantine. Consider moving to 'p=reject' once fully validated.")
                analysis.remediation.append("Upgrade policy to 'p=reject' to protect recipients against spoofing.")
            elif policy == "none":
                # Important: p=none is monitoring only, NOT a DNS failure!
                analysis.policy_level = PolicyLevel.WEAK
                analysis.score = 15
                analysis.issues.append("Policy is 'none' (monitoring only). Malicious spoofed emails will still be delivered to recipient inboxes.")
                analysis.remediation.append("Transition policy from 'p=none' to 'p=quarantine' or 'p=reject'.")
            else:
                analysis.policy_level = PolicyLevel.INVALID
                analysis.score = 0
                analysis.issues.append(f"Invalid or missing mandatory 'p' policy tag in DMARC record: '{primary}'.")
                analysis.remediation.append("Ensure the record contains a valid 'p=none', 'p=quarantine', or 'p=reject' directive.")

            # Reporting check
            if not analysis.rua:
                analysis.issues.append("No aggregate report URI ('rua=') configured. Mail receivers cannot send telemetry.")
                analysis.remediation.append(f"Add aggregate report mailbox, e.g. 'rua=mailto:dmarc-reports@{domain}'.")
                analysis.score = max(0, analysis.score - 5)

            if analysis.has_multiple_records:
                analysis.score = min(analysis.score, 5)
                analysis.policy_level = PolicyLevel.INVALID

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            analysis.has_dmarc = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append(f"No DMARC TXT record found at {dmarc_host}.")
            analysis.remediation.append(f"Publish a DMARC policy record at {dmarc_host}.")
            analysis.score = 0
        except dns.exception.Timeout:
            analysis.has_dmarc = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append("DNS query timed out while resolving DMARC record.")
            analysis.score = 0
        except Exception as e:
            analysis.has_dmarc = False
            analysis.policy_level = PolicyLevel.INVALID
            analysis.issues.append(f"Unexpected error querying DMARC: {e}")
            analysis.score = 0

        return analysis

    def check_dkim(self, domain: str, selector: str) -> DKIMAnalysis:
        """Inspects a specific DKIM selector record at <selector>._domainkey.<domain>."""
        domain = domain.strip().lower()
        selector = selector.strip().lower()
        dkim_host = f"{selector}._domainkey.{domain}"
        analysis = DKIMAnalysis(selector=selector)

        if not selector:
            analysis.issues.append("No DKIM selector provided. DKIM records cannot be discovered without an explicit selector.")
            analysis.remediation.append("Provide the active email sending DKIM selector (e.g. 'default', 'google', 'k1').")
            return analysis

        try:
            answers = self.resolver.resolve(dkim_host, "TXT")
            candidates = []
            for rdata in answers:
                txt_string = "".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                                     for part in rdata.strings)
                if "p=" in txt_string or "v=DKIM1" in txt_string:
                    candidates.append(txt_string)

            if not candidates:
                analysis.has_dkim = False
                analysis.policy_level = PolicyLevel.MISSING
                analysis.issues.append(f"No valid DKIM TXT record found at {dkim_host}.")
                analysis.remediation.append(f"Publish your DKIM public key TXT record at '{dkim_host}'.")
                analysis.score = 0
                return analysis

            primary = candidates[0]
            analysis.record = primary
            analysis.has_dkim = True
            analysis.is_valid_syntax = True

            tag_matches = re.findall(r"([a-zA-Z0-9]+)\s*=\s*([^;]+)", primary)
            tags = {k.strip().lower(): v.strip() for k, v in tag_matches}

            analysis.key_type = tags.get("k", "rsa")
            pub_key = tags.get("p", "")

            if pub_key:
                analysis.public_key_present = True
                analysis.policy_level = PolicyLevel.STRONG
                analysis.score = 30
            else:
                analysis.public_key_present = False
                analysis.policy_level = PolicyLevel.INVALID
                analysis.issues.append(f"DKIM record at {dkim_host} has an empty 'p=' tag (key revoked or malformed).")
                analysis.remediation.append("Populate the 'p=' tag with the valid Base64 RSA/Ed25519 public key.")
                analysis.score = 0

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            analysis.has_dkim = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append(f"DKIM record not found at {dkim_host}.")
            analysis.remediation.append(f"Publish the DKIM record for selector '{selector}' at '{dkim_host}'.")
            analysis.score = 0
        except dns.exception.Timeout:
            analysis.has_dkim = False
            analysis.policy_level = PolicyLevel.MISSING
            analysis.issues.append(f"DNS timeout querying {dkim_host}.")
            analysis.score = 0
        except Exception as e:
            analysis.has_dkim = False
            analysis.policy_level = PolicyLevel.INVALID
            analysis.issues.append(f"Error checking DKIM: {e}")
            analysis.score = 0

        return analysis

    def check_domain(self, domain: str, dkim_selector: Optional[str] = None) -> DomainSecurityReport:
        """Performs a comprehensive domain email security assessment."""
        domain = domain.strip().lower()
        spf_res = self.check_spf(domain)
        dmarc_res = self.check_dmarc(domain)
        dkim_res = self.check_dkim(domain, dkim_selector) if dkim_selector else None

        # Calculate score (out of 100)
        # Weighting: DMARC: 40 pts, SPF: 30 pts, DKIM: 30 pts (or 60/40 if no DKIM selector provided)
        if dkim_res is not None:
            total_score = spf_res.score + dmarc_res.score + dkim_res.score
        else:
            # Rescale SPF (30 -> 40) and DMARC (40 -> 60) if no selector provided
            scaled_spf = int((spf_res.score / 30.0) * 40.0)
            scaled_dmarc = int((dmarc_res.score / 40.0) * 60.0)
            total_score = scaled_spf + scaled_dmarc

        total_score = max(0, min(100, total_score))

        # Overall rating
        if total_score >= 85:
            rating = "EXCELLENT"
        elif total_score >= 70:
            rating = "GOOD"
        elif total_score >= 50:
            rating = "FAIR"
        elif total_score >= 30:
            rating = "POOR"
        else:
            rating = "CRITICAL"

        recommendations = []
        recommendations.extend(spf_res.remediation)
        recommendations.extend(dmarc_res.remediation)
        if dkim_res:
            recommendations.extend(dkim_res.remediation)
        elif not dkim_selector:
            recommendations.append("Provide a valid DKIM selector to verify cryptographic DKIM public key deployment.")

        return DomainSecurityReport(
            domain=domain,
            overall_score=total_score,
            rating=rating,
            spf=spf_res,
            dmarc=dmarc_res,
            dkim=dkim_res,
            recommendations=list(dict.fromkeys(recommendations)),
        )
