"""
ZeroGate Cloud — Email Security Assessment Models
Data structures for SPF, DKIM, and DMARC inspection findings, scoring,
and actionable remediation guidance.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PolicyLevel(str, Enum):
    MISSING = "MISSING"
    WEAK = "WEAK"          # e.g., p=none, +all, ?all
    MODERATE = "MODERATE"  # e.g., ~all, p=quarantine
    STRONG = "STRONG"      # e.g., -all, p=reject
    INVALID = "INVALID"


@dataclass
class SPFAnalysis:
    record: Optional[str] = None
    all_records: List[str] = field(default_factory=list)
    has_spf: bool = False
    is_valid_syntax: bool = False
    has_multiple_records: bool = False
    qualifier: Optional[str] = None  # "+all", "-all", "~all", "?all"
    policy_level: PolicyLevel = PolicyLevel.MISSING
    mechanisms: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    score: int = 0  # 0 to 30


@dataclass
class DMARCAnalysis:
    record: Optional[str] = None
    all_records: List[str] = field(default_factory=list)
    has_dmarc: bool = False
    is_valid_syntax: bool = False
    has_multiple_records: bool = False
    policy: Optional[str] = None  # "none", "quarantine", "reject"
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua: Optional[str] = None
    ruf: Optional[str] = None
    policy_level: PolicyLevel = PolicyLevel.MISSING
    issues: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    score: int = 0  # 0 to 40


@dataclass
class DKIMAnalysis:
    selector: Optional[str] = None
    record: Optional[str] = None
    has_dkim: bool = False
    is_valid_syntax: bool = False
    key_type: Optional[str] = None
    public_key_present: bool = False
    policy_level: PolicyLevel = PolicyLevel.MISSING
    issues: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    score: int = 0  # 0 to 30


@dataclass
class DomainSecurityReport:
    domain: str
    overall_score: int  # 0 to 100
    rating: str         # "EXCELLENT", "GOOD", "FAIR", "POOR", "CRITICAL"
    spf: SPFAnalysis
    dmarc: DMARCAnalysis
    dkim: Optional[DKIMAnalysis] = None
    recommendations: List[str] = field(default_factory=list)
    limitations_disclaimer: str = (
        "DNS assessment verifies public DNS record presence and syntax only. "
        "It does not test real message alignment, mailbox delivery, or cryptographic "
        "DKIM signature verification on outbound emails."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "overall_score": self.overall_score,
            "rating": self.rating,
            "spf": {
                "record": self.spf.record,
                "has_spf": self.spf.has_spf,
                "policy_level": self.spf.policy_level.value,
                "qualifier": self.spf.qualifier,
                "issues": self.spf.issues,
                "remediation": self.spf.remediation,
                "score": self.spf.score,
            },
            "dmarc": {
                "record": self.dmarc.record,
                "has_dmarc": self.dmarc.has_dmarc,
                "policy": self.dmarc.policy,
                "policy_level": self.dmarc.policy_level.value,
                "percentage": self.dmarc.percentage,
                "rua": self.dmarc.rua,
                "issues": self.dmarc.issues,
                "remediation": self.dmarc.remediation,
                "score": self.dmarc.score,
            },
            "dkim": {
                "selector": self.dkim.selector if self.dkim else None,
                "has_dkim": self.dkim.has_dkim if self.dkim else False,
                "policy_level": self.dkim.policy_level.value if self.dkim else PolicyLevel.MISSING.value,
                "issues": self.dkim.issues if self.dkim else [],
                "remediation": self.dkim.remediation if self.dkim else [],
                "score": self.dkim.score if self.dkim else 0,
            } if self.dkim else None,
            "recommendations": self.recommendations,
            "disclaimer": self.limitations_disclaimer,
        }
