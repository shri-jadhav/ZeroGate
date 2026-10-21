"""
ZeroGate Cloud — Email Security Assessment Package
Integrates with standard library email package to ensure full backwards compatibility
with standard library email.message, email.policy, message_from_string, etc.
"""

import sys
import os

# 1. Extend __path__ with standard library email directory
_std_email_dir = os.path.join(sys.base_prefix, "Lib", "email")
if os.path.isdir(_std_email_dir) and _std_email_dir not in __path__:
    __path__.append(_std_email_dir)

# 2. Inherit all standard library email exports
_std_email_init = os.path.join(_std_email_dir, "__init__.py")
if os.path.exists(_std_email_init):
    with open(_std_email_init, "r", encoding="utf-8") as _f:
        _code = _f.read()
    exec(compile(_code, _std_email_init, "exec"), globals())

# 3. Export ZeroGate Email Security components
from email.models import (
    PolicyLevel,
    SPFAnalysis,
    DMARCAnalysis,
    DKIMAnalysis,
    DomainSecurityReport,
)
from email.checker import EmailSecurityChecker

__all__ = list(globals().get("__all__", [])) + [
    "PolicyLevel",
    "SPFAnalysis",
    "DMARCAnalysis",
    "DKIMAnalysis",
    "DomainSecurityReport",
    "EmailSecurityChecker",
]
