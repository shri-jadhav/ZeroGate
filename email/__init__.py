"""
ZeroGate Cloud — Email Security Assessment Package
Integrates with standard library email package to ensure full backwards compatibility
with standard library email.message, email.policy, message_from_string, etc.
"""

import os
import sys
import sysconfig


def _resolve_stdlib_email_dir() -> str:
    """Locates the Python standard library 'email' package directory across Linux, macOS, and Windows."""
    candidates = [
        os.path.join(os.path.dirname(os.__file__), "email"),
    ]
    stdlib_path = sysconfig.get_path("stdlib")
    if stdlib_path:
        candidates.append(os.path.join(stdlib_path, "email"))
    candidates.extend(
        [
            os.path.join(
                sys.base_prefix,
                "lib",
                f"python{sys.version_info.major}.{sys.version_info.minor}",
                "email",
            ),
            os.path.join(sys.base_prefix, "Lib", "email"),
        ]
    )
    this_dir = os.path.abspath(os.path.dirname(__file__))
    for candidate in candidates:
        if os.path.isdir(candidate) and os.path.abspath(candidate) != this_dir:
            return candidate
    return candidates[0] if candidates else ""


# 1. Extend __path__ with standard library email directory
_std_email_dir = _resolve_stdlib_email_dir()
if _std_email_dir and os.path.isdir(_std_email_dir) and _std_email_dir not in __path__:
    __path__.append(_std_email_dir)

# 2. Inherit all standard library email exports
_std_email_init = os.path.join(_std_email_dir, "__init__.py") if _std_email_dir else ""
if _std_email_init and os.path.exists(_std_email_init):
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

try:
    from email.checker import EmailSecurityChecker
except ModuleNotFoundError:
    EmailSecurityChecker = None  # type: ignore[assignment,misc]

__all__ = list(globals().get("__all__", [])) + [
    "PolicyLevel",
    "SPFAnalysis",
    "DMARCAnalysis",
    "DKIMAnalysis",
    "DomainSecurityReport",
    "EmailSecurityChecker",
]
