"""
ZeroGate Cloud — DLP Detection Patterns & Validators
Defines detection rules for synthetic Indian identities (Aadhaar, PAN)
and API keys / secrets with strict boundary and checksum validation.
"""

import re
from typing import List, Dict, Any, Optional
from enum import Enum
from dlp.verhoeff import validate_verhoeff


class DetectorType(str, Enum):
    AADHAAR = "IN_AADHAAR"
    PAN = "IN_PAN"
    AWS_KEY = "SECRET_AWS_ACCESS_KEY"
    AWS_SECRET = "SECRET_AWS_SECRET_KEY"
    GENERIC_API_KEY = "SECRET_GENERIC_API_KEY"
    GITHUB_TOKEN = "SECRET_GITHUB_TOKEN"
    OPENAI_KEY = "SECRET_OPENAI_KEY"
    GOOGLE_KEY = "SECRET_GOOGLE_KEY"
    ZEROGATE_TOKEN = "SECRET_ZEROGATE_TOKEN"


# Regex definitions with word boundaries and contextual structures
_AADHAAR_REGEX = re.compile(
    r"\b([2-9]\d{3})[-\s]?(\d{4})[-\s]?(\d{4})\b"
)

# Indian PAN: 5 uppercase letters (4th is entity status in PCHFATBLJG), 4 digits, 1 letter
_PAN_REGEX = re.compile(
    r"\b([A-Z]{3})([PCHFATBLJG])([A-Z])(\d{4})([A-Z])\b"
)

_AWS_KEY_REGEX = re.compile(
    r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"
)

_AWS_SECRET_REGEX = re.compile(
    r"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)

_GENERIC_API_KEY_REGEX = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,64})['\"]?"
)

_GITHUB_TOKEN_REGEX = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,40})\b"
)

_OPENAI_KEY_REGEX = re.compile(
    r"\b(sk-[A-Za-z0-9]{20,48})\b"
)

_GOOGLE_KEY_REGEX = re.compile(
    r"\b(AIza[0-9A-Za-z\-_]{30,38})\b"
)

_ZEROGATE_TOKEN_REGEX = re.compile(
    r"\b(zg_(?:live|test)_[A-Za-z0-9]{32})\b"
)


class RawMatch:
    """Represents an unredacted raw match with position metadata."""
    def __init__(self, detector: DetectorType, raw_value: str, start: int, end: int, confidence: float):
        self.detector = detector
        self.raw_value = raw_value
        self.start = start
        self.end = end
        self.confidence = confidence


def find_aadhaar_matches(text: str) -> List[RawMatch]:
    """Finds and validates synthetic Aadhaar numbers using Verhoeff checksum."""
    matches = []
    for m in _AADHAAR_REGEX.finditer(text):
        raw_full = m.group(0)
        digits_only = re.sub(r"[-\s]", "", raw_full)
        if len(digits_only) != 12:
            continue
        # Reject repeated single-digit dummy patterns like 222222222222, 999999999999
        if len(set(digits_only)) <= 1:
            continue
        # Verify Verhoeff checksum
        if validate_verhoeff(digits_only):
            matches.append(RawMatch(
                detector=DetectorType.AADHAAR,
                raw_value=raw_full,
                start=m.start(),
                end=m.end(),
                confidence=0.95
            ))
    return matches


def find_pan_matches(text: str) -> List[RawMatch]:
    """Finds and validates synthetic PAN identifiers."""
    matches = []
    for m in _PAN_REGEX.finditer(text):
        raw_val = m.group(0)
        # 4th char is already enforced by regex to be in [PCHFATBLJG]
        # 6th-9th digits should not be 0000
        digits_part = m.group(4)
        if digits_part == "0000":
            continue
        matches.append(RawMatch(
            detector=DetectorType.PAN,
            raw_value=raw_val,
            start=m.start(),
            end=m.end(),
            confidence=0.90
        ))
    return matches


def find_secret_matches(text: str) -> List[RawMatch]:
    """Finds API keys, tokens, and secret patterns."""
    matches = []

    # AWS Access Key
    for m in _AWS_KEY_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.AWS_KEY, val, m.start(1), m.end(1), 0.98))

    # AWS Secret Key
    for m in _AWS_SECRET_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.AWS_SECRET, val, m.start(1), m.end(1), 0.95))

    # GitHub Token
    for m in _GITHUB_TOKEN_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.GITHUB_TOKEN, val, m.start(1), m.end(1), 0.99))

    # OpenAI Key
    for m in _OPENAI_KEY_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.OPENAI_KEY, val, m.start(1), m.end(1), 0.95))

    # Google API Key
    for m in _GOOGLE_KEY_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.GOOGLE_KEY, val, m.start(1), m.end(1), 0.95))

    # ZeroGate Token
    for m in _ZEROGATE_TOKEN_REGEX.finditer(text):
        val = m.group(1)
        matches.append(RawMatch(DetectorType.ZEROGATE_TOKEN, val, m.start(1), m.end(1), 0.99))

    # Generic API Key
    for m in _GENERIC_API_KEY_REGEX.finditer(text):
        val = m.group(1)
        # Avoid duplicating specific tokens matched above
        if not any(val == existing.raw_value for existing in matches):
            matches.append(RawMatch(DetectorType.GENERIC_API_KEY, val, m.start(1), m.end(1), 0.85))

    return matches


def scan_all_patterns(text: str) -> List[RawMatch]:
    """Runs all detectors and returns non-overlapping matches sorted by offset."""
    all_matches = []
    all_matches.extend(find_aadhaar_matches(text))
    all_matches.extend(find_pan_matches(text))
    all_matches.extend(find_secret_matches(text))

    # Sort matches by start position
    all_matches.sort(key=lambda m: (m.start, -m.end))

    # Remove overlapping matches
    deduped: List[RawMatch] = []
    last_end = -1
    for m in all_matches:
        if m.start >= last_end:
            deduped.append(m)
            last_end = m.end

    return deduped
