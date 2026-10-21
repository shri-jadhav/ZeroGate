"""
ZeroGate Cloud — DLP Redaction & Masking Module
Provides deterministic masking of sensitive entities to ensure raw secrets
and identity identifiers are never printed to logs or audit outputs.
"""

import re
from typing import List
from dlp.patterns import DetectorType, RawMatch


def mask_sensitive_value(detector: DetectorType, raw_value: str) -> str:
    """Masks an individual detected value based on its entity type."""
    if detector == DetectorType.AADHAAR:
        # Normalize digits
        clean = re.sub(r"[-\s]", "", raw_value)
        if len(clean) == 12:
            last4 = clean[-4:]
            if "-" in raw_value:
                return f"XXXX-XXXX-{last4}"
            elif " " in raw_value:
                return f"XXXX XXXX {last4}"
            else:
                return f"XXXXXXXX{last4}"
        return "XXXX-XXXX-XXXX"

    elif detector == DetectorType.PAN:
        if len(raw_value) == 10:
            return f"{raw_value[:3]}XXXXXX{raw_value[-1]}"
        return "XXXXXXXXXX"

    elif detector in (DetectorType.AWS_KEY, DetectorType.GITHUB_TOKEN,
                      DetectorType.OPENAI_KEY, DetectorType.GOOGLE_KEY,
                      DetectorType.ZEROGATE_TOKEN, DetectorType.AWS_SECRET,
                      DetectorType.GENERIC_API_KEY):
        # Keep prefix (first 4-7 chars) and append [REDACTED]
        if len(raw_value) > 10:
            prefix = raw_value[:6]
            return f"{prefix}...[REDACTED]"
        return "[REDACTED_SECRET]"

    return "[REDACTED]"


def redact_document_text(text: str, matches: List[RawMatch]) -> str:
    """
    Replaces all detected raw matches in text with their masked representations.
    Returns the sanitized safe document content.
    """
    if not matches:
        return text

    # Apply redactions from end to start to maintain string offset validity
    sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
    redacted_text = text

    for m in sorted_matches:
        masked_val = mask_sensitive_value(m.detector, m.raw_value)
        redacted_text = redacted_text[:m.start] + masked_val + redacted_text[m.end:]

    return redacted_text
