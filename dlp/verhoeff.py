"""
ZeroGate Cloud — Verhoeff Checksum Algorithm
Implements dihedral group D5 checksum calculation and verification
for Indian Aadhaar synthetic numbers.
"""

# Multiplication table d (Dihedral group D5)
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table p
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table inv
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number_str: str) -> bool:
    """
    Validates a numeric string using the Verhoeff algorithm.
    Returns True if the check digit matches, False otherwise.
    """
    if not number_str or not number_str.isdigit():
        return False
    c = 0
    reversed_digits = [int(x) for x in reversed(number_str)]
    for i, digit in enumerate(reversed_digits):
        c = _D[c][_P[i % 8][digit]]
    return c == 0


def generate_verhoeff_checksum(number_str: str) -> int:
    """
    Calculates the Verhoeff check digit for an input string of digits.
    Appending this digit produces a string that passes validate_verhoeff().
    """
    if not number_str or not number_str.isdigit():
        raise ValueError("Input must be a non-empty numeric string")
    c = 0
    reversed_digits = [int(x) for x in reversed(number_str)]
    for i, digit in enumerate(reversed_digits):
        c = _D[c][_P[(i + 1) % 8][digit]]
    return _INV[c]


def generate_synthetic_aadhaar(seed_11_digits: str) -> str:
    """
    Given 11 digits starting with [2-9], computes the 12th Verhoeff check digit
    to return a valid synthetic 12-digit Aadhaar number for testing.
    """
    if len(seed_11_digits) != 11 or not seed_11_digits.isdigit():
        raise ValueError("Seed must be exactly 11 digits")
    if seed_11_digits[0] in ("0", "1"):
        raise ValueError("Aadhaar seed cannot start with 0 or 1")
    check_digit = generate_verhoeff_checksum(seed_11_digits)
    return f"{seed_11_digits}{check_digit}"
