"""Password validation and strength-check helpers."""

from __future__ import annotations


def validate_password_strength(password: str) -> dict:
    """Return a simple password-strength score for the GUI."""
    if not isinstance(password, str):
        return {"score": 0, "label": "Invalid", "criteria": []}

    checks = {
        "minimum_length": len(password) >= 8,
        "uppercase": any(ch.isupper() for ch in password),
        "lowercase": any(ch.islower() for ch in password),
        "digit": any(ch.isdigit() for ch in password),
        "special": any(not ch.isalnum() for ch in password),
    }

    score = sum(1 for value in checks.values() if value)
    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"

    return {"score": score, "label": label, "criteria": checks}
