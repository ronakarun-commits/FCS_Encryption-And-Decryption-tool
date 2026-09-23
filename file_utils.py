"""Utility helpers for secure file operations, hashing, and logging.

This module contains file validation, SHA-256 hashing, output-path handling, and
safe activity logging for the desktop encryption tool.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional, Union


def calculate_sha256(file_path: Union[str, Path]) -> str:
    """Return the SHA-256 hex digest for a file."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_password_strength(password: str) -> dict:
    """Provide a simple usability-focused password strength score."""
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


def ensure_parent_directory(path: Union[str, Path]) -> Path:
    """Create the parent directory for a file path whenever needed."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def resolve_output_path(
    input_path: Union[str, Path],
    selected_output: Optional[Union[str, Path]] = None,
    is_encrypt: bool = True,
    original_name: Optional[str] = None,
) -> Path:
    """Resolve the output path based on input, user selection, and operation type."""
    input_file = Path(input_path)
    if selected_output:
        candidate = Path(selected_output)
        if candidate.suffix == "" and candidate.exists() and candidate.is_dir():
            if is_encrypt:
                filename = f"{input_file.name}.enc"
            else:
                filename = original_name or input_file.name
            return candidate / filename
        return candidate

    if is_encrypt:
        return input_file.with_name(f"{input_file.name}.enc")

    if original_name:
        return input_file.with_name(original_name)
    return input_file.with_name(f"{input_file.stem}_decrypted{input_file.suffix}")


def setup_logging(log_dir: Union[str, Path] = "logs") -> logging.Logger:
    """Create a safe logger that records application activity without secrets."""
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("secure_file_tool")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        file_handler = logging.FileHandler(log_path / "secure_file_tool.log", encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s - %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_activity(message: str) -> None:
    """Write a safe application log entry without storing sensitive data."""
    logger = setup_logging()
    logger.info(message)
