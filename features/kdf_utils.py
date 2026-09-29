"""Key-derivation helpers for PBKDF2 and Argon2id."""

from __future__ import annotations

import hashlib

try:
    from argon2.low_level import Type, hash_secret_raw

    ARGON2_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    ARGON2_AVAILABLE = False
    Type = None
    hash_secret_raw = None

KDF_ID = 1
ARGON2_KDF_ID = 2
KDF_ITERATIONS = 600_000
ARGON2_TIME_COST = 3
SALT_LENGTH = 16
AES_KEY_LENGTH = 32


def is_argon2_available() -> bool:
    """Return True when Argon2id support is available."""
    return ARGON2_AVAILABLE


def get_kdf_name(kdf_id: int) -> str:
    """Return a readable KDF label."""
    if kdf_id == KDF_ID:
        return "PBKDF2-HMAC-SHA256"
    if kdf_id == ARGON2_KDF_ID:
        return "Argon2id"
    raise ValueError(f"Unsupported KDF ID: {kdf_id}")


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS, kdf_id: int = KDF_ID) -> bytes:
    """Derive a 256-bit AES key using PBKDF2 or Argon2id."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be bytes.")

    salt_bytes = bytes(salt)
    if len(salt_bytes) != SALT_LENGTH:
        raise ValueError("Salt length must be exactly 16 bytes.")

    if kdf_id == KDF_ID:
        if iterations <= 0:
            raise ValueError("PBKDF2 iteration count must be greater than zero.")
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            iterations,
            dklen=AES_KEY_LENGTH,
        )

    if kdf_id == ARGON2_KDF_ID:
        if not ARGON2_AVAILABLE:
            raise RuntimeError("Argon2id support requires the argon2-cffi package to be installed.")

        time_cost = ARGON2_TIME_COST if iterations == KDF_ITERATIONS else max(1, int(iterations))
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt_bytes,
            time_cost=time_cost,
            memory_cost=64 * 1024,
            parallelism=2,
            hash_len=AES_KEY_LENGTH,
            type=Type.ID,
        )

    raise ValueError(f"Unsupported KDF ID: {kdf_id}")
