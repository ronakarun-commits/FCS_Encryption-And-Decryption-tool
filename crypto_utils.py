"""Security-focused file encryption helpers for the Secure File Encryption Tool.

This module implements the Phase 1 cryptographic core required by the mini-project.
It intentionally keeps the encryption logic separate from the GUI and includes
validation around the custom SFET file format, PBKDF2 key derivation, and AES-GCM
authentication checks.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SFET"
VERSION = 1
KDF_ID = 1
KDF_ITERATIONS = 600_000
SALT_LENGTH = 16
NONCE_LENGTH = 12
AES_KEY_LENGTH = 32
MAX_FILENAME_LENGTH = 65535
HEADER_MIN_SIZE = 4 + 1 + 1 + 4 + SALT_LENGTH + NONCE_LENGTH + 2


class SFETError(Exception):
    """Base class for SFET file validation and processing errors."""


class InvalidHeaderError(SFETError):
    """Raised when the encrypted file header is malformed or unsupported."""


class AuthenticationFailureError(SFETError):
    """Raised when AES-GCM authentication fails."""


def build_aad(version: int, kdf_id: int, filename_bytes: bytes, file_size: int) -> bytes:
    """Construct deterministic authenticated metadata for AES-GCM.

    The metadata includes the file format version, KDF identifier, original filename,
    and the original file size. The same inputs must always produce the same AAD.
    """
    if not isinstance(filename_bytes, (bytes, bytearray)):
        raise TypeError("filename_bytes must be bytes-like.")

    filename_bytes = bytes(filename_bytes)
    if len(filename_bytes) > MAX_FILENAME_LENGTH:
        raise ValueError("Filename is too long for the SFET header format.")
    if file_size < 0:
        raise ValueError("file_size cannot be negative.")

    return struct.pack("!BBH", version, kdf_id, len(filename_bytes)) + filename_bytes + struct.pack("!Q", file_size)


def create_sfet_header(version: int, kdf_id: int, iterations: int, salt: bytes, nonce: bytes, filename_bytes: bytes) -> bytes:
    """Build the custom SFET header for an encrypted file."""
    if version != VERSION:
        raise ValueError(f"Unsupported SFET version: {version}")
    if kdf_id != KDF_ID:
        raise ValueError(f"Unsupported KDF ID: {kdf_id}")
    if iterations <= 0:
        raise ValueError("PBKDF2 iteration count must be positive.")
    if not isinstance(salt, (bytes, bytearray)) or len(bytes(salt)) != SALT_LENGTH:
        raise ValueError("Salt must be exactly 16 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(bytes(nonce)) != NONCE_LENGTH:
        raise ValueError("Nonce must be exactly 12 bytes.")
    if not isinstance(filename_bytes, (bytes, bytearray)):
        raise TypeError("filename_bytes must be bytes-like.")

    filename_bytes = bytes(filename_bytes)
    if len(filename_bytes) > MAX_FILENAME_LENGTH:
        raise ValueError("Filename is too long for the SFET header format.")

    header = bytearray()
    header.extend(MAGIC)
    header.extend(struct.pack("!BBI", version, kdf_id, iterations))
    header.extend(bytes(salt))
    header.extend(bytes(nonce))
    header.extend(struct.pack("!H", len(filename_bytes)))
    header.extend(filename_bytes)
    return bytes(header)


def parse_sfet_header(data: bytes) -> Dict[str, Any]:
    """Parse and validate the SFET header stored at the start of encrypted files."""
    if not isinstance(data, (bytes, bytearray)):
        raise InvalidHeaderError("Encrypted file content is not valid bytes.")

    blob = bytes(data)
    if len(blob) < HEADER_MIN_SIZE:
        raise InvalidHeaderError("Encrypted file is too short to contain a valid SFET header.")

    magic = blob[:4]
    if magic != MAGIC:
        raise InvalidHeaderError("Invalid encrypted file: magic number does not match SFET.")

    version = blob[4]
    if version != VERSION:
        raise InvalidHeaderError(f"Unsupported SFET version: {version}")

    kdf_id = blob[5]
    if kdf_id != KDF_ID:
        raise InvalidHeaderError(f"Unsupported KDF ID: {kdf_id}")

    iterations = struct.unpack("!I", blob[6:10])[0]
    if iterations <= 0:
        raise InvalidHeaderError("Invalid PBKDF2 iteration count.")

    salt = blob[10:26]
    if len(salt) != SALT_LENGTH:
        raise InvalidHeaderError("Invalid salt length in SFET header.")

    nonce = blob[26:38]
    if len(nonce) != NONCE_LENGTH:
        raise InvalidHeaderError("Invalid nonce length in SFET header.")

    filename_length = struct.unpack("!H", blob[38:40])[0]
    if 40 + filename_length > len(blob):
        raise InvalidHeaderError("Filename length exceeds the size of the encrypted file.")

    filename_bytes = blob[40:40 + filename_length]
    ciphertext = blob[40 + filename_length:]
    if len(ciphertext) < 16:
        raise InvalidHeaderError("Encrypted file is truncated or missing the authentication tag.")

    return {
        "magic": magic,
        "version": version,
        "kdf_id": kdf_id,
        "iterations": iterations,
        "salt": salt,
        "nonce": nonce,
        "filename": filename_bytes,
        "ciphertext": ciphertext,
    }


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be bytes.")

    salt_bytes = bytes(salt)
    if len(salt_bytes) != SALT_LENGTH:
        raise ValueError("Salt length must be exactly 16 bytes.")
    if iterations <= 0:
        raise ValueError("PBKDF2 iteration count must be greater than zero.")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        iterations,
        dklen=AES_KEY_LENGTH,
    )


def encrypt_file(input_path: str, output_path: str, password: str) -> Dict[str, Any]:
    """Encrypt a file using AES-256-GCM and store it in the custom SFET format."""
    try:
        input_file = Path(input_path)
        if not input_file.exists():
            return {"success": False, "message": "Input file does not exist."}
        if not input_file.is_file():
            return {"success": False, "message": "Input path is not a valid file."}

        plaintext = input_file.read_bytes()
        original_name = os.path.basename(str(input_file))
        filename_bytes = original_name.encode("utf-8", "surrogateescape")
        if len(filename_bytes) > MAX_FILENAME_LENGTH:
            return {"success": False, "message": "Filename is too long to encrypt."}

        salt = os.urandom(SALT_LENGTH)
        nonce = os.urandom(NONCE_LENGTH)
        key = derive_key(password, salt, KDF_ITERATIONS)
        aad = build_aad(VERSION, KDF_ID, filename_bytes, len(plaintext))
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

        header = create_sfet_header(VERSION, KDF_ID, KDF_ITERATIONS, salt, nonce, filename_bytes)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("wb") as handle:
            handle.write(header)
            handle.write(ciphertext)

        return {
            "success": True,
            "message": "File encrypted successfully.",
            "output_path": str(output_file),
        }
    except PermissionError:
        return {"success": False, "message": "Permission denied while reading or writing files."}
    except ValueError as exc:
        return {"success": False, "message": str(exc)}
    except OSError as exc:
        return {"success": False, "message": f"File I/O error: {exc}"}
    except Exception:
        return {"success": False, "message": "Unexpected cryptographic error while encrypting the file."}


def decrypt_file(input_path: str, output_path: str, password: str) -> Dict[str, Any]:
    """Decrypt an SFET file only after authenticated AES-GCM verification succeeds."""
    try:
        encrypted_file = Path(input_path)
        if not encrypted_file.exists():
            return {"success": False, "message": "Encrypted file does not exist."}
        if not encrypted_file.is_file():
            return {"success": False, "message": "Encrypted path is not a valid file."}

        blob = encrypted_file.read_bytes()
        parsed = parse_sfet_header(blob)
        key = derive_key(password, parsed["salt"], parsed["iterations"])

        ciphertext = parsed["ciphertext"]
        if len(ciphertext) < 16:
            return {"success": False, "message": "Encrypted file is truncated or invalid."}

        original_length = len(ciphertext) - 16
        aad = build_aad(parsed["version"], parsed["kdf_id"], parsed["filename"], original_length)

        try:
            plaintext = AESGCM(key).decrypt(parsed["nonce"], ciphertext, aad)
        except InvalidTag:
            return {
                "success": False,
                "message": "Authentication failed. The encrypted file may have been modified or corrupted.",
            }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with output_file.open("wb") as handle:
            handle.write(plaintext)

        return {
            "success": True,
            "message": "File decrypted successfully.",
            "output_path": str(output_file),
        }
    except InvalidHeaderError as exc:
        return {"success": False, "message": str(exc)}
    except PermissionError:
        return {"success": False, "message": "Permission denied while reading or writing files."}
    except ValueError as exc:
        return {"success": False, "message": str(exc)}
    except OSError as exc:
        return {"success": False, "message": f"File I/O error: {exc}"}
    except Exception:
        return {"success": False, "message": "Unexpected cryptographic error while decrypting the file."}


__all__ = [
    "AES_KEY_LENGTH",
    "KDF_ITERATIONS",
    "MAGIC",
    "VERSION",
    "KDF_ID",
    "SFETError",
    "InvalidHeaderError",
    "AuthenticationFailureError",
    "build_aad",
    "create_sfet_header",
    "parse_sfet_header",
    "derive_key",
    "encrypt_file",
    "decrypt_file",
]
