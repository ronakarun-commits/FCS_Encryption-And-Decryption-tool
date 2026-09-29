"""Security-focused file encryption helpers for the Secure File Encryption Tool.

This module keeps the cryptographic core separate from the GUI and includes
validation for the SFET file format, key derivation, and AES-GCM authentication.
The implementation is intentionally simple enough for learning while still using
secure defaults and safer file handling.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, Dict, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from features.kdf_utils import (
    ARGON2_KDF_ID,
    ARGON2_TIME_COST,
    AES_KEY_LENGTH,
    KDF_ID,
    KDF_ITERATIONS,
    SALT_LENGTH,
    derive_key as kdf_derive_key,
    get_kdf_name as kdf_get_kdf_name,
    is_argon2_available as kdf_is_argon2_available,
)
from features.safe_io import write_atomic_file as safe_write_atomic_file

MAGIC = b"SFET"
VERSION = 1
NONCE_LENGTH = 12
MAX_FILENAME_LENGTH = 65535
FILE_SIZE_LENGTH = 8
HEADER_MIN_SIZE = 4 + 1 + 1 + 4 + SALT_LENGTH + NONCE_LENGTH + 2 + FILE_SIZE_LENGTH


class SFETError(Exception):
    """Base class for SFET file validation and processing errors."""


class InvalidHeaderError(SFETError):
    """Raised when the encrypted file header is malformed or unsupported."""


class AuthenticationFailureError(SFETError):
    """Raised when AES-GCM authentication fails."""


def is_argon2_available() -> bool:
    """Return True when Argon2id support is available in the Python environment."""
    return kdf_is_argon2_available()


def write_atomic_file(path: Union[str, Path], content: bytes) -> Path:
    """Write a file atomically so partial output is avoided on errors."""
    return safe_write_atomic_file(path, content)


def get_kdf_name(kdf_id: int) -> str:
    """Return a readable label for the selected key-derivation function."""
    return kdf_get_kdf_name(kdf_id)


def build_aad(version: int, kdf_id: int, filename_bytes: bytes, file_size: int) -> bytes:
    """Construct deterministic authenticated metadata for AES-GCM."""
    if not isinstance(filename_bytes, (bytes, bytearray)):
        raise TypeError("filename_bytes must be bytes-like.")

    filename_bytes = bytes(filename_bytes)
    if len(filename_bytes) > MAX_FILENAME_LENGTH:
        raise ValueError("Filename is too long for the SFET header format.")
    if file_size < 0:
        raise ValueError("file_size cannot be negative.")

    return struct.pack("!BBH", version, kdf_id, len(filename_bytes)) + filename_bytes + struct.pack("!Q", file_size)


def create_sfet_header(
    version: int,
    kdf_id: int,
    iterations: int,
    salt: bytes,
    nonce: bytes,
    filename_bytes: bytes,
    file_size: int,
) -> bytes:
    """Build the custom SFET header for an encrypted file."""
    if version != VERSION:
        raise ValueError(f"Unsupported SFET version: {version}")
    if kdf_id not in (KDF_ID, ARGON2_KDF_ID):
        raise ValueError(f"Unsupported KDF ID: {kdf_id}")
    if iterations <= 0:
        raise ValueError("Key-derivation iteration count must be positive.")
    if not isinstance(salt, (bytes, bytearray)) or len(bytes(salt)) != SALT_LENGTH:
        raise ValueError("Salt must be exactly 16 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(bytes(nonce)) != NONCE_LENGTH:
        raise ValueError("Nonce must be exactly 12 bytes.")
    if not isinstance(filename_bytes, (bytes, bytearray)):
        raise TypeError("filename_bytes must be bytes-like.")
    if file_size < 0:
        raise ValueError("file_size must be non-negative.")

    filename_bytes = bytes(filename_bytes)
    if len(filename_bytes) > MAX_FILENAME_LENGTH:
        raise ValueError("Filename is too long for the SFET header format.")

    header = bytearray()
    header.extend(MAGIC)
    header.extend(struct.pack("!BBI", version, kdf_id, iterations))
    header.extend(bytes(salt))
    header.extend(bytes(nonce))
    header.extend(struct.pack("!H", len(filename_bytes)))
    header.extend(struct.pack("!Q", file_size))
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
    if kdf_id not in (KDF_ID, ARGON2_KDF_ID):
        raise InvalidHeaderError(f"Unsupported KDF ID: {kdf_id}")

    iterations = struct.unpack("!I", blob[6:10])[0]
    if iterations <= 0:
        raise InvalidHeaderError("Invalid key-derivation iteration count.")

    salt = blob[10:26]
    if len(salt) != SALT_LENGTH:
        raise InvalidHeaderError("Invalid salt length in SFET header.")

    nonce = blob[26:38]
    if len(nonce) != NONCE_LENGTH:
        raise InvalidHeaderError("Invalid nonce length in SFET header.")

    filename_length = struct.unpack("!H", blob[38:40])[0]
    file_size = struct.unpack("!Q", blob[40:48])[0]
    if 48 + filename_length > len(blob):
        raise InvalidHeaderError("Filename length exceeds the size of the encrypted file.")

    filename_bytes = blob[48:48 + filename_length]
    ciphertext = blob[48 + filename_length:]
    if len(ciphertext) < 16:
        raise InvalidHeaderError("Encrypted file is truncated or missing the authentication tag.")

    return {
        "magic": magic,
        "version": version,
        "kdf_id": kdf_id,
        "iterations": iterations,
        "salt": salt,
        "nonce": nonce,
        "filename_length": filename_length,
        "file_size": file_size,
        "filename": filename_bytes,
        "ciphertext": ciphertext,
    }


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS, kdf_id: int = KDF_ID) -> bytes:
    """Derive a 256-bit AES key using PBKDF2 or Argon2id."""
    return kdf_derive_key(password, salt, iterations, kdf_id)


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    kdf_id: int = KDF_ID,
    iterations: int | None = None,
) -> Dict[str, Any]:
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

        if kdf_id not in (KDF_ID, ARGON2_KDF_ID):
            return {"success": False, "message": f"Unsupported KDF ID: {kdf_id}"}

        selected_iterations = KDF_ITERATIONS if iterations is None else iterations
        if kdf_id == ARGON2_KDF_ID and iterations is None:
            selected_iterations = ARGON2_TIME_COST

        salt = os.urandom(SALT_LENGTH)
        nonce = os.urandom(NONCE_LENGTH)
        key = derive_key(password, salt, selected_iterations, kdf_id)
        aad = build_aad(VERSION, kdf_id, filename_bytes, len(plaintext))
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

        header = create_sfet_header(VERSION, kdf_id, selected_iterations, salt, nonce, filename_bytes, len(plaintext))

        output_file = Path(output_path)
        if output_file.exists():
            return {"success": False, "message": "Output file already exists. Choose a different output path or remove the existing file."}

        payload = header + ciphertext
        write_atomic_file(output_file, payload)

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


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
) -> Dict[str, Any]:
    """Decrypt an SFET file only after authenticated AES-GCM verification succeeds."""
    try:
        encrypted_file = Path(input_path)
        if not encrypted_file.exists():
            return {"success": False, "message": "Encrypted file does not exist."}
        if not encrypted_file.is_file():
            return {"success": False, "message": "Encrypted path is not a valid file."}

        blob = encrypted_file.read_bytes()
        parsed = parse_sfet_header(blob)
        key = derive_key(password, parsed["salt"], parsed["iterations"], parsed["kdf_id"])

        ciphertext = parsed["ciphertext"]
        if len(ciphertext) < 16:
            return {"success": False, "message": "Encrypted file is truncated or invalid."}

        aad = build_aad(parsed["version"], parsed["kdf_id"], parsed["filename"], parsed["file_size"])

        try:
            plaintext = AESGCM(key).decrypt(parsed["nonce"], ciphertext, aad)
        except InvalidTag:
            return {
                "success": False,
                "message": "Authentication failed. The encrypted file may have been modified or corrupted.",
            }

        if len(plaintext) != parsed["file_size"]:
            return {
                "success": False,
                "message": "Authentication failed. The encrypted file may have been modified or corrupted.",
            }

        output_file = Path(output_path)
        if output_file.exists():
            return {"success": False, "message": "Output file already exists. Choose a different output path or remove the existing file."}

        write_atomic_file(output_file, plaintext)

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
    "ARGON2_KDF_ID",
    "ARGON2_TIME_COST",
    "KDF_ITERATIONS",
    "MAGIC",
    "VERSION",
    "KDF_ID",
    "is_argon2_available",
    "write_atomic_file",
    "get_kdf_name",
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
