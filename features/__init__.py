"""Feature modules for the Secure File Encryption Tool."""

__all__ = [
    "ARGON2_KDF_ID",
    "KDF_ID",
    "decrypt_files",
    "derive_key",
    "encrypt_files",
    "get_kdf_name",
    "is_argon2_available",
    "read_file_in_chunks",
    "validate_password_strength",
    "write_atomic_file",
]


def __getattr__(name):
    if name == "decrypt_files":
        from .batch_operations import decrypt_files
        return decrypt_files
    if name == "encrypt_files":
        from .batch_operations import encrypt_files
        return encrypt_files
    if name in {"ARGON2_KDF_ID", "KDF_ID", "derive_key", "get_kdf_name", "is_argon2_available"}:
        from .kdf_utils import ARGON2_KDF_ID, KDF_ID, derive_key, get_kdf_name, is_argon2_available
        if name == "ARGON2_KDF_ID":
            return ARGON2_KDF_ID
        if name == "KDF_ID":
            return KDF_ID
        if name == "derive_key":
            return derive_key
        if name == "get_kdf_name":
            return get_kdf_name
        if name == "is_argon2_available":
            return is_argon2_available
    if name == "validate_password_strength":
        from .password_validation import validate_password_strength
        return validate_password_strength
    if name in {"read_file_in_chunks", "write_atomic_file"}:
        from .safe_io import read_file_in_chunks, write_atomic_file
        if name == "read_file_in_chunks":
            return read_file_in_chunks
        return write_atomic_file
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
