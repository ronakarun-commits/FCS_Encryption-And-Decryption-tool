"""Simple batch helpers for processing groups of files."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from crypto_utils import decrypt_file, encrypt_file


def encrypt_files(file_paths: Iterable[str], password: str, output_dir: str | None = None) -> List[str]:
    """Encrypt a collection of input files and return output paths."""
    results: List[str] = []
    target_dir = Path(output_dir) if output_dir else None

    for input_path in file_paths:
        source = Path(input_path)
        target = target_dir / f"{source.name}.enc" if target_dir else source.with_name(f"{source.name}.enc")
        result = encrypt_file(str(source), str(target), password)
        if result["success"]:
            results.append(str(target))

    return results


def decrypt_files(file_paths: Iterable[str], password: str, output_dir: str | None = None) -> List[str]:
    """Decrypt a collection of encrypted files and return output paths."""
    results: List[str] = []
    target_dir = Path(output_dir) if output_dir else None

    for input_path in file_paths:
        source = Path(input_path)
        if target_dir:
            target = target_dir / source.name.replace(".enc", "")
        else:
            target = source.with_name(source.name.replace(".enc", ""))

        result = decrypt_file(str(source), str(target), password)
        if result["success"]:
            results.append(str(target))

    return results
