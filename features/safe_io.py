"""File I/O helpers for safe reading and atomic output writes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Union


def read_file_in_chunks(file_path: Union[str, Path], chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file contents in small blocks to keep memory use low."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def write_atomic_file(path: Union[str, Path], content: bytes) -> Path:
    """Write bytes to a temp file and replace the target atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target.with_name(f".{target.name}.tmp")

    if temp_path.exists():
        temp_path.unlink()

    with temp_path.open("wb") as handle:
        handle.write(content)

    os.replace(temp_path, target)
    return target


def ensure_parent_directory(path: Union[str, Path]) -> Path:
    """Create the parent directory for a file path when needed."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination
