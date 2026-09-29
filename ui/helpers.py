"""Helper functions for the desktop UI."""

from __future__ import annotations

from pathlib import Path


def format_file_size(size: int) -> str:
    """Convert bytes to a human-readable file-size label."""
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    return f"{value:.2f} {units[index]}" if index else f"{int(value)} {units[index]}"


def get_selected_file_size(file_path: str) -> str:
    """Return a display string for the selected file size."""
    if not file_path:
        return "File size: not selected"
    try:
        size = Path(file_path).stat().st_size
        return f"File size: {format_file_size(size)}"
    except OSError:
        return "File size: unable to read"
