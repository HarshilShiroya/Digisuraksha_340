# core/repo_utils.py
import os
from pathlib import Path
from typing import Union


def ensure_dir(path: Union[str, Path]) -> str:
    """
    Ensure the given directory exists. Creates parent directories if necessary.

    Args:
        path (str | Path): Directory path.

    Returns:
        str: The absolute path of the ensured directory.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return str(p.resolve())


def safe_write_text(path: Union[str, Path], data: str, encoding: str = 'utf-8') -> str:
    """
    Safely write text to a file using atomic write (via temp file then replace).

    Args:
        path (str | Path): Target file path.
        data (str): Text content to write.
        encoding (str, optional): File encoding. Defaults to 'utf-8'.

    Returns:
        str: The absolute path of the written file.
    """
    p = Path(path)
    ensure_dir(p.parent)

    tmp = p.with_suffix(p.suffix + '.tmp')

    # Remove old tmp if exists
    if tmp.exists():
        tmp.unlink()

    with tmp.open('w', encoding=encoding) as fh:
        fh.write(data)

    tmp.replace(p)
    return str(p.resolve())


def human_size(num: float, suffix: str = 'B') -> str:
    """
    Convert file size in bytes into a human-readable format.

    Args:
        num (float): File size in bytes.
        suffix (str, optional): Unit suffix. Defaults to 'B'.

    Returns:
        str: Human-readable file size string (e.g., '1.2MB').
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}P{suffix}"
