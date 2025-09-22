# core/entropy.py
"""
Entropy utilities for evidence_rescue.

Provides:
- shannon_entropy(data) -> float
- sample_entropy_bytes(data) -> float (alias)
- entropy_scan(path, window, step, outdir) -> list[dict]
- detect_encrypted(input_path_or_index, threshold, sample_size) -> list[dict]

Behavior:
- entropy_scan writes {outdir}/entropy.json and returns the list of windows with entropy.
- detect_encrypted accepts:
    * a file path to a binary file -> computes entropy on an initial sample and prints classification
    * a JSON index file path -> expects JSON array of entries with at least "path" or "entropy".
      If an entry lacks "entropy" but provides "path", entropy will be calculated (sample of sample_size bytes).
      Writes a report file "<input>.encrypted_report.json" containing classifications and returns it.
"""

from __future__ import annotations
import os
import json
import logging
from math import log2
from typing import List, Dict, Union, Optional

log = logging.getLogger(__name__)


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy (bits per byte) for the provided bytes.
    Returns 0.0 for empty data.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for f in freq:
        if f == 0:
            continue
        p = f / length
        ent -= p * log2(p)
    return ent


def sample_entropy_bytes(data: bytes) -> float:
    """
    Alias for shannon_entropy - kept for backward compatibility.
    """
    return shannon_entropy(data)


def entropy_scan(
    path: str,
    window: int = 1024 * 1024,
    step: int = 512 * 1024,
    outdir: str = "out_entropy",
    max_windows: Optional[int] = None,
) -> List[Dict]:
    """
    Scan `path` in sliding windows and compute Shannon entropy for each window.

    Args:
      path: path to binary/image file to scan
      window: size of each window in bytes (default 1 MiB)
      step: step between windows in bytes (default 512 KiB)
      outdir: directory where entropy.json will be written (created if missing)
      max_windows: optional limit to number of windows scanned (useful for tests)

    Returns:
      List of dicts: [{'offset': int, 'size': int, 'entropy': float}, ...]
    """
    os.makedirs(outdir, exist_ok=True)

    if not os.path.isfile(path):
        raise FileNotFoundError(f"No such file: {path}")

    size = os.path.getsize(path)
    results: List[Dict] = []
    scanned = 0

    log.info("Starting entropy scan: %s (size=%s) window=%d step=%d", path, size, window, step)

    with open(path, "rb") as fh:
        offset = 0
        while offset < size:
            if max_windows is not None and scanned >= max_windows:
                log.debug("Reached max_windows=%d, stopping scan", max_windows)
                break
            fh.seek(offset)
            data = fh.read(window)
            if not data:
                break
            h = shannon_entropy(data)
            results.append({"offset": offset, "size": len(data), "entropy": h})
            scanned += 1
            offset += step
            # occasional log
            if scanned % 50 == 0:
                log.info("Scanned %d windows (offset=%d)", scanned, offset)

    out_json = os.path.join(outdir, "entropy.json")
    try:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        log.info("Wrote entropy scan to %s (windows=%d)", out_json, len(results))
    except Exception as e:
        log.exception("Failed to write entropy json: %s", e)

    return results


def detect_encrypted(
    input_path_or_index: str,
    threshold: float = 10,
    sample_size: int = 16 * 1024,
    out_suffix: str = ".encrypted_report.json",
) -> List[Dict]:
    """
    Detect likely-encrypted files.

    Args:
      input_path_or_index:
        - path to a single file (binary) -> function will read a sample (sample_size) and print classification
        - path to a JSON index file (array of entries) -> will produce a classification for each entry and write a report
          Expected JSON entry shapes supported:
            { "id": "...", "path": "...", "entropy": 7.8 }  OR
            { "path": "..." }  (entropy will be computed from sample)
      threshold: entropy threshold above which file is classified 'likely_encrypted' (default 7.9)
      sample_size: when computing entropy from a file, how many bytes to read (default 16 KiB)
      out_suffix: suffix for the generated report file when input is a JSON index

    Returns:
      list of candidate dicts with keys: id (optional), path, entropy, classification
    """
    def classify_entropy(ent: float, thr: float) -> str:
        return "likely_encrypted" if ent >= thr else "likely_plain"

    def compute_sample_entropy_for_file(p: str, n: int) -> float:
        try:
            with open(p, "rb") as fh:
                sample = fh.read(n)
            return shannon_entropy(sample)
        except Exception as e:
            log.debug("Error reading sample from %s: %s", p, e)
            return 0.0

    results: List[Dict] = []

    # Case A: single file path (not a JSON index)
    if os.path.isfile(input_path_or_index) and not input_path_or_index.lower().endswith(".json"):
        ent = compute_sample_entropy_for_file(input_path_or_index, sample_size)
        cls = classify_entropy(ent, threshold)
        result = {"path": input_path_or_index, "entropy": ent, "classification": cls}
        print(f"{input_path_or_index} entropy: {ent:.4f} => {cls}")
        results.append(result)
        return results

    # Case B: JSON index file expected
    if not os.path.isfile(input_path_or_index):
        raise FileNotFoundError(f"File not found: {input_path_or_index}")

    # Load JSON index
    with open(input_path_or_index, "r", encoding="utf-8") as fh:
        try:
            idx = json.load(fh)
        except Exception as e:
            raise ValueError(f"Failed to parse JSON index {input_path_or_index}: {e}")

    if not isinstance(idx, list):
        raise ValueError("JSON index must be an array/list of entries")

    for entry in idx:
        ent = None
        entry_path = None
        entry_id = entry.get("id") if isinstance(entry, dict) else None

        if isinstance(entry, dict):
            entry_path = entry.get("path")
            ent_val = entry.get("entropy")
            if isinstance(ent_val, (int, float)):
                ent = float(ent_val)
        else:
            # allow entries that are just strings (paths)
            entry_path = entry

        if entry_path:
            if ent is None:
                ent = compute_sample_entropy_for_file(entry_path, sample_size)
        else:
            log.debug("Skipping index entry without path: %s", entry)
            continue

        cls = classify_entropy(ent, threshold)
        out_entry = {
            "id": entry_id,
            "path": entry_path,
            "entropy": ent,
            "classification": cls
        }
        results.append(out_entry)

    out_path = input_path_or_index + out_suffix
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        log.info("Wrote encrypted report to %s", out_path)
    except Exception as e:
        log.exception("Failed to write encrypted report %s: %s", out_path, e)

    print(f"Wrote encrypted report to {out_path} ({len(results)} entries)")

    return results
