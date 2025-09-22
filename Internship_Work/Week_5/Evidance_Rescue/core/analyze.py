# core/analyze.py
"""
High-level analysis functions for evidence_rescue.

Main exported function:
  - detect_encrypted_candidates(carved_results, fs_file_entries, out_report_path, entropy_threshold=7.6)

This function inspects files (carved outputs and any extracted files from FS metadata)
and detects likely encrypted or password-protected items using:
 - format-specific flags (PDF /Encrypt, ZIP member flag_bits)
 - high-entropy heuristic (Shannon entropy)
 - inability to parse archive formats (treated as suspicious)

It writes a simple report to out_report_path and returns a list of candidate dicts.
Each candidate dict contains: {path, entropy, reasons}
"""

from __future__ import annotations
import os
import zipfile
import logging
from typing import List, Dict, Any, Optional

# try to import helper entropy function from core.entropy (if available)
try:
    from .entropy import shannon_entropy
except Exception:
    # fallback local implementation if core.entropy not available
    from math import log2
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0]*256
        for b in data:
            freq[b] += 1
        ent = 0.0
        L = len(data)
        for c in freq:
            if c == 0:
                continue
            p = c / L
            ent -= p * log2(p)
        return ent

log = logging.getLogger(__name__)

def _check_pdf_encrypted(sample: bytes) -> bool:
    """
    Quick heuristic: check for /Encrypt token inside sample bytes.
    """
    if not sample:
        return False
    return b'/Encrypt' in sample or b'/Filter /Standard' in sample

def _check_zip_encrypted(path: str) -> (bool, Optional[str]):
    """
    Inspect a ZIP (or ZIP-based container like docx) for encrypted entries.
    Returns (is_encrypted, note)
    """
    try:
        with zipfile.ZipFile(path, 'r') as z:
            reasons = []
            for zi in z.infolist():
                # bit 0 set in flag_bits indicates that entry is encrypted
                if zi.flag_bits & 0x1:
                    reasons.append(f"{zi.filename}")
            if reasons:
                return True, "encrypted entries: " + ",".join(reasons)
            else:
                return False, None
    except zipfile.BadZipFile:
        # cannot parse as zip -> suspicious (could be encrypted or corrupted)
        return True, "badzip (cannot parse) - possible encrypted or corrupt"
    except Exception as e:
        return False, f"zip-check-error:{e}"

def _sample_file(path: str, sample_size: int = 65536) -> bytes:
    """
    Return up to sample_size bytes from the start of file. If file not readable, returns b''.
    """
    try:
        with open(path, 'rb') as fh:
            return fh.read(sample_size)
    except Exception:
        return b''

def detect_encrypted_candidates(
    carved_results: List[Dict[str, Any]],
    fs_file_entries: List[Dict[str, Any]],
    out_report_path: str,
    entropy_threshold: float = 7.6
) -> List[Dict[str, Any]]:
    """
    Inspect carved files and FS-extracted files for encryption/password protection.

    Args:
      carved_results: list of dicts from carver (each dict should include 'outpath' key)
      fs_file_entries: list of dicts from fs_parser; if entries have 'extracted_path' they will be checked
      out_report_path: path to write a textual report (one-line-per-candidate)
      entropy_threshold: Shannon entropy threshold above which a file is flagged as high-entropy

    Returns:
      List of candidate dicts, each with keys:
        - path: str (file path)
        - entropy: float
        - reasons: list[str]
    """
    candidates: List[Dict[str, Any]] = []
    checked = set()

    # Build list of file paths to examine
    paths_to_check: List[str] = []

    # carved outputs
    for c in carved_results or []:
        p = c.get('outpath')
        if p:
            paths_to_check.append(p)

    # fs-extracted files (if extracted_path present)
    for e in fs_file_entries or []:
        p = e.get('extracted_path') or e.get('path')
        if p:
            paths_to_check.append(p)

    # dedupe while preserving order
    deduped_paths = []
    for p in paths_to_check:
        if p and p not in checked:
            checked.add(p)
            deduped_paths.append(p)

    for path in deduped_paths:
        reasons = []
        sample = _sample_file(path, 65536)
        ent = shannon_entropy(sample)

        # Format-specific heuristics
        # PDF
        if sample.startswith(b'%PDF') or sample[:4] == b'%PDF':
            if _check_pdf_encrypted(sample):
                reasons.append("PDF /Encrypt flag")

        # ZIP-like (PK...) (docx/pptx/xlsx)
        if sample.startswith(b'PK') or sample[:2] == b'PK':
            zip_flag, note = _check_zip_encrypted(path)
            if zip_flag:
                reasons.append(f"ZIP/Office: {note}")

        # High entropy
        if ent >= entropy_threshold:
            reasons.append(f"low_entropy:{ent:.2f}")

        # If we couldn't read sample at all, mark as unreadable
        if not sample:
            reasons.append("unreadable_or_empty")

        if reasons:
            cand = {'path': path, 'entropy': ent, 'reasons': reasons}
            candidates.append(cand)

    # Write simple tab-separated report lines to out_report_path
    try:
        os.makedirs(os.path.dirname(out_report_path) or ".", exist_ok=True)
        with open(out_report_path, 'w', encoding='utf-8') as of:
            for c in candidates:
                of.write(f"{c['path']}\t{c['entropy']:.4f}\t{';'.join(c['reasons'])}\n")
    except Exception as e:
        log.exception("Failed to write encrypted candidates report %s: %s", out_report_path, e)

    return candidates
