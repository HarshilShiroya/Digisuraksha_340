# core/signature_loader.py
"""
Load and normalize signature DB (JSON). Accepts headers/footers expressed
as hex strings OR as literal ASCII sequences (e.g. "%%EOF").

Output: list of signature dicts with:
  - id (str)
  - ext (list[str])
  - header_bytes (list[bytes])
  - footer_bytes (list[bytes])
  - offset (int)
  - min_size (int)
  - description (str)
"""

from pathlib import Path
import json
import re
from typing import List, Tuple

HEX_CHARS_RE = re.compile(r'^[0-9a-fA-F\s]+$')

def _try_parse_hex(s: str) -> bytes:
    s2 = ''.join(s.split())
    if len(s2) % 2 == 1:
        s2 = '0' + s2
    return bytes.fromhex(s2)

def _to_bytes(sig_str: str) -> bytes:
    if not isinstance(sig_str, str):
        raise TypeError("signature must be a string")
    s = sig_str.strip()
    if s == "":
        return b""
    if HEX_CHARS_RE.match(s):
        try:
            return _try_parse_hex(s)
        except Exception:
            return s.encode('latin-1', errors='replace')
    return s.encode('latin-1', errors='replace')

def load_signatures(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)

    raw = json.loads(p.read_text(encoding='utf-8'))
    signatures = []
    problems = []
    seen_ids = set()

    if not isinstance(raw, list):
        problems.append("signature file root is not a list")
        return [], problems

    for idx, entry in enumerate(raw):
        try:
            sid = entry.get('id', f'entry_{idx}')
            if sid in seen_ids:
                problems.append(f"duplicate id '{sid}' at index {idx}")
            seen_ids.add(sid)

            exts = entry.get('ext') or []
            if isinstance(exts, str):
                exts = [exts]
            header_list = entry.get('header') or []
            footer_list = entry.get('footer') or []
            offset = int(entry.get('offset', 0) or 0)
            min_size = int(entry.get('min_size', 1) or 1)
            desc = entry.get('description', '')

            header_bytes = []
            footer_bytes = []

            if isinstance(header_list, str):
                header_list = [header_list]
            if isinstance(footer_list, str):
                footer_list = [footer_list]

            for h in header_list:
                try:
                    hb = _to_bytes(h)
                    if hb:
                        header_bytes.append(hb)
                    else:
                        problems.append(f"{sid}: header '{h}' parsed to empty bytes")
                except Exception as e:
                    problems.append(f"{sid}: header parse error '{h}': {e}")

            for f in footer_list:
                try:
                    fb = _to_bytes(f)
                    if fb:
                        footer_bytes.append(fb)
                except Exception as e:
                    problems.append(f"{sid}: footer parse error '{f}': {e}")

            signatures.append({
                'id': sid,
                'ext': exts,
                'header_bytes': header_bytes,
                'footer_bytes': footer_bytes,
                'offset': offset,
                'min_size': min_size,
                'description': desc
            })
        except Exception as e:
            problems.append(f"entry at index {idx} failed to parse: {e}")

    return signatures, problems
