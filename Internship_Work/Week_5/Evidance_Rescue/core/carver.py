# core/carver.py
"""
Signature carver with strict ZIP central-directory validation.

Key improvements:
- Parses EOCD and central directory entries to ensure a candidate slice
  actually *starts* at the archive (one CD entry must have rel_offset == 0).
- Verifies referenced local headers exist and lie within the slice.
- Avoids large in-memory Zip opens; better correctness for many PK markers.
"""

import mmap
from pathlib import Path
from typing import List, Dict, Optional
import os

JPEG_START = bytes.fromhex('ffd8ff')
JPEG_END = bytes.fromhex('ffd9')
PNG_IEND = bytes.fromhex('49454e44ae426082')  # IEND + CRC
PDF_EOF = b'%%EOF'
ZIP_EOCD = b'PK\x05\x06'  # EOCD signature
ZIP_CENTRAL = b'PK\x01\x02'  # central dir file header signature
ZIP_LOCAL = b'PK\x03\x04'  # local file header
MAX_CARVE_SIZE = 200 * 1024 * 1024
ZIP_MAX_SEARCH = 50 * 1024 * 1024  # how far to search for EOCD after a header
ZIP_MAX_EXTRACT = 200 * 1024 * 1024  # safety upper bound for archive size to consider

def _find_all(mm: mmap.mmap, pattern: bytes, start: int = 0):
    pos = mm.find(pattern, start)
    while pos != -1:
        yield pos
        pos = mm.find(pattern, pos + 1)

def _find_next_header(mm: mmap.mmap, headers: List[bytes], start: int):
    next_pos = None
    for h in headers:
        pos = mm.find(h, start + 1)
        if pos != -1:
            if next_pos is None or pos < next_pos:
                next_pos = pos
    return next_pos

def _iter_eocd_candidates(mm: mmap.mmap, start: int, search_end: int):
    pos = mm.find(ZIP_EOCD, start + 4, search_end)
    while pos != -1:
        yield pos
        pos = mm.find(ZIP_EOCD, pos + 1, search_end)

def _eocd_end(mm: mmap.mmap, eocd_pos: int) -> Optional[int]:
    """
    Compute EOCD end offset (22 bytes + comment length). Return None if truncated.
    """
    size = mm.size()
    if eocd_pos + 22 > size:
        return None
    # comment length = 2 bytes at offset eocd_pos+20
    comment_len = int.from_bytes(mm[eocd_pos + 20:eocd_pos + 22], 'little')
    eocd_end = eocd_pos + 22 + comment_len
    if eocd_end > size:
        return None
    return eocd_end

def _parse_central_directory_and_validate(mm: mmap.mmap, start: int, eocd_pos: int) -> Optional[int]:
    """
    Given mm and start and EOCD position, parse EOCD entries:
      - read cd_size and cd_offset from EOCD
      - compute cd_abs = start + cd_offset
      - ensure cd_abs + cd_size <= eocd_pos
      - parse central dir entries (signature PK\x01\x02), for each entry:
          * read filename_len, extra_len, comment_len
          * read relative_local_header_offset (4 bytes at offset 42 within the central entry header)
          * verify that at least one relative_local_header_offset == 0 (archive begins at slice start)
          * verify local header at start + rel_offset begins with PK\x03\x04
    Returns eocd_end if valid; else None.
    """
    size = mm.size()
    if eocd_pos + 22 > size:
        return None
    try:
        cd_size = int.from_bytes(mm[eocd_pos + 12:eocd_pos + 16], 'little')
        cd_offset = int.from_bytes(mm[eocd_pos + 16:eocd_pos + 20], 'little')
    except Exception:
        return None
    cd_abs = start + cd_offset
    if cd_abs < start or cd_abs + cd_size > eocd_pos:
        return None
    if cd_size < 0 or cd_size > (eocd_pos - cd_abs):
        return None
    pos = cd_abs
    end_cd = cd_abs + cd_size
    found_entries = 0
    has_rel0 = False
    while pos + 46 <= end_cd:
        sig = mm[pos:pos+4]
        if sig != ZIP_CENTRAL:
            break
        try:
            fname_len = int.from_bytes(mm[pos+28:pos+30], 'little')
            extra_len = int.from_bytes(mm[pos+30:pos+32], 'little')
            comment_len = int.from_bytes(mm[pos+32:pos+34], 'little')
            rel_offset = int.from_bytes(mm[pos+42:pos+46], 'little')
        except Exception:
            return None
        total_entry_len = 46 + fname_len + extra_len + comment_len
        if pos + total_entry_len > end_cd:
            return None
        local_abs = start + rel_offset
        if not (start <= local_abs < eocd_pos):
            return None
        if local_abs + 4 > size:
            return None
        if mm[local_abs:local_abs+4] != ZIP_LOCAL:
            return None
        if rel_offset == 0:
            has_rel0 = True
        found_entries += 1
        pos += total_entry_len
    if found_entries == 0 or not has_rel0:
        return None
    eocd_end = _eocd_end(mm, eocd_pos)
    return eocd_end

def carve_by_signatures(image_path: str, signatures: List[dict], outdir: str = 'carved', verbose: bool = True) -> List[Dict]:
    os.makedirs(outdir, exist_ok=True)
    results: List[Dict] = []
    seen_ranges = set()  # avoid exact duplicates

    p = Path(image_path)
    size = p.stat().st_size

    # collect all headers for next-header fallback
    all_headers = []
    for sig in signatures:
        for h in sig.get('header_bytes', []):
            if h:
                all_headers.append(h)

    with open(image_path, 'rb') as fh:
        mm = mmap.mmap(fh.fileno(), length=0, access=mmap.ACCESS_READ)

        for sig in signatures:
            sid = sig.get('id')
            headers = sig.get('header_bytes', []) or []
            footers = sig.get('footer_bytes', []) or []
            min_size = int(sig.get('min_size', 1) or 1)
            exts = sig.get('ext') or []
            preferred_ext = (exts[0] if exts else sid)

            occ = 0
            for header in headers:
                for start in _find_all(mm, header, start=0):
                    # offset enforcement if provided
                    if sig.get('offset', 0):
                        if start != int(sig['offset']):
                            continue

                    end = None

                    # explicit footer if present (fast path)
                    if footers:
                        for f in footers:
                            fpos = mm.find(f, start + len(header))
                            if fpos != -1:
                                end = fpos + len(f)
                                break

                    # ZIP-specific: strict central-dir validation
                    if end is None and (header.startswith(ZIP_LOCAL) or header.startswith(b'PK')):
                        search_end = min(size, start + ZIP_MAX_SEARCH)
                        valid_end = None
                        for eocd_pos in _iter_eocd_candidates(mm, start, search_end):
                            eocd_end = _eocd_end(mm, eocd_pos)
                            if eocd_end is None:
                                continue
                            slice_len = eocd_end - start
                            if slice_len <= 0 or slice_len > ZIP_MAX_EXTRACT:
                                continue
                            validated_end = _parse_central_directory_and_validate(mm, start, eocd_pos)
                            if validated_end:
                                valid_end = validated_end
                                break
                        if valid_end:
                            end = valid_end
                        else:
                            if verbose:
                                print(f"[carve:zip-skip] no valid EOCD for PK at {start}; skipping")
                            continue

                    # JPEG heuristic
                    if end is None and header.startswith(JPEG_START):
                        jend = mm.find(JPEG_END, start + 2)
                        if jend != -1:
                            end = jend + len(JPEG_END)

                    # PNG heuristic
                    if end is None and header.startswith(bytes.fromhex('89504e47')):
                        iend = mm.find(PNG_IEND, start + 8)
                        if iend != -1:
                            end = iend + len(PNG_IEND)

                    # PDF heuristic
                    if end is None and (header.startswith(b'%PDF') or header[:4] == b'%PDF' or header.startswith(bytes.fromhex('25504446'))):
                        lastpos = -1
                        pos = mm.find(PDF_EOF, start + 4)
                        while pos != -1:
                            lastpos = pos
                            pos = mm.find(PDF_EOF, pos + 1)
                        if lastpos != -1:
                            end = lastpos + len(PDF_EOF)
                            while end < size and mm[end] in b'\x00\r\n \t':
                                end += 1

                    # fallback: next header or bounded max carve size
                    if end is None:
                        next_h = _find_next_header(mm, all_headers, start)
                        if next_h:
                            end = next_h
                        else:
                            end = min(start + MAX_CARVE_SIZE, size)

                    if end - start < min_size:
                        continue

                    if (start, end) in seen_ranges:
                        continue

                    outname = f"{sid}_{occ}.{preferred_ext}"
                    outpath = Path(outdir) / outname
                    with open(outpath, 'wb') as of:
                        of.write(mm[start:end])

                    results.append({
                        'id': sid,
                        'ext': preferred_ext,
                        'start': start,
                        'end': end,
                        'outpath': str(outpath)
                    })
                    seen_ranges.add((start, end))
                    occ += 1
                    if verbose:
                        print(f"[carve] {sid} found at {start}..{end} -> {outpath}")

        mm.close()
    return results
