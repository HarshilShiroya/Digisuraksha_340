# core/report.py
"""
Report generation module for evidence_rescue.

Provides:
- write_filesystem_tree(file_entries, out_path)
- write_metadata_manifest(...)
- write_detailed_report(file_entries, outdir)
- write_extensions_list(file_entries, outdir)
- write_carve_manifest(carved_results, out_path)
- write_encrypted_report(candidates, out_path)
- generate_reports_for_image(...) convenience wrapper
"""

from __future__ import annotations
import os
import json
import csv
from pathlib import Path
from typing import List, Dict, Optional, Any
from collections import Counter

from .repo_utils import ensure_dir, safe_write_text, human_size

def _ensure_outdir(path: Path) -> Path:
    ensure_dir(path.parent)
    return path

def _cluster_runs_to_byte_ranges(cluster_runs: List[tuple], block_size: int, fs_offset: int = 0) -> List[Dict[str,int]]:
    out = []
    for addr, length in cluster_runs:
        start_byte = fs_offset + (addr * block_size)
        byte_len = length * block_size
        out.append({'start': int(start_byte), 'length': int(byte_len), 'end': int(start_byte + byte_len)})
    return out

def _make_carved_name(sig_id: str, start: int, end: int, ext: Optional[str]) -> str:
    safe_ext = (ext.lstrip('.') if ext else 'bin')
    return f"{sig_id}_{start}-{end}.{safe_ext}"

# -------------------------
# Core functions
# -------------------------
def write_filesystem_tree(file_entries: List[Dict[str,Any]], out_path: str) -> str:
    outp = Path(out_path)
    _ensure_outdir(outp)
    lines = []
    for fe in sorted(file_entries, key=lambda x: x.get('path','')):
        path = fe.get('path')
        if not path:
            continue
        lines.append(path)
    safe_write_text(str(outp), "\n".join(lines))
    return str(outp)

def write_metadata_manifest(
    file_entries: List[Dict[str,Any]],
    out_path: str,
    *,
    block_size_map: Optional[Dict[int,int]] = None,
    write_csv: bool = False,
    include_sample_preview: bool = False,
    chart: bool = False,
    chart_sample_limit: int = 50,
    encrypted_candidates: Optional[List[Dict[str,Any]]] = None
) -> str:
    outp = Path(out_path)
    _ensure_outdir(outp)

    enc_map = {}
    if encrypted_candidates:
        for c in encrypted_candidates:
            enc_map[c.get('path')] = {'entropy': c.get('entropy'), 'reasons': c.get('reasons')}

    derived_block_size_map = {}
    if not block_size_map:
        for fe in file_entries:
            try:
                fs_off = int(fe.get('fs_offset', 0))
            except Exception:
                continue
            bpc = fe.get('bytes_per_cluster')
            if bpc:
                derived_block_size_map.setdefault(fs_off, int(bpc))
        if derived_block_size_map:
            block_size_map = derived_block_size_map
    else:
        block_size_map = {int(k): int(v) for k, v in block_size_map.items()}

    manifest = []
    for fe in file_entries:
        entry = {
            'path': fe.get('path'),
            'name': fe.get('name'),
            'size': int(fe.get('size', 0)),
            'mtime': fe.get('mtime'),
            'meta_addr': fe.get('meta_addr'),
            'clusters': fe.get('clusters', []),
            'fs_offset': fe.get('fs_offset', 0)
        }

        if block_size_map:
            try:
                bs = block_size_map.get(int(entry['fs_offset']), None)
                if bs and entry['clusters']:
                    entry['byte_ranges'] = _cluster_runs_to_byte_ranges(entry['clusters'], bs, int(entry['fs_offset']))
            except Exception:
                pass

        if include_sample_preview and fe.get('extracted_path'):
            try:
                with open(fe['extracted_path'], 'rb') as fh:
                    preview = fh.read(512)
                entry['sample_preview'] = preview.hex()
            except Exception:
                entry['sample_preview'] = None

        if entry['path'] in enc_map:
            entry['encrypted_info'] = enc_map[entry['path']]

        manifest.append(entry)

    safe_write_text(str(outp), json.dumps(manifest, indent=2))

    if write_csv:
        csv_path = str(outp) + ".csv"
        keys = ['path','name','size','mtime','meta_addr','fs_offset']
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for m in manifest:
                row = {k: m.get(k) for k in keys}
                writer.writerow(row)

    if chart:
        chart_path = str(outp) + ".chart.txt"
        lines = []
        lines.append("+------------------------------------------------------------+")
        lines.append("| Boot Sector / Partition Table (MBR/GPT)                    |")
        lines.append("+------------------------------------------------------------+")
        lines.append(f"Image manifest entries: {len(manifest)}")
        lines.append("+------------------------------------------------------------+")
        lines.append("| File System Metadata (MFT in NTFS / FAT table / Inodes)    |")
        lines.append("+------------------------------------------------------------+")
        sample = manifest[:chart_sample_limit]
        for e in sample:
            lines.append(f"|   - \"{e.get('name')}\" filename, size {e.get('size')}, timestamps {e.get('mtime')}")
            lines.append(f"|   - Points to clusters: {e.get('clusters')}")
            lines.append(f"|   - Parent folder: {os.path.dirname(e.get('path') or '')}")
            lines.append("+------------------------------------------------------------+")
        safe_write_text(chart_path, "\n".join(lines))

    return str(outp)

def write_detailed_report(file_entries: List[Dict[str,Any]], outdir: str = "reports") -> str:
    ensure_dir(Path(outdir))
    outfile = Path(outdir) / "detailed_report.txt"
    lines = []
    lines.append("+------------------------------------------------------------+")
    lines.append("| Detailed Filesystem Report                                 |")
    lines.append("+------------------------------------------------------------+")
    if not file_entries:
        lines.append("No filesystem entries detected.")
        safe_write_text(str(outfile), "\n".join(lines))
        return str(outfile)

    for fe in file_entries:
        lines.append(f"Path: {fe.get('path','?')}")
        lines.append(f"  Name: {fe.get('name','?')}")
        lines.append(f"  Size: {fe.get('size',0)}")
        lines.append(f"  MTime: {fe.get('mtime','?')}")
        lines.append(f"  Inode/Meta Addr: {fe.get('meta_addr','N/A')}")
        lines.append(f"  Parent FS Offset: {fe.get('fs_offset',0)}")
        clusters = fe.get('clusters', [])
        if clusters:
            lines.append("  Clusters:")
            for addr, length in clusters[:20]:
                lines.append(f"    - Start: {addr} Len: {length}")
        else:
            lines.append("  Clusters: None")
        if fe.get('byte_ranges'):
            lines.append("  Byte Ranges:")
            for br in fe.get('byte_ranges')[:20]:
                lines.append(f"    - Start: {br.get('start')} Len: {br.get('length')}")
        lines.append("")
    safe_write_text(str(outfile), "\n".join(lines))
    return str(outfile)

def write_extensions_list(file_entries: List[Dict[str,Any]], outdir: str = "reports") -> str:
    ensure_dir(Path(outdir))
    outfile = Path(outdir) / "extensions_list.txt"
    exts = []
    for fe in file_entries:
        name = fe.get('name','')
        if '.' in name:
            ext = name.split('.')[-1].lower()
            exts.append(ext)
        else:
            exts.append('(noext)')
    counter = Counter(exts)
    lines = ["File Extensions Summary", "=======================", ""]
    for ext, cnt in counter.most_common():
        display_ext = f".{ext}" if ext != '(noext)' else "(no extension)"
        lines.append(f"{display_ext}\t{cnt}")
    safe_write_text(str(outfile), "\n".join(lines))
    print(f"[Extensions] {len(counter)} unique extensions, {sum(counter.values())} total files")
    return str(outfile)

def write_carve_manifest(
    carved_results: List[Dict[str,Any]],
    out_path: str,
    *,
    write_csv: bool = False,
    include_entropy_map: Optional[Dict[str,Any]] = None
) -> str:
    outp = Path(out_path)
    _ensure_outdir(outp)
    manifest = []
    for c in carved_results:
        sigid = c.get('id')
        ext = (c.get('ext') or '').lstrip('.')
        start = int(c.get('start', 0))
        end = int(c.get('end', 0))
        outpath = c.get('outpath')
        if not outpath:
            name = _make_carved_name(sigid, start, end, ext or None)
            outpath = str(outp.parent / 'carved' / name)
        entry = {
            'signature_id': sigid,
            'start': start,
            'end': end,
            'size': end - start,
            'ext': ext or 'bin',
            'outpath': outpath
        }
        if include_entropy_map and outpath in include_entropy_map:
            entry['encrypted_info'] = include_entropy_map[outpath]
        manifest.append(entry)
    safe_write_text(str(outp), json.dumps(manifest, indent=2))
    if write_csv:
        csv_path = str(outp) + ".csv"
        keys = ['signature_id','start','end','size','ext','outpath']
        with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            for m in manifest:
                w.writerow({k: m.get(k) for k in keys})
    return str(outp)

def write_encrypted_report(candidates: List[Dict[str,Any]], out_path: str) -> str:
    ensure_dir(Path(out_path).parent)
    outp = Path(out_path)
    lines = []
    for c in candidates:
        path = c.get('path')
        ent = c.get('entropy')
        reasons = c.get('reasons') or c.get('reason') or []
        lines.append(f"{path}\t{ent}\t{';'.join(reasons)}")
    safe_write_text(str(outp), "\n".join(lines))
    return str(outp)

def generate_reports_for_image(
    file_entries: List[Dict[str,Any]],
    carved_results: List[Dict[str,Any]],
    outdir: str,
    *,
    block_size_map: Optional[Dict[int,int]] = None,
    write_csv: bool = False,
    include_chart: bool = False,
    encrypted_candidates: Optional[List[Dict[str,Any]]] = None
) -> Dict[str,str]:
    outdir_p = Path(outdir)
    ensure_dir(outdir_p)
    outputs = {}
    tree_path = str(outdir_p / "filesystem_tree.txt")
    write_filesystem_tree(file_entries, tree_path)
    outputs['filesystem_tree'] = tree_path

    manifest_path = str(outdir_p / "metadata_manifest.json")
    write_metadata_manifest(
        file_entries,
        manifest_path,
        block_size_map=block_size_map,
        write_csv=write_csv,
        chart=include_chart,
        encrypted_candidates=encrypted_candidates
    )
    outputs['metadata_manifest'] = manifest_path
    if write_csv:
        outputs['metadata_manifest_csv'] = manifest_path + ".csv"
    if include_chart:
        outputs['chart'] = manifest_path + ".chart.txt"

    if file_entries:
        detailed_path = str(outdir_p / "detailed_report.txt")
        write_detailed_report(file_entries, str(outdir_p))
        outputs['detailed_report'] = detailed_path

    if file_entries:
        ext_path = str(outdir_p / "extensions_list.txt")
        write_extensions_list(file_entries, str(outdir_p))
        outputs['extensions_list'] = ext_path

    if carved_results:
        carve_path = str(outdir_p / "carve_manifest.json")
        entropy_map = {}
        if encrypted_candidates:
            for c in encrypted_candidates:
                entropy_map[c.get('path')] = {'entropy': c.get('entropy'), 'reasons': c.get('reasons')}
        write_carve_manifest(carved_results, carve_path, write_csv=write_csv, include_entropy_map=entropy_map)
        outputs['carve_manifest'] = carve_path
        if write_csv:
            outputs['carve_manifest_csv'] = carve_path + ".csv"

    if encrypted_candidates:
        enc_path = str(outdir_p / "encrypted_candidates.txt")
        write_encrypted_report(encrypted_candidates, enc_path)
        outputs['encrypted_candidates'] = enc_path

    return outputs
