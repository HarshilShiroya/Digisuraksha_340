#!/usr/bin/env python3
"""
evidence_rescue.py - CLI entrypoint for carving, listing, and extracting evidence images.

This file integrates:
- EWF auto conversion (core.ewf_utils)
- FS enumeration (core.fs_parser.enumerate_filesystem)
- Signature carver (core.carver.carve_by_signatures)
- Signature loader (core.signature_loader.load_signatures)
- Reporting (core.report.generate_reports_for_image)
- Encrypted detection (core.analyze.detect_encrypted_candidates)

The generate_reports_for_image call DOES NOT require a block_size_map argument;
report will auto-derive byte_ranges from the fs entries if bytes_per_cluster exists.
"""

import argparse
import os
import shutil
from pathlib import Path

# core helpers
from core.ewf_utils import is_ewf, open_ewf_as_raw
from core.signature_loader import load_signatures
from core.carver import carve_by_signatures
from core.fs_parser import enumerate_filesystem, extract_file_by_meta
from core.analyze import detect_encrypted_candidates
from core.report import generate_reports_for_image

# optional: pytsk3 used inside fs_parser
try:
    import pytsk3  # noqa: F401
except Exception:
    pytsk3 = None

def prepare_image(path: str):
    """
    If image is EWF, convert to a temporary raw file and return (raw_path, is_temp=True).
    Otherwise return (path, False).
    """
    if is_ewf(path):
        print("[*] EWF detected, converting to raw temporary file...")
        raw = open_ewf_as_raw(path)
        return raw, True
    return path, False

def carve_command(image: str, signatures_path: str, outdir: str):
    raw, is_temp = prepare_image(image)
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)

    # 1) filesystem enumeration (metadata)
    print("[*] Enumerating filesystem (if available)...")
    fs_files = enumerate_filesystem(raw)
    print(f"[*] Found {len(fs_files)} files via FS metadata.")

    # 2) signature loading
    print("[*] Loading signatures...")
    sigs, problems = load_signatures(signatures_path)
    if problems:
        print("[!] Signature file problems detected (first 20):")
        for p in problems[:20]:
            print(" -", p)

    # 3) signature-based carving
    print("[*] Running signature carver...")
    carved_outdir = outdir_p / 'carved'
    carved_outdir.mkdir(parents=True, exist_ok=True)
    carved = carve_by_signatures(raw, sigs, outdir=str(carved_outdir))
    print(f"[*] Carving complete. {len(carved)} items carved into {carved_outdir}")

    # 4) encrypted/password detection (on carved + fs-extracted items)
    enc_report_path = outdir_p / 'encrypted_candidates.txt'
    print("[*] Detecting encrypted/password-protected candidates...")
    encrypted_candidates = detect_encrypted_candidates(carved, fs_files, str(enc_report_path))
    print(f"[*] Encrypted detection: {len(encrypted_candidates)} candidates (report: {enc_report_path})")

    # 5) attempt to extract files referenced by FS metadata (if pytsk3 available)
    extracted_count = 0
    if fs_files and pytsk3:
        print("[*] Extracting files from filesystem metadata (where possible)...")
        for fe in fs_files:
            # build a safe output path inside outdir/extracted/
            safe_rel = fe.get('path', '').lstrip('/')
            if not safe_rel:
                continue
            dest = outdir_p / 'extracted' / safe_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                extract_file_by_meta(raw, fe, str(dest))
                fe['extracted_path'] = str(dest)
                extracted_count += 1
            except Exception as e:
                # skip extraction failures but continue
                continue
        print(f"[*] Extracted {extracted_count} files via FS metadata into {outdir_p/'extracted'}")

    # 6) generate reports (auto-derives byte_ranges from bytes_per_cluster on fs_files)
    print("[*] Generating reports...")
    outputs = generate_reports_for_image(
        file_entries=fs_files,
        carved_results=carved,
        outdir=str(outdir_p),
        write_csv=True,
        include_chart=False,
        encrypted_candidates=encrypted_candidates
    )
    print("[*] Reports written:", outputs)

    # cleanup temp raw
    if is_temp:
        try:
            os.unlink(raw)
            print("[*] Removed temporary raw file.")
        except Exception:
            pass

def list_command(image: str, outdir: str):
    raw, is_temp = prepare_image(image)
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)

    fs_files = enumerate_filesystem(raw)
    print(f"[*] Found {len(fs_files)} files via FS metadata.")
    outputs = generate_reports_for_image(
        file_entries=fs_files,
        carved_results=[],
        outdir=str(outdir_p),
        write_csv=True,
        include_chart=False,
        encrypted_candidates=None
    )
    print("[*] Reports written:", outputs)
    if is_temp:
        try:
            os.unlink(raw)
        except Exception:
            pass

def extract_ext_command(image: str, exts: list, outdir: str):
    raw, is_temp = prepare_image(image)
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)

    fs_files = enumerate_filesystem(raw)
    extracted = 0
    # normalize exts
    exts = [e if e.startswith('.') else f".{e}" for e in exts]
    # attempt metadata-based extraction first
    if fs_files and pytsk3:
        for fe in fs_files:
            name = fe.get('name','')
            ext = os.path.splitext(name)[1].lower()
            if ext in exts:
                dest = outdir_p / 'extracted_ext' / fe.get('path','').lstrip('/')
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    extract_file_by_meta(raw, fe, str(dest))
                    fe['extracted_path'] = str(dest)
                    extracted += 1
                except Exception:
                    continue
    # if none extracted via metadata, run carver and filter carved outputs
    if extracted == 0:
        sigs, problems = load_signatures('signatures.json')
        carved = carve_by_signatures(raw, sigs, outdir=str(outdir_p/'carved_for_extract'))
        for c in carved:
            of = c.get('outpath','')
            if any(of.lower().endswith(ext) for ext in exts):
                # move/copy to extracted_ext output
                dest = outdir_p / 'extracted_ext' / Path(of).name
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy(of, str(dest))
                    extracted += 1
                except Exception:
                    continue

    print(f"[*] Extracted {extracted} files to {outdir_p/'extracted_ext'}")
    if is_temp:
        try:
            os.unlink(raw)
        except Exception:
            pass

def detect_encrypted_command(image: str, signatures_path: str, outdir: str):
    raw, is_temp = prepare_image(image)
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)

    # run signature carver to get files to inspect
    sigs, problems = load_signatures(signatures_path)
    carved = carve_by_signatures(raw, sigs, outdir=str(outdir_p/'tmp_carved_for_detect'))
    fs_files = enumerate_filesystem(raw)
    enc_report = outdir_p / 'encrypted_candidates.txt'
    candidates = detect_encrypted_candidates(carved, fs_files, str(enc_report))
    print(f"[*] Detected {len(candidates)} candidates - report at {enc_report}")
    if is_temp:
        try:
            os.unlink(raw)
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(prog='evidence_rescue.py')
    sub = parser.add_subparsers(dest='cmd')

    p_carve = sub.add_parser('carve', help='Convert/mount E01 if needed, enumerate FS, carve signatures, detect encrypted and generate reports')
    p_carve.add_argument('image', help='image path (raw or E01)')
    p_carve.add_argument('--signatures', default='signatures.json', help='signatures.json path')
    p_carve.add_argument('--out', default='output', help='output directory')

    p_list = sub.add_parser('list', help='List filesystem files and generate metadata manifest')
    p_list.add_argument('image', help='image path')
    p_list.add_argument('--out', default='output', help='output directory')

    p_extract = sub.add_parser('extract-ext', help='Extract files with given extension(s)')
    p_extract.add_argument('image', help='image path')
    p_extract.add_argument('ext', nargs='+', help='one or more extensions (.docx .pdf etc)')
    p_extract.add_argument('--out', default='output', help='output directory')

    p_detect = sub.add_parser('detect-encrypted', help='Detect encrypted/password-protected files')
    p_detect.add_argument('image', help='image path')
    p_detect.add_argument('--signatures', default='signatures.json', help='signatures.json path')
    p_detect.add_argument('--out', default='output', help='output directory')

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    if args.cmd == 'carve':
        carve_command(args.image, args.signatures, args.out)
    elif args.cmd == 'list':
        list_command(args.image, args.out)
    elif args.cmd == 'extract-ext':
        extract_ext_command(args.image, args.ext, args.out)
    elif args.cmd == 'detect-encrypted':
        detect_encrypted_command(args.image, args.signatures, args.out)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
