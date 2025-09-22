#!/usr/bin/env python3
"""
detect_and_list_fs.py

Scan a raw image for FAT boot sectors, validate BPB fields, and try to open FAT
filesystems with pytsk3. If a filesystem is found, produce:
  - outdir/filesystem_tree.txt
  - outdir/metadata_manifest.json

Usage:
  python3 detect_and_list_fs.py image.dd out_dir

Notes:
 - Requires pytsk3 installed in active Python environment.
 - Scans in 512-byte steps by default; you can increase step/limits in constants below.
"""
import os, sys, json, datetime, argparse
from pathlib import Path

# Optional dependency
try:
    import pytsk3
except Exception as e:
    print("pytsk3 import error:", e)
    print("Activate venv or install pytsk3. Aborting.")
    sys.exit(1)

SECTOR_SIZES_TO_TRY = [512]    # keep default small; can add 4096 if needed
MAX_SEARCH_BYTES = 200 * 1024 * 1024  # limit search to first X bytes (200MB) by default
BOOT_SIG_OFFSET = 510  # 0x1FE
BPB_MIN_LEN = 36

def fmt_time(ts):
    try:
        return datetime.datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
    except Exception:
        return None

def read_at(fh, offset, size):
    fh.seek(offset)
    return fh.read(size)

def plausibility_checks_bpb(bpb):
    # Expects at least 36 bytes of BPB (standard)
    # offsets are relative to start of boot sector:
    # bytes_per_sector (11-12), sectors_per_cluster (13),
    # reserved_sectors (14-15), num_fats (16), root_entries (17-18),
    # total_sectors_short (19-20), media (21), fat_size_16 (22-23)
    if len(bpb) < 36:
        return False, "too_short"
    try:
        bytes_per_sector = int.from_bytes(bpb[11:13], 'little')
        sectors_per_cluster = bpb[13]
        reserved_sectors = int.from_bytes(bpb[14:16], 'little')
        num_fats = bpb[16]
        root_entries = int.from_bytes(bpb[17:19], 'little')
        total_sectors_short = int.from_bytes(bpb[19:21], 'little')
        fat_size_16 = int.from_bytes(bpb[22:24], 'little')
    except Exception as e:
        return False, f"bpb_parse_error:{e}"

    # Basic plausibility rules
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return False, f"bad_bytes_per_sector:{bytes_per_sector}"
    if sectors_per_cluster == 0 or sectors_per_cluster > 128:
        return False, f"bad_sectors_per_cluster:{sectors_per_cluster}"
    if num_fats not in (1,2,3,4):
        return False, f"bad_num_fats:{num_fats}"
    # reserved sectors typically >0
    if reserved_sectors <= 0 or reserved_sectors > 65536:
        return False, f"bad_reserved:{reserved_sectors}"
    # root entries reasonable (for FAT12/16) or zero for FAT32
    if root_entries > 65536:
        return False, f"bad_root_entries:{root_entries}"

    return True, {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "reserved_sectors": reserved_sectors,
        "num_fats": num_fats,
        "root_entries": root_entries,
        "total_sectors_short": total_sectors_short,
        "fat_size_16": fat_size_16
    }

def try_open_fs(img_info, offset):
    try:
        fs = pytsk3.FS_Info(img_info, offset=offset)
        # root probe
        _ = fs.open_dir(path="/")
        return fs
    except Exception as e:
        return None

def walk_dir(fs, directory, parent_path, results, tree_lines, depth=0):
    for entry in directory:
        try:
            name = entry.info.name.name.decode('utf-8', errors='ignore')
        except Exception:
            continue
        if name in [".", ".."]:
            continue
        meta = entry.info.meta
        path = parent_path.rstrip("/") + "/" + name if parent_path != "/" else "/" + name
        if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            tree_lines.append("  " * depth + f"{name}/")
            results.append({
                "name": name,
                "path": path,
                "size": None,
                "mtime": fmt_time(meta.mtime) if meta and hasattr(meta, 'mtime') else None,
                "inode": int(meta.addr) if meta and hasattr(meta, 'addr') else None,
                "type": "dir"
            })
            try:
                subdir = fs.open_dir(inode=meta.addr)
                walk_dir(fs, subdir, path, results, tree_lines, depth+1)
            except Exception:
                continue
        else:
            size = int(meta.size) if meta and hasattr(meta, "size") else None
            mtime = fmt_time(meta.mtime) if meta and hasattr(meta, "mtime") else None
            tree_lines.append("  " * depth + f"{name}    ({size} bytes)    {mtime}")
            results.append({
                "name": name,
                "path": path,
                "size": size,
                "mtime": mtime,
                "inode": int(meta.addr) if meta and hasattr(meta, 'addr') else None,
                "type": "file"
            })

def main():
    ap = argparse.ArgumentParser(description="Detect FAT boot sectors and list filesystem tree")
    ap.add_argument("image", help="raw image file (.dd)")
    ap.add_argument("outdir", help="output directory")
    ap.add_argument("--max-bytes", type=int, default=MAX_SEARCH_BYTES, help="max bytes to scan from start")
    ap.add_argument("--step", type=int, default=512, help="scan step in bytes (default 512)")
    args = ap.parse_args()

    image_path = Path(args.image)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    size = image_path.stat().st_size
    max_scan = min(size, args.max_bytes)
    step = args.step

    print(f"Image size: {size} bytes; scanning first {max_scan} bytes step {step}")

    img = pytsk3.Img_Info(str(image_path))

    candidates = []
    with open(image_path, "rb") as fh:
        offset = 0
        while offset < max_scan:
            # read boot-sector sized region
            try:
                block = read_at(fh, offset, 512)
            except Exception:
                break
            if len(block) < 512:
                break
            # check signature 0x55AA at offset+510
            if block[BOOT_SIG_OFFSET:BOOT_SIG_OFFSET+2] == b'\x55\xAA':
                ok, info = plausibility_checks_bpb(block)
                if ok:
                    # note candidate and try to open FS via pytsk3
                    print(f"[candidate] boot signature at offset {offset}; BPB plausible {info}")
                    fs = try_open_fs(img, offset)
                    if fs:
                        print(f"[success] opened filesystem at offset {offset}")
                        # enumerate
                        tree_lines = []
                        results = []
                        try:
                            root = fs.open_dir(path="/")
                            tree_lines.append(f"Filesystem tree for image: {image_path}")
                            tree_lines.append(f"Detected FAT-like FS at offset {offset}")
                            tree_lines.append("")
                            walk_dir(fs, root, "/", results, tree_lines, depth=0)
                        except Exception as e:
                            print("error enumerating root:", e)
                            tree_lines = ["Enumeration failed: " + str(e)]
                            results = []

                        tree_path = outdir / f"filesystem_tree_offset_{offset}.txt"
                        manifest_path = outdir / f"metadata_manifest_offset_{offset}.json"
                        tree_path.write_text("\n".join(tree_lines), encoding="utf-8")
                        manifest_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
                        print("Wrote:", tree_path, manifest_path)
                        return 0
                    else:
                        print(f"[fail] pytsk3 couldn't open FS at offset {offset}")
                        candidates.append(offset)
            offset += step

    # If we get here no FS opened
    print("No usable FAT filesystem detected by scanning boot sectors.")
    if candidates:
        print("Boot-signature candidates found (but could not be opened):", candidates[:20])
    else:
        print("No 0x55AA boot signatures found in scanned range.")
    print("Try: run 'mmls <image>' (sleuthkit) to inspect partition table; or increase scan range/step.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
