import os
from pathlib import Path

try:
    import pytsk3
except Exception:
    pytsk3 = None

def _safe_decode(name_bytes):
    try:
        return name_bytes.decode('utf-8', errors='replace')
    except Exception:
        return str(name_bytes)

def _detect_bytes_per_cluster(fs) -> int:
    """
    Try to detect bytes-per-cluster / block size from a pytsk3.FS_Info object.
    Try a few common attribute names; fallback to 4096.
    """
    candidates = [
        'block_size',       # common name
        'blocksize',        # alternative
        'info',              # some wrappers store sizes in nested objects
    ]
    # try direct attributes / properties
    for name in ['block_size', 'blocksize', 'bytes_per_sector', 'dev_bsize']:
        try:
            val = getattr(fs.info, name)
            if isinstance(val, int) and val > 0:
                return int(val)
        except Exception:
            pass
        try:
            val = getattr(fs, name)
            if isinstance(val, int) and val > 0:
                return int(val)
        except Exception:
            pass
    # fallback: try common methods / properties
    try:
        # Some environments expose 'info' object with logical_block_size or similar
        info = getattr(fs, 'info', None)
        if info:
            for cand in ('block_size','blocksize','bytes_per_cluster','fragment_size','logical_block_size'):
                try:
                    val = getattr(info, cand)
                    if isinstance(val, int) and val > 0:
                        return int(val)
                except Exception:
                    pass
    except Exception:
        pass
    # final fallback: assume 4096 (reasonable default)
    return 4096

def enumerate_filesystem(image_path):
    """
    Enumerate files using filesystem metadata via pytsk3.
    Returns list of file entries (same as previous) but each entry now includes:
      - 'bytes_per_cluster' : int (detected per FS)
    If pytsk3 is not installed returns empty list.
    """
    results = []
    if pytsk3 is None:
        return results

    img = pytsk3.Img_Info(str(image_path))
    # Determine either partitions or single fs
    offsets = [0]
    try:
        vol = pytsk3.Volume_Info(img)
        parts = [p for p in vol]
        offsets = [p.start * 512 for p in parts if p.len > 0] or [0]
    except Exception:
        offsets = [0]

    for off in offsets:
        try:
            fs = pytsk3.FS_Info(img, offset=off)
        except Exception:
            continue

        # detect bytes per cluster for this FS
        try:
            bpc = _detect_bytes_per_cluster(fs)
        except Exception:
            bpc = 4096

        root = fs.open_dir(path="/")
        def walk(directory, parent):
            for entry in directory:
                nameb = entry.info.name.name
                if not nameb:
                    continue
                name = _safe_decode(nameb)
                if name in ['.', '..']:
                    continue
                meta = entry.info.meta
                full = os.path.join(parent, name)
                if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        walk(fs.open_dir(inode=meta.addr), full)
                    except Exception:
                        continue
                else:
                    clusters = []
                    try:
                        runs = meta.get_runs()
                        for r in runs:
                            if r.addr is not None and r.len:
                                clusters.append((r.addr, r.len))
                    except Exception:
                        clusters = []
                    results.append({
                        'path': full,
                        'name': name,
                        'size': meta.size if meta else 0,
                        'mtime': meta.mtime if meta else None,
                        'meta_addr': meta.addr if meta else None,
                        'clusters': clusters,
                        'fs_offset': off,
                        'bytes_per_cluster': int(bpc)
                    })
        try:
            walk(root, '/')
        except Exception:
            pass
    return results
    
    # core/fs_parser.py (append this function at the bottom)

def extract_file_by_meta(image_path, file_entry, outdir):
    """
    Extract a file from the image based on metadata (clusters/byte_ranges).
    Args:
      image_path : path to raw image (str or Path)
      file_entry : dict from metadata manifest with either 'byte_ranges' or 'clusters'
      outdir     : directory to write recovered file
    Returns:
      path to extracted file, or None if failed
    """
    import os
    os.makedirs(outdir, exist_ok=True)
    outname = file_entry.get("name") or "unnamed.bin"
    safe_name = outname.replace("/", "_")
    outfile = os.path.join(outdir, safe_name)

    with open(image_path, "rb") as src, open(outfile, "wb") as dst:
        if file_entry.get("byte_ranges"):
            # Preferred: precise byte ranges already computed
            for r in file_entry["byte_ranges"]:
                start = int(r["start"])
                length = int(r["length"])
                src.seek(start)
                dst.write(src.read(length))
        elif file_entry.get("clusters"):
            # Fallback: compute using clusters and bytes_per_cluster
            bpc = int(file_entry.get("bytes_per_cluster", 4096))
            for addr, length in file_entry["clusters"]:
                offset = addr * bpc
                src.seek(offset)
                dst.write(src.read(length * bpc))
        else:
            # If no ranges or clusters, just skip
            return None

    return outfile

