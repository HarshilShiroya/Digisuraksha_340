# core/ewf_utils.py
import os
import tempfile

try:
    import pyewf
except Exception:
    pyewf = None

def is_ewf(path):
    if pyewf is None:
        return False
    try:
        return pyewf.check_file_signature(path)
    except Exception:
        return False

def open_ewf_as_raw(path):
    """
    If path is an EWF/AD1/AFF family file, dump a temporary raw image and return its path.
    If not EWF, returns the original path.
    Caller must remove returned temp file if it was created (function returns (path, is_temp) in evidence_rescue usage).
    """
    if pyewf is None:
        raise RuntimeError("pyewf not installed. Install python binding for libewf (pyewf).")

    if not is_ewf(path):
        return path

    filenames = pyewf.glob(path)
    eh = pyewf.handle()
    eh.open(filenames)
    size = eh.get_media_size()

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".raw")
    tmp_path = tmp.name

    CHUNK = 1024 * 1024
    offset = 0
    while offset < size:
        to_read = int(min(CHUNK, size - offset))
        data = eh.read(to_read)
        if not data:
            break
        tmp.write(data)
        offset += len(data)
    tmp.flush()
    tmp.close()
    eh.close()
    return tmp_path
