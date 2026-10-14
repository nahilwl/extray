import io
import lzma
import os
import zipfile
import zlib
from pathlib import Path

from extray.fetch import chrome
from extray.fetch.crx import MAGIC, crx_to_zip

MB = 1024 * 1024
MAX_TOTAL = 200 * MB
MAX_FILES = 5000
MAX_RATIO = 100
RATIO_MIN_SIZE = MB  # tiny files of whitespace legitimately compress >100x, only big ones can be bombs


def extract(data: bytes, max_total=MAX_TOTAL, max_files=MAX_FILES, max_ratio=MAX_RATIO) -> dict[str, bytes]:
    """Decompress a zip in memory, counting real decompressed bytes (zip headers can lie)."""
    z = zipfile.ZipFile(io.BytesIO(data))
    infos = [i for i in z.infolist() if not i.is_dir()]
    if len(infos) > max_files:
        raise ValueError(f"zip has {len(infos)} files, limit is {max_files}")
    files, total = {}, 0
    for info in infos:
        chunks, size = [], 0
        try:
            with z.open(info) as f:
                while chunk := f.read(64 * 1024):
                    size += len(chunk)
                    total += len(chunk)
                    if total > max_total:
                        raise ValueError(f"zip decompresses to more than {max_total} bytes, aborted")
                    if size > RATIO_MIN_SIZE and size > max_ratio * max(info.compress_size, 1):
                        raise ValueError(f"{info.filename}: compression ratio above {max_ratio}, possible zip bomb")
                    chunks.append(chunk)
        # zipfile raises these for encrypted entries, unsupported methods and corrupt streams
        except (RuntimeError, NotImplementedError, zlib.error, lzma.LZMAError, EOFError) as e:
            reason = "file is encrypted (password protected)" if info.flag_bits & 1 else e
            raise ValueError(f"cannot extract {info.filename}: {reason}") from e
        files[info.filename] = b"".join(chunks)
    return files


def read_dir(root: str, max_total=MAX_TOTAL, max_files=MAX_FILES) -> dict[str, bytes]:
    """Read an unpacked extension with the same limits as a zip. Symlinks and special files are refused:
    a link could pull files from outside the folder into the report, a FIFO would block the read."""
    files, total = {}, 0
    for dirpath, dirnames, filenames in os.walk(root):  # does not descend into symlinked folders
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            rel = Path(os.path.relpath(path, root)).as_posix()
            if os.path.islink(path):
                raise ValueError(f"{rel}: symbolic links are not supported")
            if name in dirnames:
                continue
            if not os.path.isfile(path):
                raise ValueError(f"{rel}: not a regular file")
            if len(files) == max_files:
                raise ValueError(f"folder has more than {max_files} files, limit is {max_files}")
            total += os.path.getsize(path)
            if total > max_total:
                raise ValueError(f"folder holds more than {max_total} bytes, aborted")
            files[rel] = Path(path).read_bytes()
    return files


def load(target: str) -> dict[str, bytes]:
    """Return the files of an unpacked extension folder, a local .crx/.zip or a Web Store ID, in memory
    (nothing is written to disk)."""
    path = Path(target)
    if path.is_dir():
        return read_dir(target)
    if path.is_file():
        data = path.read_bytes()
    elif chrome.ID_RE.fullmatch(target):
        data = chrome.download(target)
    else:
        raise ValueError(f"{target}: not a file, a folder nor a Chrome extension ID")
    if data[:4] == MAGIC:
        data = crx_to_zip(data)
    return extract(data)
