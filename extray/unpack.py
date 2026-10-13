import io
import zipfile
from pathlib import Path

from extray.fetch import chrome
from extray.fetch.crx import MAGIC, crx_to_zip


def load(target: str) -> zipfile.ZipFile:
    """Open a local .crx/.zip or a Web Store ID as an in-memory zip (nothing is written to disk)."""
    path = Path(target)
    if path.is_file():
        data = path.read_bytes()
    elif chrome.ID_RE.fullmatch(target):
        data = chrome.download(target)
    else:
        raise ValueError(f"{target}: not a file nor a Chrome extension ID")
    if data[:4] == MAGIC:
        data = crx_to_zip(data)
    return zipfile.ZipFile(io.BytesIO(data))
