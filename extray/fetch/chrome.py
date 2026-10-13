import re
import urllib.request

ID_RE = re.compile(r"[a-p]{32}")
MAX_SIZE = 50 * 1024 * 1024
URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D{id}%26uc"
)


def download(ext_id: str, max_size: int = MAX_SIZE) -> bytes:
    """Download the latest .crx of a Chrome Web Store extension."""
    if not ID_RE.fullmatch(ext_id):
        raise ValueError(f"invalid Chrome extension ID: {ext_id}")
    with urllib.request.urlopen(URL.format(id=ext_id), timeout=30) as r:
        data = r.read(max_size + 1)  # stops reading the stream one byte past the limit
    if len(data) > max_size:
        raise ValueError(f"download of {ext_id} exceeds {max_size} bytes, aborted")
    if not data:
        raise ValueError(f"extension {ext_id} not found on the Web Store")
    return data
