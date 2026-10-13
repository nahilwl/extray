import re
import urllib.request

ID_RE = re.compile(r"[a-p]{32}")
URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=130.0&acceptformat=crx2,crx3&x=id%3D{id}%26uc"
)


def download(ext_id: str) -> bytes:
    """Download the latest .crx of a Chrome Web Store extension."""
    if not ID_RE.fullmatch(ext_id):
        raise ValueError(f"invalid Chrome extension ID: {ext_id}")
    # shortcut: no size cap on the response, add one if we ever scan untrusted mirrors
    with urllib.request.urlopen(URL.format(id=ext_id), timeout=30) as r:
        data = r.read()
    if not data:
        raise ValueError(f"extension {ext_id} not found on the Web Store")
    return data
