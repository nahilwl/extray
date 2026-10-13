import io
import zipfile

import pytest

from extray.fetch import chrome
from extray.unpack import extract

EXT_ID = "a" * 32


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def fake_urlopen(body):
    return lambda url, timeout: io.BytesIO(body)


def test_download_under_limit(monkeypatch):
    monkeypatch.setattr(chrome.urllib.request, "urlopen", fake_urlopen(b"x" * 100))
    assert chrome.download(EXT_ID, max_size=100) == b"x" * 100


def test_download_over_limit_is_aborted(monkeypatch):
    monkeypatch.setattr(chrome.urllib.request, "urlopen", fake_urlopen(b"x" * 101))
    with pytest.raises(ValueError, match="exceeds 100 bytes"):
        chrome.download(EXT_ID, max_size=100)


def test_extract_returns_files():
    assert extract(make_zip({"manifest.json": b"{}", "a/b.js": b"1"})) == {"manifest.json": b"{}", "a/b.js": b"1"}


def test_too_many_files():
    with pytest.raises(ValueError, match="limit is 2"):
        extract(make_zip({f"{i}.js": b"" for i in range(3)}), max_files=2)


def test_total_decompressed_size():
    data = make_zip({"a.js": b"x" * 600, "b.js": b"y" * 600})
    with pytest.raises(ValueError, match="more than 1000 bytes"):
        extract(data, max_total=1000)


def test_zip_bomb_ratio():
    with pytest.raises(ValueError, match="possible zip bomb"):
        extract(make_zip({"bomb.js": b"\0" * (4 * 1024 * 1024)}))


def test_lying_header_is_rejected():
    # header announces a tiny file, real content is bigger: zipfile stops at the announced size and fails the CRC
    data = bytearray(make_zip({"a.js": b"x" * 5000}))
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24 : cd + 28] = (10).to_bytes(4, "little")  # central directory uncompressed size
    with pytest.raises(zipfile.BadZipFile, match="CRC"):
        extract(bytes(data))
