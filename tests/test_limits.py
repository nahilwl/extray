import io
import zipfile

import pytest
from typer.testing import CliRunner

from extray.cli import app
from extray.fetch import chrome
from extray.unpack import extract, load, read_dir

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


def _patch_headers(data, offsets):
    """Patch the same field in the local header and the central directory of a one-file zip."""
    data = bytearray(data)
    (local_off, cd_off), value = offsets
    cd = data.rfind(b"PK\x01\x02")
    data[local_off : local_off + 2] = value
    data[cd + cd_off : cd + cd_off + 2] = value
    return bytes(data)


def encrypted_zip():
    return _patch_headers(make_zip({"a.js": b"1"}), ((6, 8), (1).to_bytes(2, "little")))  # flag bit 0


def unknown_method_zip():
    return _patch_headers(make_zip({"a.js": b"1"}), ((8, 10), (77).to_bytes(2, "little")))  # compression method


def corrupt_zip(method):
    """One-file zip whose compressed stream is overwritten with 0xFF just past the codec header."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        z.writestr("a.js", b"console.log(1);\n" * 200)
    data = bytearray(buf.getvalue())
    start = 30 + int.from_bytes(data[26:28], "little") + int.from_bytes(data[28:30], "little")
    skip = 13 if method == zipfile.ZIP_LZMA else 4  # lzma: version + props size + props, bzip2: "BZh9"
    data[start + skip : start + 30] = b"\xff" * (30 - skip)
    return bytes(data)


def test_corrupt_lzma_stream():
    with pytest.raises(ValueError, match="cannot extract a.js: Corrupt input data"):
        extract(corrupt_zip(zipfile.ZIP_LZMA))


def test_encrypted_zip():
    with pytest.raises(ValueError, match="cannot extract a.js: .*encrypted"):
        extract(encrypted_zip())


def test_unknown_compression_method():
    with pytest.raises(ValueError, match="cannot extract a.js: .*compression method"):
        extract(unknown_method_zip())


@pytest.mark.parametrize("data, message", [
    (encrypted_zip(), "encrypted"),
    (unknown_method_zip(), "compression method"),
    (corrupt_zip(zipfile.ZIP_LZMA), "cannot extract a.js: Corrupt input data"),
    (corrupt_zip(zipfile.ZIP_BZIP2), "Invalid data stream"),
    (b"PK not a zip", "error:"),
    (make_zip({"bomb.js": b"\0" * (4 * 1024 * 1024)}), "zip bomb"),
])
def test_cli_reports_extraction_errors_cleanly(tmp_path, data, message):
    path = tmp_path / "ext.zip"
    path.write_bytes(data)
    result = CliRunner().invoke(app, ["scan", str(path)])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)  # no uncaught exception, so no traceback
    assert result.output.startswith("error: ") and message in result.output


def make_dir(root, files):
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


def test_load_folder(tmp_path):
    files = {"manifest.json": b"{}", "js/a.js": b"1"}
    assert load(str(make_dir(tmp_path, files))) == files


def test_folder_limits(tmp_path):
    make_dir(tmp_path, {"a.js": b"x" * 600, "b.js": b"y" * 600})
    with pytest.raises(ValueError, match="limit is 1"):
        read_dir(str(tmp_path), max_files=1)
    with pytest.raises(ValueError, match="more than 1000 bytes"):
        read_dir(str(tmp_path), max_total=1000)


@pytest.mark.parametrize("link", ["file", "folder"])
def test_folder_refuses_symlinks(tmp_path, link):
    outside = make_dir(tmp_path / "outside", {"secret": b"key"})
    ext = make_dir(tmp_path / "ext", {"manifest.json": b"{}"})
    (ext / "x").symlink_to(outside / "secret" if link == "file" else outside)
    with pytest.raises(ValueError, match="x: symbolic links are not supported"):
        read_dir(str(ext))


def test_cli_scans_a_folder(tmp_path):
    make_dir(tmp_path, {"manifest.json": b'{"name": "Folder ext", "manifest_version": 3}', "a.js": b"eval(x);"})
    result = CliRunner().invoke(app, ["scan", str(tmp_path)], env={"COLUMNS": "200"})
    assert result.exit_code == 0 and "Folder ext" in result.output and "js.code-exec" in result.output
