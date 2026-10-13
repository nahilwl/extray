import struct
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from extray import manifest
from extray.cli import app
from extray.fetch.crx import crx_to_zip

FIXTURES = Path(__file__).parent / "fixtures"
ALL_RULES = {
    "manifest.mv2",
    "manifest.dangerous-permission",
    "manifest.all-hosts",
    "manifest.externally-connectable",
    "manifest.web-accessible-html",
    "manifest.csp-unsafe-eval",
    "manifest.csp-remote-script",
    "manifest.content-script-all-urls",
}


def read(name):
    return (FIXTURES / name / "manifest.json").read_text()


def test_vulnerable_manifest_triggers_every_rule():
    findings = manifest.analyze(read("manifest_vuln"))
    assert {f.rule for f in findings} == ALL_RULES
    remote = next(f for f in findings if f.rule == "manifest.csp-remote-script")
    assert remote.line == 14 and "cdn.example.com" in remote.evidence
    cs = next(f for f in findings if f.rule == "manifest.content-script-all-urls")
    assert cs.severity == "medium" and "document_start" in cs.message


def test_clean_manifest_has_no_findings():
    assert manifest.analyze(read("manifest_clean")) == []


def _crx(zip_bytes):
    header = b"fake-protobuf-header"
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


def test_crx3_header_is_stripped():
    assert crx_to_zip(_crx(b"PK-zip")) == b"PK-zip"


def test_scan_crx_end_to_end(tmp_path):
    zpath = tmp_path / "ext.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.write(FIXTURES / "manifest_vuln" / "manifest.json", "manifest.json")
    crx = tmp_path / "ext.crx"
    crx.write_bytes(_crx(zpath.read_bytes()))
    for target in (zpath, crx):
        result = CliRunner().invoke(app, ["scan", str(target)], env={"COLUMNS": "200"})
        assert result.exit_code == 0, result.output
        assert "manifest.all-hosts" in result.output


def test_scan_rejects_garbage():
    result = CliRunner().invoke(app, ["scan", "not-an-id"])
    assert result.exit_code == 1
