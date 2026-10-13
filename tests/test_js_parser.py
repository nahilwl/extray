import zipfile

from typer.testing import CliRunner

from extray.cli import app
from extray.js.parser import JSFile, snippet
from extray.scan import scan

MANIFEST = b'{"name": "t", "version": "1", "manifest_version": 3}'


def test_position_is_in_the_original_file_and_counts_characters():
    # minified, multi-line, with a non-ASCII character before the target on the same line
    js = JSFile("a.js", 'var a=1;\nvar b="é";foo(b)'.encode())
    call = js.nodes("call_expression")[0]
    assert js.position(call) == (2, 11)  # byte offset would give 12: "é" is 2 bytes


def test_nodes_are_in_source_order():
    js = JSFile("a.js", b"a();b(c());d()")
    assert [n.child_by_field_name("function").text for n in js.nodes("call_expression")] == [b"a", b"b", b"c", b"d"]


def test_snippet_is_beautified_and_truncated():
    assert snippet("function f(){a();b()}") == "function f() {\n    a();\n    b()\n}"
    assert snippet(";".join(f"a{i}()" for i in range(20))).splitlines()[-1] == "..."


def test_big_js_files_are_skipped_with_an_info_finding():
    findings = scan({"manifest.json": MANIFEST, "big.js": b"x" * 11, "small.js": b"x"}, max_js_size=10)
    assert [(f.rule, f.severity, f.file) for f in findings] == [("js.too-large", "info", "big.js")]


def test_missing_manifest_is_a_clean_error(tmp_path):
    path = tmp_path / "ext.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("background.js", "1")
    result = CliRunner().invoke(app, ["scan", str(path)])
    assert result.exit_code == 1 and "no manifest.json" in result.output


def test_cli_max_js_size_option(tmp_path):
    path = tmp_path / "ext.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("manifest.json", MANIFEST)
        z.writestr("big.js", "x" * 11)
    result = CliRunner().invoke(app, ["scan", str(path), "--max-js-size", "10"], env={"COLUMNS": "200"})
    assert result.exit_code == 0 and "js.too-large" in result.output
