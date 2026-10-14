import os
import signal
import time

from extray import scan as scan_module
from extray.js.parser import JSFile
from extray.scan import scan

FILES = {"manifest.json": b'{"manifest_version": 3}', "a.js": b"eval(x);", "crash.js": b"", "hang.js": b"",
         "raise.js": b"", "z.js": b"eval(y);"}


def broken_parser(name, source):
    # workers are forked, so they see this patch
    if name == "crash.js":
        os.kill(os.getpid(), signal.SIGSEGV)
    if name == "hang.js":
        time.sleep(60)
    if name == "raise.js":
        raise RecursionError("too deep")
    return JSFile(name, source)


def not_analyzed(findings):
    assert all(f.severity == "info" for f in findings if f.rule == "js.not-analyzed")
    return {(f.file, f.message) for f in findings if f.rule == "js.not-analyzed"}


def test_scan_survives_parser_crash_and_error(monkeypatch):
    monkeypatch.setattr(scan_module, "JSFile", broken_parser)
    files = {k: v for k, v in FILES.items() if k != "hang.js"}
    findings = scan(files)  # the default timeout: a crash dump (apport, systemd-coredump) can take a second
    assert not_analyzed(findings) == {("crash.js", "not analyzed: parser crashed (SIGSEGV)"),
                                      ("raise.js", "not analyzed: RecursionError: too deep")}
    assert {f.file for f in findings if f.rule == "js.code-exec"} == {"a.js", "z.js"}  # the others are analyzed


def test_scan_survives_parser_hang(monkeypatch):
    monkeypatch.setattr(scan_module, "JSFile", broken_parser)
    start = time.monotonic()
    findings = scan({k: v for k, v in FILES.items() if k not in ("crash.js", "raise.js")}, js_timeout=0.5)
    assert time.monotonic() - start < 5
    assert not_analyzed(findings) == {("hang.js", "not analyzed: timeout after 0.5s")}
    assert {f.file for f in findings if f.rule == "js.code-exec"} == {"a.js", "z.js"}
