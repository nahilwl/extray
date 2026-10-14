import multiprocessing
import os
import signal
import time
from functools import cache
from multiprocessing.connection import wait

from extray.context import contexts, imported_files
from extray.js.parser import JSFile
from extray.manifest import Manifest
from extray.rules import load_rules
from extray.rules.base import Finding

MAX_JS_SIZE = 5 * 1024 * 1024
JS_TIMEOUT = 30.0
JS_EXTENSIONS = (".js", ".mjs", ".cjs")
# fork starts workers in milliseconds; spawn where fork does not exist (Windows)
_MP = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")


@cache
def _rules():
    return load_rules()


def _imports_of(name: str, source: bytes) -> list[str]:
    return imported_files(JSFile(name, source))


def _check(name: str, source: bytes, ctxs, mf: Manifest) -> list[Finding]:
    # parsed again: tree-sitter trees cannot be sent between processes
    js = JSFile(name, source)
    js.contexts, js.manifest = ctxs, mf
    return [f for rule in _rules() for f in rule.check_js(js)]


def _serve(conn):
    if hasattr(os, "fork"):
        import resource  # POSIX only
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # a crash on hostile JS needs no core dump, and dumping takes seconds
    while True:
        try:
            fn, args = conn.recv()
        except EOFError:
            return
        try:
            result = (True, fn(*args))
        except Exception as e:
            result = (False, f"{type(e).__name__}: {e}")
        conn.send(result)


class _Pool:
    """Worker processes running one task at a time, so a crash or a hang only loses that task.

    Workers are reused across run() calls; a dead or killed one is replaced on demand.
    """

    def __init__(self, size: int, timeout: float):
        self.size, self.timeout, self.idle = size, timeout, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for proc, conn in self.idle:
            proc.terminate()  # closing conn is not enough: forked siblings hold a copy of it
            proc.join()
            conn.close()

    def _start(self):
        parent, child = _MP.Pipe()
        proc = _MP.Process(target=_serve, args=(child,), daemon=True)
        proc.start()
        child.close()
        return proc, parent

    def run(self, fn, tasks: dict) -> dict:
        """{key: args} -> {key: (True, fn(*args)) or (False, why it failed)}."""
        pending, busy, results = list(tasks.items()), {}, {}
        while pending or busy:
            while pending and len(busy) < self.size:
                proc, conn = self.idle.pop() if self.idle else self._start()
                key, args = pending.pop()
                conn.send((fn, args))
                busy[conn] = (key, proc, time.monotonic() + self.timeout)
            for conn in wait(list(busy), max(0, min(d for _, _, d in busy.values()) - time.monotonic())):
                key, proc, _ = busy.pop(conn)
                try:
                    results[key] = conn.recv()
                    self.idle.append((proc, conn))
                except (EOFError, OSError):
                    proc.join()
                    code = proc.exitcode
                    results[key] = (False, f"parser crashed ({signal.Signals(-code).name if code < 0 else f'exit code {code}'})")
            now = time.monotonic()
            for conn, (key, proc, deadline) in list(busy.items()):
                if deadline <= now:
                    proc.kill()
                    proc.join()
                    del busy[conn]
                    results[key] = (False, f"timeout after {self.timeout:g}s")
        return results


def scan(files: dict[str, bytes], max_js_size: int = MAX_JS_SIZE, js_timeout: float = JS_TIMEOUT) -> list[Finding]:
    """Run every rule on the manifest and on each JS file of the extension.

    JS files are parsed and checked in worker processes: a file that crashes the parser or takes more
    than js_timeout seconds is reported as an info finding instead of stopping the scan.
    """
    if "manifest.json" not in files:
        raise ValueError("no manifest.json at the root of the archive")
    mf = Manifest.from_text(files["manifest.json"].decode("utf-8-sig"))
    findings = [f for rule in _rules() for f in rule.check_manifest(mf)]
    js = []
    for name in sorted(files):
        if not name.endswith(JS_EXTENSIONS):
            continue
        size = len(files[name])
        if size > max_js_size:
            findings.append(Finding("js.too-large", "info", f"not analyzed: {size} bytes, limit is {max_js_size}",
                                    name, 1, ""))
        else:
            js.append(name)

    failed = {}
    with _Pool(os.cpu_count() or 1, js_timeout) as pool:
        imports = {}
        for name, (ok, value) in pool.run(_imports_of, {n: (n, files[n]) for n in js}).items():
            (imports if ok else failed)[name] = value
        ctxs = contexts(mf, files, imports)
        checked = pool.run(_check, {n: (n, files[n], ctxs[n], mf) for n in imports})
    for name in js:
        ok, value = checked.get(name, (False, failed.get(name)))
        if ok:
            findings += value
        else:
            findings.append(Finding("js.not-analyzed", "info", f"not analyzed: {value}", name, 1, ""))
    return findings
