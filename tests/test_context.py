import json

from extray.context import Context, contexts, imported_files
from extray.js.parser import JSFile
from extray.manifest import Manifest
from extray.scan import scan

MANIFEST = {
    "manifest_version": 3,
    "content_scripts": [
        {"matches": ["<all_urls>"], "js": ["cs/main.js", "/shared.js"]},
        {"matches": ["https://mail.example.com/*"], "js": ["cs/mail.js"]},
    ],
    "background": {"service_worker": "bg.js", "type": "module"},
    "action": {"default_popup": "popup.html"},
    "web_accessible_resources": [
        {"resources": ["pages/frame.html"], "matches": ["<all_urls>"]},
        {"resources": ["pages/dyn-*.html"], "matches": ["<all_urls>"], "use_dynamic_url": True},
    ],
}
FILES = {
    "manifest.json": json.dumps(MANIFEST).encode(),
    "cs/main.js": b"",
    "cs/mail.js": b"",
    "shared.js": b"",
    "bg.js": b'import { x } from "./lib/util.js"; import "lodash"; export * from "./lib/reexport.js";',
    "lib/util.js": b'const m = import("./deep.js");',
    "lib/deep.js": b"",
    "lib/reexport.js": b"",
    "legacy-sw.js": b'importScripts("vendor/old.js");',
    "vendor/old.js": b"",
    "popup.html": b'<html><script src="shared.js"></script><script src="/popup.js?v=2"></script>'
                  b'<script src="https://cdn.example.com/x.js"></script></html>',
    "popup.js": b"",
    "pages/frame.html": b'<script src="../frame.js"></script>',
    "frame.js": b"",
    "pages/dyn-a.html": b'<script src="dyn.js"></script>',
    "pages/dyn.js": b"",
    "orphan.js": b"",
}


def run(files=FILES):
    mf = Manifest.from_text(files["manifest.json"].decode())
    imports = {n: imported_files(JSFile(n, d)) for n, d in files.items() if n.endswith(".js")}
    return contexts(mf, files, imports)


def kinds(result, name):
    return sorted(c.kind for c in result[name])


def test_contexts_from_manifest_html_and_imports():
    r = run()
    assert r["cs/main.js"] == {Context("content_script", ("<all_urls>",))}
    assert r["cs/main.js"].pop().all_sites
    assert r["cs/mail.js"] == {Context("content_script", ("https://mail.example.com/*",))}
    assert kinds(r, "shared.js") == ["content_script", "extension_page"]  # several contexts
    assert kinds(r, "popup.js") == ["extension_page"]
    for name in ("bg.js", "lib/util.js", "lib/deep.js", "lib/reexport.js"):  # static, dynamic and re-exports
        assert kinds(r, name) == ["background"], name
    assert r["frame.js"] == {Context("web_accessible_page", ("<all_urls>",), "pages/frame.html")}
    assert r["pages/dyn.js"].pop().dynamic_url
    assert kinds(r, "orphan.js") == kinds(r, "legacy-sw.js") == kinds(r, "vendor/old.js") == ["unknown"]


def test_import_scripts_and_mv2_background_page():
    manifest = {"manifest_version": 2, "background": {"page": "bg.html"}, "web_accessible_resources": ["page.html"]}
    files = {
        "manifest.json": json.dumps(manifest).encode(),
        "bg.html": b'<script src="bg.js"></script>',
        "bg.js": b'importScripts("vendor/old.js");',
        "vendor/old.js": b"",
        "page.html": b'<script src="page.js"></script>',
        "page.js": b"",
    }
    r = run(files)
    assert kinds(r, "bg.js") == kinds(r, "vendor/old.js") == ["background"]
    assert r["page.js"] == {Context("web_accessible_page", ("<all_urls>",), "page.html")}  # MV2: every site


def test_findings_carry_their_context():
    files = {**FILES, "cs/main.js": b'window.addEventListener("message", (e) => run(e.data));'}
    finding = next(f for f in scan(files) if f.file == "cs/main.js")
    assert finding.context == "content script on all sites"
