"""Where each JS file of an extension runs, deduced from the manifest, the HTML pages and imports."""

import posixpath
from dataclasses import dataclass
from fnmatch import fnmatch
from html.parser import HTMLParser

from extray.js.parser import JSFile, args, callee, string_value
from extray.manifest import Manifest, all_hosts

KINDS = ("content_script", "background", "extension_page", "web_accessible_page", "unknown")


@dataclass(frozen=True)
class Context:
    kind: str  # one of KINDS
    matches: tuple[str, ...] = ()  # sites a content script or web-accessible page is exposed to
    page: str = ""  # HTML page loading the script
    dynamic_url: bool = False  # web-accessible page with use_dynamic_url: its URL is unguessable

    @property
    def all_sites(self) -> bool:
        return any(all_hosts(m) for m in self.matches)

    def __str__(self) -> str:
        sites = "all sites" if self.all_sites else ", ".join(self.matches) or "no site"
        return {
            "content_script": f"content script on {sites}",
            "background": "background",
            "extension_page": f"extension page {self.page}",
            "web_accessible_page": f"web-accessible page {self.page} on {sites}" + (" (dynamic URL)" if self.dynamic_url else ""),
            "unknown": "unknown context",
        }[self.kind]


class _ScriptSources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attrs):
        src = dict(attrs).get("src")
        if tag == "script" and src:
            self.sources.append(src)


def _resolve(base_file: str, ref, bare_is_relative: bool = True) -> str | None:
    """Package path of a reference made from base_file; None if remote or a bare module name.

    '/x.js' is the package root. A bare 'x.js' is relative for HTML src, importScripts and the manifest,
    but names a package in an ES import ('lodash').
    """
    if not isinstance(ref, str) or not ref or "://" in ref or ref.startswith("//"):
        return None
    ref = ref.split("?")[0].split("#")[0]
    if ref.startswith("/"):
        return posixpath.normpath(ref.lstrip("/"))
    if not bare_is_relative and not ref.startswith("."):
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(base_file), ref))


def imported_files(js: JSFile) -> list[str]:
    """Files loaded by a JS file: import/export ... from, import("..."), importScripts("...")."""
    refs = [(string_value(n.child_by_field_name("source")), False)
            for n in js.nodes("import_statement", "export_statement") if n.child_by_field_name("source")]
    for call in js.nodes("call_expression"):
        name = callee(call)
        if name == "import" or name.endswith("importScripts"):
            refs += [(string_value(a), name != "import") for a in args(call)]
    return [p for ref, bare in refs if (p := _resolve(js.file, ref, bare))]


def _page_context(mf: Manifest, page: str) -> Context:
    background = mf.data.get("background", {})
    if isinstance(background, dict) and _resolve("", background.get("page")) == page:
        return Context("background", page=page)
    for entry in mf.data.get("web_accessible_resources", []):
        resources = [entry] if isinstance(entry, str) else entry.get("resources", [])
        if any(isinstance(r, str) and fnmatch(page, r.lstrip("/")) for r in resources):
            if isinstance(entry, str):  # MV2: exposed to every website
                return Context("web_accessible_page", ("<all_urls>",), page)
            return Context("web_accessible_page", tuple(entry.get("matches", [])), page, bool(entry.get("use_dynamic_url")))
    return Context("extension_page", page=page)


def contexts(mf: Manifest, files: dict[str, bytes], imports: dict[str, list[str]]) -> dict[str, set[Context]]:
    """Contexts of every parsed JS file, given the files each one imports (see imported_files);
    a file can run in several, and unreferenced ones are 'unknown'."""
    found: dict[str, set[Context]] = {name: set() for name in imports}

    def add(path, ctx):
        if path in found:
            found[path].add(ctx)

    for cs in mf.data.get("content_scripts", []):
        ctx = Context("content_script", tuple(m for m in cs.get("matches", []) if isinstance(m, str)))
        for path in cs.get("js", []):
            add(_resolve("", path), ctx)

    background = mf.data.get("background", {})
    if isinstance(background, dict):
        for path in [background.get("service_worker"), *background.get("scripts", [])]:
            add(_resolve("", path), Context("background"))

    for page in (name for name in files if name.endswith((".html", ".htm"))):
        parser = _ScriptSources()
        parser.feed(files[page].decode("utf-8", "replace"))
        ctx = _page_context(mf, page)
        for src in parser.sources:
            add(_resolve(page, src), ctx)

    # imported files run wherever their importer runs, transitively
    changed = True
    while changed:
        changed = False
        for name, targets in imports.items():
            for target in targets:
                if target in found and not found[name] <= found[target]:
                    found[target] |= found[name]
                    changed = True

    return {name: ctxs or {Context("unknown")} for name, ctxs in found.items()}


EXPOSURES = ("internal", "sites", "web")  # who can feed a source, from least to most exposed
EXPOSURE_LABELS = {"internal": "the extension only", "sites": "some websites or extensions", "web": "any website"}


def _context_exposure(ctx: Context) -> str:
    """Who controls the page around code running in this context (its URL, its postMessage calls)."""
    if ctx.kind in ("content_script", "web_accessible_page") and ctx.matches:
        return "web" if ctx.all_sites and not ctx.dynamic_url else "sites"
    return "internal"


def exposure(source_kind: str, ctxs: set[Context], mf: Manifest | None) -> str:
    """How exposed a source is: window messages and page sources depend on where the code runs,
    external messages on externally_connectable, internal runtime messages only reach the extension."""
    if source_kind == "runtime_message":
        return "internal"
    if source_kind == "external_message":
        ec = mf.data.get("externally_connectable") if mf else None
        if not isinstance(ec, dict):
            return "sites"  # not declared: every other extension can send messages
        matches = [m for m in ec.get("matches", []) if isinstance(m, str)]
        if any(all_hosts(m) for m in matches):
            return "web"
        return "sites" if matches or "*" in ec.get("ids", []) else "internal"
    return max((_context_exposure(c) for c in ctxs), key=EXPOSURES.index, default="internal")
