from extray.context import contexts
from extray.js.parser import JSFile
from extray.manifest import Manifest
from extray.rules import load_rules
from extray.rules.base import Finding

MAX_JS_SIZE = 5 * 1024 * 1024
JS_EXTENSIONS = (".js", ".mjs", ".cjs")


def scan(files: dict[str, bytes], max_js_size: int = MAX_JS_SIZE) -> list[Finding]:
    """Run every rule on the manifest and on each JS file of the extension."""
    if "manifest.json" not in files:
        raise ValueError("no manifest.json at the root of the archive")
    rules = load_rules()
    mf = Manifest.from_text(files["manifest.json"].decode("utf-8-sig"))
    findings = [f for rule in rules for f in rule.check_manifest(mf)]
    parsed = {}
    for name in sorted(files):
        if not name.endswith(JS_EXTENSIONS):
            continue
        size = len(files[name])
        if size > max_js_size:
            findings.append(Finding("js.too-large", "info", f"not analyzed: {size} bytes, limit is {max_js_size}",
                                    name, 1, ""))
            continue
        parsed[name] = JSFile(name, files[name])
    for name, ctxs in contexts(mf, files, parsed).items():
        parsed[name].contexts = ctxs
    for js in parsed.values():
        findings += [f for rule in rules for f in rule.check_js(js)]
    return findings
