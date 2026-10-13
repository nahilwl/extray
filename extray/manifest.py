import json

from extray.rules.base import Finding

DANGEROUS_PERMISSIONS = {"cookies", "webRequest", "debugger", "nativeMessaging", "management", "history"}


def _all_hosts(pattern) -> bool:
    """True for <all_urls> and match patterns whose host is a bare `*` (*://*/*, https://*/*...)."""
    return isinstance(pattern, str) and (
        pattern == "<all_urls>" or pattern.partition("://")[2].split("/")[0] == "*"
    )


def _line(text: str, needle: str) -> int:
    # shortcut: first textual occurrence, can point at the wrong spot if the value is repeated elsewhere
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


def analyze(text: str, file: str = "manifest.json") -> list[Finding]:
    m = json.loads(text)
    lines = text.splitlines() or [""]
    findings = []

    def add(rule, severity, message, needle):
        n = _line(text, needle)
        findings.append(Finding(rule, severity, message, file, n, lines[n - 1].strip()))

    if m.get("manifest_version") == 2:
        add("manifest.mv2", "low", "Manifest V2 (deprecated, more permissive CSP)", '"manifest_version"')

    for p in m.get("permissions", []) + m.get("host_permissions", []):
        if p in DANGEROUS_PERMISSIONS:
            add("manifest.dangerous-permission", "medium", f"dangerous permission: {p}", json.dumps(p))
        elif _all_hosts(p):
            add("manifest.all-hosts", "high", f"access to every website: {p}", json.dumps(p))

    ec = m.get("externally_connectable", {})
    for p in ec.get("matches", []):
        if _all_hosts(p):
            add("manifest.externally-connectable", "high", f"any website can message the extension: {p}", json.dumps(p))
    if "*" in ec.get("ids", []):
        add("manifest.externally-connectable", "medium", "any extension can message the extension", '"ids"')

    for entry in m.get("web_accessible_resources", []):
        # MV2: list of strings, MV3: list of {resources, matches}
        for r in [entry] if isinstance(entry, str) else entry.get("resources", []):
            if r.endswith((".html", "*")):
                add("manifest.web-accessible-html", "medium", f"internal page exposed to websites: {r}", json.dumps(r))

    csp = m.get("content_security_policy", "")
    for policy in csp.values() if isinstance(csp, dict) else [csp]:
        if "unsafe-eval" in policy:
            add("manifest.csp-unsafe-eval", "high", "CSP allows 'unsafe-eval'", "unsafe-eval")
        for directive in policy.split(";"):
            name, *sources = directive.split() or [""]
            if name in ("script-src", "default-src"):
                for s in sources:
                    if s.startswith(("http", "*", "data:")):
                        add("manifest.csp-remote-script", "high", f"CSP allows remote scripts: {s}", s)

    for cs in m.get("content_scripts", []):
        if any(_all_hosts(p) for p in cs.get("matches", [])):
            extras = [x for x, on in (("document_start", cs.get("run_at") == "document_start"),
                                      ("all_frames", cs.get("all_frames"))) if on]
            add("manifest.content-script-all-urls", "medium" if extras else "low",
                "content script injected into every website" + (f" ({', '.join(extras)})" if extras else ""),
                '"content_scripts"')

    return findings
