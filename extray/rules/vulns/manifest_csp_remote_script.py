from extray.rules.base import Rule


class CspRemoteScript(Rule):
    id = "manifest.csp-remote-script"
    severity = "high"
    description = "CSP allows scripts from remote sources"

    def check_manifest(self, mf):
        for policy in mf.csp_policies():
            for directive in policy.split(";"):
                name, *sources = directive.split() or [""]
                if name in ("script-src", "default-src"):
                    for s in sources:
                        if s.startswith(("http", "*", "data:")):
                            yield mf.finding(self, f"CSP allows remote scripts: {s}", s)
