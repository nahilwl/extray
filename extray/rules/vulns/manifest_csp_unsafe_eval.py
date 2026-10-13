from extray.rules.base import Rule


class CspUnsafeEval(Rule):
    id = "manifest.csp-unsafe-eval"
    severity = "high"
    description = "CSP allows 'unsafe-eval'"

    def check_manifest(self, mf):
        for policy in mf.csp_policies():
            if "unsafe-eval" in policy:
                yield mf.finding(self, self.description, "unsafe-eval")
