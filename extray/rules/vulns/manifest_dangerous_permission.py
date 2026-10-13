import json

from extray.rules.base import Rule

DANGEROUS = {"cookies", "webRequest", "debugger", "nativeMessaging", "management", "history"}


class DangerousPermission(Rule):
    id = "manifest.dangerous-permission"
    severity = "medium"
    description = "Permission giving access to sensitive data or control over the browser"

    def check_manifest(self, mf):
        for p in mf.permissions():
            if p in DANGEROUS:
                yield mf.finding(self, f"dangerous permission: {p}", json.dumps(p))
