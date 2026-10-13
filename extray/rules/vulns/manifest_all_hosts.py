import json

from extray.manifest import all_hosts
from extray.rules.base import Rule


class AllHosts(Rule):
    id = "manifest.all-hosts"
    severity = "high"
    description = "Host permission covering every website"

    def check_manifest(self, mf):
        for p in mf.permissions():
            if all_hosts(p):
                yield mf.finding(self, f"access to every website: {p}", json.dumps(p))
