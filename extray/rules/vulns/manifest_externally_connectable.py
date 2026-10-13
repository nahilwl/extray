import json

from extray.manifest import all_hosts
from extray.rules.base import Rule


class ExternallyConnectable(Rule):
    id = "manifest.externally-connectable"
    severity = "high"
    description = "externally_connectable lets any website or extension message the extension"

    def check_manifest(self, mf):
        ec = mf.data.get("externally_connectable", {})
        for p in ec.get("matches", []):
            if all_hosts(p):
                yield mf.finding(self, f"any website can message the extension: {p}", json.dumps(p))
        if "*" in ec.get("ids", []):
            yield mf.finding(self, "any extension can message the extension", '"ids"', "medium")
