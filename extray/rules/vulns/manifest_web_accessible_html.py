import json

from extray.manifest import all_hosts
from extray.rules.base import Rule


class WebAccessibleHtml(Rule):
    id = "manifest.web-accessible-html"
    severity = "medium"
    description = "Internal HTML page reachable from websites (clickjacking, UXSS entry point)"

    def check_manifest(self, mf):
        for entry in mf.data.get("web_accessible_resources", []):
            if isinstance(entry, str):  # MV2: no matches, exposed to every website
                resources, everywhere = [entry], True
            else:  # MV3: use_dynamic_url makes the URL unguessable for websites
                resources = entry.get("resources", [])
                everywhere = any(all_hosts(p) for p in entry.get("matches", [])) and not entry.get("use_dynamic_url")
            for r in resources:
                if r.endswith((".html", "*")):
                    yield mf.finding(self, f"internal page exposed to websites: {r}", json.dumps(r),
                                     "medium" if everywhere else "low")
