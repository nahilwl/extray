from extray.manifest import all_hosts
from extray.rules.base import Rule


class ContentScriptAllUrls(Rule):
    id = "manifest.content-script-all-urls"
    severity = "low"
    description = "Content script injected into every website"

    def check_manifest(self, mf):
        for cs in mf.data.get("content_scripts", []):
            if any(all_hosts(p) for p in cs.get("matches", [])):
                extras = [x for x, on in (("document_start", cs.get("run_at") == "document_start"),
                                          ("all_frames", cs.get("all_frames"))) if on]
                yield mf.finding(self, self.description + (f" ({', '.join(extras)})" if extras else ""),
                                 '"content_scripts"', "medium" if extras else None)
