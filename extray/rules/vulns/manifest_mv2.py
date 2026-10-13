from extray.rules.base import Rule


class ManifestV2(Rule):
    id = "manifest.mv2"
    severity = "low"
    description = "Manifest V2 (deprecated, more permissive CSP)"

    def check_manifest(self, mf):
        if mf.data.get("manifest_version") == 2:
            yield mf.finding(self, self.description, '"manifest_version"')
