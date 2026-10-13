from collections.abc import Iterable
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    rule: str
    severity: str  # one of SEVERITIES
    message: str
    file: str
    line: int
    evidence: str
    column: int = 0  # 1-based, 0 when only the line is meaningful
    context: str = ""  # where the code runs (content script on all sites, background...)


class Rule:
    """A check. One subclass per file in rules/vulns or rules/malware, loaded automatically.

    `severity` is the default; a finding may override it.
    """

    id = ""
    severity = "medium"
    description = ""

    def check_manifest(self, manifest) -> Iterable[Finding]:
        return ()

    def check_js(self, js) -> Iterable[Finding]:
        return ()
