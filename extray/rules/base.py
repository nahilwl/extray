from dataclasses import dataclass

SEVERITIES = ("low", "medium", "high")


@dataclass
class Finding:
    rule: str
    severity: str  # one of SEVERITIES
    message: str
    file: str
    line: int
    evidence: str
