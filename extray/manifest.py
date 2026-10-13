import json
import re
from dataclasses import dataclass

from extray.rules.base import Finding

# a string literal (kept as is) or a comment (blanked out)
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments outside strings, like Chrome does, keeping line numbers."""
    return _TOKEN.sub(lambda t: t[0] if t[0][0] == '"' else re.sub(r"[^\n]", " ", t[0]), text)


def parse(text: str) -> dict:
    return json.loads(strip_comments(text))


def localize(m: dict, files: dict[str, bytes]) -> dict:
    """Resolve __MSG_key__ in name/description from _locales/<default_locale>/messages.json.

    Keys are case-insensitive; a missing locale, file or key keeps the raw value.
    """
    try:
        raw = files[f"_locales/{m['default_locale']}/messages.json"].decode("utf-8-sig")
        messages = {k.lower(): v["message"] for k, v in parse(raw).items()}
    except (KeyError, ValueError, TypeError, AttributeError):
        return m

    def resolve(value):
        return re.sub(r"__MSG_(\w+?)__", lambda k: str(messages.get(k[1].lower(), k[0])), value)

    return {**m, **{k: resolve(m[k]) for k in ("name", "description") if isinstance(m.get(k), str)}}


def all_hosts(pattern) -> bool:
    """True for <all_urls> and match patterns whose host is a bare `*` (*://*/*, https://*/*...)."""
    return isinstance(pattern, str) and (
        pattern == "<all_urls>" or pattern.partition("://")[2].split("/")[0] == "*"
    )


def _line(text: str, needle: str) -> int:
    # shortcut: first textual occurrence, can point at the wrong spot if the value is repeated elsewhere
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


@dataclass
class Manifest:
    """manifest.json as seen by rules: parsed data plus the text needed to locate findings."""

    text: str  # original, for evidence
    clean: str  # comments blanked out, so needles never match inside a comment
    data: dict
    file: str = "manifest.json"

    @classmethod
    def from_text(cls, text: str, file: str = "manifest.json") -> "Manifest":
        clean = strip_comments(text)
        data = json.loads(clean)
        if not isinstance(data, dict):
            raise ValueError(f"{file} is not a JSON object")
        return cls(text, clean, data, file)

    def permissions(self) -> list[str]:
        return [p for p in self.data.get("permissions", []) + self.data.get("host_permissions", []) if isinstance(p, str)]

    def csp_policies(self) -> list[str]:
        csp = self.data.get("content_security_policy", "")
        return [p for p in (csp.values() if isinstance(csp, dict) else [csp]) if isinstance(p, str)]

    def finding(self, rule, message: str, needle: str, severity: str | None = None) -> Finding:
        n = _line(self.clean, needle)
        lines = self.text.splitlines() or [""]
        return Finding(rule.id, severity or rule.severity, message, self.file, n, lines[n - 1].strip())


def analyze(text: str, file: str = "manifest.json") -> list[Finding]:
    """Run every rule's manifest check."""
    from extray.rules import load_rules  # rules import this module

    mf = Manifest.from_text(text, file)
    return [f for rule in load_rules() for f in rule.check_manifest(mf)]
