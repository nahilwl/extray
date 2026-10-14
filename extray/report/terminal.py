from rich.console import Console
from rich.markup import escape
from rich.table import Table

from extray.rules.base import SEVERITIES, Finding

COLORS = {"info": "dim", "low": "cyan", "medium": "yellow", "high": "bold red"}


def summary(findings: list[Finding], min_severity: str) -> str:
    """'1 high, 0 medium, 2 low, 5 info (5 hidden, -v to show)': hidden ones are below min_severity."""
    counts = ", ".join(f"[{COLORS[s]}]{sum(f.severity == s for f in findings)} {s}[/]" for s in reversed(SEVERITIES))
    hidden = sum(SEVERITIES.index(f.severity) < SEVERITIES.index(min_severity) for f in findings)
    return counts + (f" ({hidden} hidden, -v to show)" if hidden else "")


def coverage(findings: list[Finding], verbose: bool) -> str:
    """'⚠ 2 JS files not analyzed (1 parser crash, 1 too large)', empty when every JS file was analyzed."""
    reasons = {}
    for f in findings:
        if f.rule == "js.too-large":
            reason = "too large"
        elif f.rule == "js.not-analyzed":
            reason = ("parser crash" if "parser crashed" in f.message else "timeout" if "timeout" in f.message
                      else "parser error")
        else:
            continue
        reasons[reason] = reasons.get(reason, 0) + 1
    if not reasons:
        return ""
    total = sum(reasons.values())
    details = ", ".join(f"{n} {r}" for r, n in reasons.items())
    return f"[yellow]⚠ {total} JS file{'s' * (total > 1)} not analyzed ({details})[/]" + ("" if verbose else " — -v for details")


def render(title: str, findings: list[Finding], min_severity: str = "info", console: Console | None = None) -> None:
    console = console or Console()
    shown = [f for f in findings if SEVERITIES.index(f.severity) >= SEVERITIES.index(min_severity)]
    if not shown:
        console.print(f"[bold]{title}[/] — [green]no findings[/]" + (f" at or above {min_severity}" if findings else ""))
    else:
        table = Table(title=title, show_lines=True)
        for col in ("Severity", "Rule", "Message", "Location", "Evidence"):
            table.add_column(col, overflow="fold")
        for f in sorted(shown, key=lambda f: (-SEVERITIES.index(f.severity), f.file, f.line, f.column)):
            c = COLORS[f.severity]
            table.add_row(f"[{c}]{f.severity}[/]", f.rule, escape(f.message), escape(f"{f.file}:{f.line}" + (f":{f.column}" if f.column else "") + (f"\n{f.context}" if f.context else "")), escape(f.evidence))
        console.print(table)
    if findings:
        console.print(summary(findings, min_severity))
    if warning := coverage(findings, min_severity == "info"):
        console.print(warning)
