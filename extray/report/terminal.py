from rich.console import Console
from rich.markup import escape
from rich.table import Table

from extray.rules.base import Finding

COLORS = {"info": "dim", "low": "cyan", "medium": "yellow", "high": "bold red"}


def render(title: str, findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print(f"[bold]{title}[/] — [green]no findings[/]")
        return
    table = Table(title=title, show_lines=True)
    for col in ("Severity", "Rule", "Message", "Location", "Evidence"):
        table.add_column(col, overflow="fold")
    for f in findings:
        c = COLORS[f.severity]
        table.add_row(f"[{c}]{f.severity}[/]", f.rule, escape(f.message), escape(f"{f.file}:{f.line}" + (f":{f.column}" if f.column else "") + (f"\n{f.context}" if f.context else "")), escape(f.evidence))
    console.print(table)
