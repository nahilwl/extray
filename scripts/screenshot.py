"""Regenerate docs/scan.svg, the README capture, from the demo extension in docs/demo/:

    python scripts/screenshot.py
"""

import io
from pathlib import Path

from rich.console import Console

from extray import manifest
from extray.report import terminal
from extray.scan import scan

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "docs/demo"

files = {p.relative_to(DEMO).as_posix(): p.read_bytes() for p in sorted(DEMO.rglob("*")) if p.is_file()}
m = manifest.parse(files["manifest.json"].decode())
console = Console(record=True, width=140, file=io.StringIO())
console.print("[bold]$ extray scan price-watch.zip[/]")
terminal.render(f"{m['name']} {m['version']}", scan(files), "low", console)
print(console.export_text(clear=False))
console.save_svg(str(ROOT / "docs/scan.svg"), title="extray")
