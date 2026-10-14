"""Regenerate docs/scan.svg, the README capture, from the demo extension in docs/demo/:

    python scripts/screenshot.py
"""

import io
from pathlib import Path

from rich.console import Console

from extray import manifest
from extray.report import terminal
from extray.scan import scan
from extray.unpack import load

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "docs/demo"

files = load(str(DEMO))
m = manifest.parse(files["manifest.json"].decode())
console = Console(record=True, width=140, file=io.StringIO())
console.print("[bold]$ extray scan docs/demo/[/]")
terminal.render(f"{m['name']} {m['version']}", scan(files), "low", console)
print(console.export_text(clear=False))
console.save_svg(str(ROOT / "docs/scan.svg"), title="extray")
