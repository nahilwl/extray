"""Regenerate docs/scan.svg, the scan capture shown in the README: python scripts/screenshot.py"""

import io
import json
from pathlib import Path

from rich.console import Console

from extray.report import terminal
from extray.scan import scan

ROOT = Path(__file__).resolve().parent.parent

files = {
    "manifest.json": json.dumps({"name": "Demo", "version": "1.0", "manifest_version": 3,
                                 "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}]}, indent=2).encode(),
    "content.js": (ROOT / "tests/fixtures/js/js.flow-html/vuln.js").read_bytes(),
}
console = Console(record=True, width=140, file=io.StringIO())
console.print("[bold]$ extray scan demo.zip[/]")
terminal.render("Demo 1.0", scan(files), "low", console)
console.save_svg(str(ROOT / "docs/scan.svg"), title="extray")
