import zipfile
from typing import Literal

import typer
from rich.markup import escape

from extray import manifest
from extray.report import terminal
from extray.scan import JS_TIMEOUT, MAX_JS_SIZE, scan as run_scan
from extray.unpack import load

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    """extray: X-ray Chrome extensions."""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Chrome Web Store ID or path to a .crx/.zip"),
    max_js_size: int = typer.Option(MAX_JS_SIZE, help="Skip JS files bigger than this many bytes"),
    js_timeout: float = typer.Option(JS_TIMEOUT, help="Give up on a JS file after this many seconds"),
    min_severity: Literal["info", "low", "medium", "high"] = typer.Option("low", help="Hide less severe findings"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show every finding, info included"),
):
    """Analyze an extension."""
    try:
        files = load(target)
        findings = run_scan(files, max_js_size, js_timeout)
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    m = manifest.localize(manifest.parse(files["manifest.json"].decode("utf-8-sig")), files)
    terminal.render(escape(f"{m.get('name', '?')} {m.get('version', '')}"), findings, "info" if verbose else min_severity)
