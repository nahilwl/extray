import zipfile

import typer
from rich.markup import escape

from extray import manifest
from extray.report import terminal
from extray.scan import MAX_JS_SIZE, scan as run_scan
from extray.unpack import load

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    """extray: X-ray Chrome extensions."""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Chrome Web Store ID or path to a .crx/.zip"),
    max_js_size: int = typer.Option(MAX_JS_SIZE, help="Skip JS files bigger than this many bytes"),
):
    """Analyze an extension."""
    try:
        files = load(target)
        findings = run_scan(files, max_js_size)
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    m = manifest.localize(manifest.parse(files["manifest.json"].decode("utf-8-sig")), files)
    terminal.render(escape(f"{m.get('name', '?')} {m.get('version', '')}"), findings)
