import json
import zipfile

import typer
from rich.markup import escape

from extray import manifest
from extray.report import terminal
from extray.unpack import load

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    """extray: X-ray Chrome extensions."""


@app.command()
def scan(target: str = typer.Argument(..., help="Chrome Web Store ID or path to a .crx/.zip")):
    """Analyze an extension."""
    try:
        text = load(target)["manifest.json"].decode("utf-8-sig")
        findings = manifest.analyze(text)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)
    m = json.loads(text)
    terminal.render(escape(f"{m.get('name', '?')} {m.get('version', '')}"), findings)
