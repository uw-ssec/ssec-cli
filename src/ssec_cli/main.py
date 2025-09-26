"""SSEC CLI - A CLI tool built with typer."""

import json
import subprocess
from pathlib import Path
import typer
from rich import print

app = typer.Typer(
    name="ssec-cli",
    help="A CLI tool built with typer",
    add_completion=True,
)
# console = Console()


@app.command(help="Install VSCode extensions from .vscode/extensions.json")
def install_vscode_extensions(
    repo_root: Path = typer.Argument(..., help="The name to greet"),
) -> None:
    # iterate over all entries in .vscode/extensions.json and install them
    extensions_file = repo_root / ".vscode" / "extensions.json"
    if not extensions_file.exists():
        print(f"No extensions file found at {extensions_file}")
        return

    with open(extensions_file, encoding="utf-8") as f:
        data = json.load(f)
    extensions = data.get("recommendations", [])
    for ext in extensions:
        result = None
        try:
            result = subprocess.run(
                ["code", "--install-extension", ext], check=True, stdout=subprocess.PIPE
            )
            print(f"[green] Installed extension: {ext}")
        except subprocess.CalledProcessError as e:
            print(
                f"[red] Failed to install extension {ext}: {e} {result.stdout.decode('utf-8') if result else ''}"
            )


@app.command(help="Run diagnostics on the current environment")
def diagnostics():
    """Run diagnostics on the current environment."""
    print("[bold]Running diagnostics...[/bold]")
    # Example diagnostic: Check Python version
    import sys

    print(f"Python version: {sys.version}")
    # Add more diagnostics as needed


if __name__ == "__main__":
    app()
