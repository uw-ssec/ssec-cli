"""`ssec tools` sub-commands."""

from pathlib import Path

import typer
from rich.console import Console

from ssec_cli.tools import report
from ssec_cli.tools.evaluate import Status, scan

tools_app = typer.Typer(
    help="Check installed tool versions against security advisories."
)


@tools_app.command()
def check(
    path: Path = typer.Option(
        Path.cwd,
        "--path",
        help="Project directory to scan for lockfiles.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    json_: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    fail_on_outdated: bool = typer.Option(
        False, "--fail-on-outdated", help="Exit 1 if anything is OUTDATED."
    ),
) -> None:
    """Check tools, Python environments and lockfiles for affected versions."""
    home = Path.home()
    console = Console()
    if json_:
        result = scan(home, path)
        typer.echo(report.to_json(result, home))
    else:
        with console.status("Scanning…"):
            result = scan(home, path)
        report.render(result, console, home)
    if fail_on_outdated and any(f.status is Status.OUTDATED for f in result.findings):
        raise typer.Exit(code=1)
