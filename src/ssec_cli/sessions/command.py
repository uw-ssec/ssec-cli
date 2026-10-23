"""The ``ssec archive-sessions`` command."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ssec_cli import __version__
from ssec_cli.sessions.agents import ALL_AGENTS, AgentConfig
from ssec_cli.sessions.discovery import discover_agents
from ssec_cli.sessions.github_user import resolve_github_username
from ssec_cli.sessions.selection import (
    AgentSelection,
    TimeWindow,
    parse_time_bound,
    select_files,
)
from ssec_cli.sessions.writer import ArchiveError, build_manifest, write_archive

console = Console()

PRIVACY_REMINDER = (
    "Agent transcripts can contain secrets, access tokens, file contents, and personal "
    "information. Review the archive before you share it."
)


def _parse_agents(value: str | None) -> list[AgentConfig]:
    if not value:
        return list(ALL_AGENTS)
    requested = [name.strip() for name in value.split(",") if name.strip()]
    valid_names = {a.name for a in ALL_AGENTS}
    unknown = [n for n in requested if n not in valid_names]
    if unknown:
        available = ", ".join(sorted(valid_names))
        raise typer.BadParameter(
            f"Unknown agent(s): {', '.join(unknown)}. Available: {available}",
            param_hint="--agents",
        )
    return [a for a in ALL_AGENTS if a.name in requested]


def _parse_bound(value: str | None, *, end: bool, option: str) -> float | None:
    if value is None:
        return None
    try:
        return parse_time_bound(value, end=end)
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not a date (YYYY-MM-DD) or date-time (YYYY-MM-DDTHH:MM).",
            param_hint=option,
        ) from None


def _format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def _default_filename(username: str, now: datetime) -> str:
    safe_user = re.sub(r"[^A-Za-z0-9_-]", "_", username)
    return f"agent-sessions-{safe_user}-{now:%Y%m%d-%H%M%S}.zip"


def _summary_table(selections: list[AgentSelection]) -> Table:
    table = Table("Agent", "Source", "Files", "Size")
    for s in selections:
        table.add_row(
            s.agent.display_name,
            str(s.root),
            str(len(s.files)),
            _format_size(s.total_bytes),
        )
    table.add_row(
        "[bold]Total[/bold]",
        "",
        str(sum(len(s.files) for s in selections)),
        _format_size(sum(s.total_bytes for s in selections)),
    )
    return table


def archive_sessions(
    agents: str | None = typer.Option(
        None,
        "--agents",
        help="Comma-separated agent names to include (default: all), e.g. claude-code,codex",
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Only files modified on or after this date (YYYY-MM-DD) or date-time",
    ),
    until: str | None = typer.Option(
        None,
        "--until",
        help="Only files modified on or before this date (YYYY-MM-DD) or date-time",
    ),
    jsonl_only: bool = typer.Option(
        False, "--jsonl-only", help="Only include *.jsonl files"
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Zip file to write (ending in .zip), or a directory to write it in, "
            "created if needed (default: current directory)"
        ),
    ),
    username: str | None = typer.Option(
        None,
        "--username",
        help="GitHub username for the filename and manifest (auto-detected if omitted)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be archived without writing anything"
    ),
) -> None:
    """Archive AI agent session transcripts to a local zip file."""
    agent_list = _parse_agents(agents)
    window = TimeWindow(
        start=_parse_bound(since, end=False, option="--since"),
        end=_parse_bound(until, end=True, option="--until"),
    )

    discovered, skipped = discover_agents(agent_list)
    for notice in skipped:
        console.print(notice, style="dim")

    selections = [
        select_files(
            d.agent,
            d.path,
            window=window,
            jsonl_only=jsonl_only,
        )
        for d in discovered
    ]
    excluded = sum(s.excluded_credentials for s in selections)
    for s in selections:
        for directory in s.unreadable_dirs:
            console.print(f"Could not read {directory}; left it out.", style="yellow")
    selections = [s for s in selections if s.files]

    if excluded:
        console.print(
            f"Left out {excluded} credential file(s), such as auth.json and oauth_creds.json."
        )

    if not selections:
        console.print("No agent session files matched.")
        raise typer.Exit()

    github_user = resolve_github_username(username)
    now = datetime.now()
    filename = _default_filename(github_user, now)
    if output is None:
        target = Path.cwd() / filename
    elif output.is_dir() or output.suffix.lower() != ".zip":
        target = output / filename
    else:
        target = output

    if target.exists():
        raise typer.BadParameter(f"{target} already exists.", param_hint="--output")

    console.print(_summary_table(selections))

    if dry_run:
        console.print(f"Dry run: would write {target}")
        return

    manifest = build_manifest(
        username=github_user,
        version=__version__,
        created_at=now.astimezone(),
        filters={
            "agents": [a.name for a in agent_list],
            "since": since,
            "until": until,
            "jsonl_only": jsonl_only,
        },
    )
    try:
        result = write_archive(target, selections, manifest)
    except ArchiveError as error:
        console.print(f"[bold red]Error:[/bold red] {error}. No archive was written.")
        raise typer.Exit(1) from None

    for s in selections:
        for db, tables in s.redacted_tables.items():
            console.print(
                f"Emptied credential tables in {s.agent.display_name}'s {db}: "
                f"{', '.join(tables)}"
            )
    for path, reason in result.skipped:
        console.print(f"Left out {path}: {reason}", style="yellow")
    console.print(
        f"Wrote {result.file_count} file(s) ({_format_size(result.total_bytes)} uncompressed) to {result.path}"
    )
    console.print(f"[bold yellow]Warning:[/bold yellow] {PRIVACY_REMINDER}")
