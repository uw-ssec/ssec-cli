"""Choose which session files from an agent's directory go into an archive."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

from ssec_cli.sessions.agents import AgentConfig
from ssec_cli.sessions.projects import (
    ProjectMatcher,
    claude_project_dirs,
    codex_session_matches,
)

EXCLUDED_FILE_PATTERNS = (
    "auth.json",
    "*-auth.json",
    "*oauth*",
    "*credential*",
    "*secret*",
    "*token*.json",
    "google_accounts.json",
    "settings.json",
    "settings.local.json",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ecdsa*",
    "id_ed25519*",
)
"""Credential and configuration files that may sit next to sessions. They are
never archived. This is a backstop: agents whose session path is a general data
directory list their session locations in ``AgentConfig.session_subpaths``."""

SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True)
class TimeWindow:
    """Modification-time bounds, as POSIX timestamps. Either end may be open."""

    start: float | None = None
    end: float | None = None

    def contains(self, mtime: float) -> bool:
        return (self.start is None or mtime >= self.start) and (
            self.end is None or mtime <= self.end
        )


def parse_time_bound(value: str, *, end: bool) -> float:
    """Parse an ISO date or date-time into a POSIX timestamp.

    Values without a timezone are local time. A bare date used as the end of a
    window covers that whole day.
    """
    try:
        day = date.fromisoformat(value)
    except ValueError:
        parsed = datetime.fromisoformat(value)
    else:
        parsed = datetime.combine(day, datetime.min.time())
        if end:
            parsed += timedelta(days=1) - timedelta(microseconds=1)
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.timestamp()


@dataclass
class AgentSelection:
    """The files chosen from one agent's session directory."""

    agent: AgentConfig
    root: Path
    files: list[Path] = field(default_factory=list)
    total_bytes: int = 0
    excluded_credentials: int = 0
    unreadable_dirs: list[Path] = field(default_factory=list)
    redacted_tables: dict[str, list[str]] = field(default_factory=dict)
    """Emptied SQLite tables, keyed by the database's path relative to *root*."""

    def manifest_entry(self) -> dict:
        entry: dict = {
            "name": self.agent.name,
            "display_name": self.agent.display_name,
            "source_path": str(self.root),
            "file_count": len(self.files),
            "total_bytes": self.total_bytes,
        }
        if self.redacted_tables:
            entry["redacted_sqlite_tables"] = self.redacted_tables
        return entry


def is_credential_file(path: Path) -> bool:
    name = path.name.lower()
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in EXCLUDED_FILE_PATTERNS)


def _is_sqlite_sidecar(path: Path) -> bool:
    """True for a SQLite WAL, shared-memory, or journal file next to its database."""
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        if path.name.endswith(suffix):
            return path.with_name(path.name.removesuffix(suffix)).is_file()
    return False


def walk_files(root: Path, errors: list[Path]) -> Iterator[Path]:
    """Yield regular files under *root*, without following symlinks.

    Directories that cannot be listed are appended to *errors*.
    """
    if root.is_file() and not root.is_symlink():
        yield root
        return

    def onerror(error: OSError) -> None:
        errors.append(Path(error.filename) if error.filename else root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        dirnames.sort()
        for filename in sorted(filenames):
            path = Path(dirpath, filename)
            if path.is_file() and not path.is_symlink():
                yield path


def _session_key(agent: AgentConfig, root: Path, path: Path) -> object:
    """Group files that belong to one session, so time filters keep them together.

    Claude Code stores ``<project>/<id>.jsonl`` next to a ``<project>/<id>/``
    directory of subagent transcripts and tool results. Other agents' files
    are treated individually.
    """
    if agent.name == "claude-code":
        parts = path.relative_to(root).parts
        if len(parts) >= 2:
            return (parts[0], parts[1].removesuffix(".jsonl"))
    return path


def _mtime(path: Path, stat: os.stat_result) -> float:
    """Return the modification time, counting a SQLite database's write-ahead log."""
    wal = path.with_name(path.name + "-wal")
    try:
        return max(stat.st_mtime, wal.stat().st_mtime)
    except OSError:
        return stat.st_mtime


def select_files(
    agent: AgentConfig,
    root: Path,
    *,
    window: TimeWindow | None = None,
    jsonl_only: bool = False,
    project: ProjectMatcher | None = None,
) -> AgentSelection:
    """Choose the files to archive from one agent's session directory.

    *project* must be ``None`` for agents not in ``PROJECT_AGENTS``. With a
    time window, a session is kept whole if any of its files were
    modified in the window. SQLite WAL and shared-memory files are left out;
    the archive writer copies their content into a snapshot of the database.
    """
    window = window or TimeWindow()
    selection = AgentSelection(agent=agent, root=root)
    errors = selection.unreadable_dirs

    if project is None:
        tops = [root / sub for sub in agent.session_subpaths] or [root]
        candidates: Iterator[Path] = (
            f for top in tops if top.exists() for f in walk_files(top, errors)
        )
    elif agent.name == "claude-code":
        candidates = (
            f for d in claude_project_dirs(root, project) for f in walk_files(d, errors)
        )
    elif agent.name == "codex":
        candidates = (
            f for f in walk_files(root, errors) if codex_session_matches(f, project)
        )
    else:
        raise ValueError(f"--project is not supported for {agent.display_name}")

    sessions: dict[object, list[tuple[Path, int]]] = {}
    in_window: set[object] = set()
    for path in candidates:
        if is_credential_file(path):
            selection.excluded_credentials += 1
            continue
        if jsonl_only and path.suffix != ".jsonl":
            continue
        if _is_sqlite_sidecar(path):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        key = _session_key(agent, root, path)
        sessions.setdefault(key, []).append((path, stat.st_size))
        if window.contains(_mtime(path, stat)):
            in_window.add(key)

    for key, members in sessions.items():
        if key in in_window:
            for path, size in members:
                selection.files.append(path)
                selection.total_bytes += size

    return selection
