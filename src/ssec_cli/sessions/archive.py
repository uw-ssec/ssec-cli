"""Select agent session files and write them to a zip archive."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path, PurePath

from ssec_cli.sessions.agents import AgentConfig

MANIFEST_NAME = "manifest.json"

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

SQLITE_REDACT_TABLE_PATTERNS = (
    "*account*",
    "*auth*",
    "*credential*",
    "*password*",
    "*secret*",
    "*token*",
)
"""Tables emptied in every archived SQLite database. OpenCode, for example,
keeps OAuth tokens in ``account`` and ``control_account`` next to its sessions."""

PROJECT_AGENTS = frozenset({"claude-code", "codex"})
"""Agents that ``--project`` can filter. Other agents are skipped when it is set."""

SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

_SQLITE_MAGIC = b"SQLite format 3\x00"

# How many leading lines of a transcript to scan for the recorded working directory.
_CWD_SCAN_LINES = 50

_CASE_INSENSITIVE_PATHS = sys.platform in ("darwin", "win32")


class ArchiveError(Exception):
    """Writing the archive failed and nothing was written."""


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


def _path_key(path: PurePath) -> tuple[str, ...]:
    parts = path.parts
    return tuple(p.casefold() for p in parts) if _CASE_INSENSITIVE_PATHS else parts


@dataclass(frozen=True)
class ProjectMatcher:
    """Matches a working directory against a ``--project`` value.

    A value that looks like a path (contains a separator, or starts with ``.``
    or ``~``) matches that directory and anything under it. Any other value
    matches a working directory whose final component has that name. Matching
    ignores case on macOS and Windows.
    """

    paths: tuple[PurePath, ...] = ()
    """The project directory as given (made absolute) and with symlinks resolved."""

    name: str | None = None

    @classmethod
    def parse(cls, value: str) -> ProjectMatcher:
        if "/" in value or os.sep in value or value.startswith((".", "~")):
            given = Path(os.path.abspath(Path(value).expanduser()))
            return cls(paths=tuple(dict.fromkeys((given, given.resolve()))))
        return cls(name=value)

    def matches(self, cwd: str) -> bool:
        cwd_key = _path_key(PurePath(cwd))
        if self.name is not None:
            return bool(cwd_key) and cwd_key[-1:] == _path_key(PurePath(self.name))
        return any(cwd_key[: len(k)] == k for k in map(_path_key, self.paths))


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


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC
    except OSError:
        return False


def _walk_files(root: Path, errors: list[Path]) -> Iterator[Path]:
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


def _read_cwd(path: Path, extract: Callable[[dict], str | None]) -> str | None:
    """Return the first working directory *extract* finds in a JSONL transcript."""
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= _CWD_SCAN_LINES:
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and (cwd := extract(record)):
                    return cwd
    except OSError:
        return None
    return None


def _claude_cwd(record: dict) -> str | None:
    cwd = record.get("cwd")
    return cwd if isinstance(cwd, str) else None


def _codex_cwd(record: dict) -> str | None:
    if record.get("type") != "session_meta":
        return None
    payload = record.get("payload")
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    return cwd if isinstance(cwd, str) else None


def _encode_claude_project(path: PurePath) -> str:
    """Encode a path the way Claude Code names its per-project directories."""
    return re.sub(r"[^A-Za-z0-9]", "-", str(path))


def _claude_project_dirs(root: Path, matcher: ProjectMatcher) -> list[Path]:
    """Return the Claude Code project directories that belong to *matcher*'s project.

    Claude Code keeps one directory per working directory, named by encoding
    the path. The encoding is lossy, so each directory's real working
    directory is read from its transcripts, with the name as a fallback.
    """
    matched = []
    for project_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        cwd = next(
            (
                cwd
                for f in sorted(project_dir.glob("*.jsonl"))
                if (cwd := _read_cwd(f, _claude_cwd))
            ),
            None,
        )
        if cwd is not None:
            if matcher.matches(cwd):
                matched.append(project_dir)
        elif any(
            _path_key(PurePath(project_dir.name))
            == _path_key(PurePath(_encode_claude_project(p)))
            for p in matcher.paths
        ):
            matched.append(project_dir)
    return matched


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
    time window, a session is kept whole if any of its files were modified in
    the window.
    """
    window = window or TimeWindow()
    selection = AgentSelection(agent=agent, root=root)
    errors = selection.unreadable_dirs

    if project is None:
        tops = [root / sub for sub in agent.session_subpaths] or [root]
        candidates: Iterator[Path] = (
            f for top in tops if top.exists() for f in _walk_files(top, errors)
        )
    elif agent.name == "claude-code":
        candidates = (
            f
            for d in _claude_project_dirs(root, project)
            for f in _walk_files(d, errors)
        )
    elif agent.name == "codex":
        candidates = (
            f
            for f in _walk_files(root, errors)
            if f.suffix == ".jsonl"
            and (cwd := _read_cwd(f, _codex_cwd))
            and project.matches(cwd)
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
            continue  # Folded into the database's snapshot when it is written.
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


@dataclass
class ArchiveResult:
    path: Path
    file_count: int
    total_bytes: int
    skipped: list[tuple[Path, str]]
    """Files left out while writing, with the reason."""


def _is_redacted_table(name: str, redact: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return lowered in redact or any(
        fnmatch.fnmatchcase(lowered, p) for p in SQLITE_REDACT_TABLE_PATTERNS
    )


def _snapshot_sqlite(path: Path, dest: Path, redact: tuple[str, ...]) -> list[str]:
    """Copy a SQLite database, including committed WAL content, to *dest*.

    Tables named in *redact*, or matching ``SQLITE_REDACT_TABLE_PATTERNS``, are
    emptied in the copy, which is then vacuumed so the deleted rows are gone.
    Return the names of the tables that had rows removed.
    """
    source = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=10)
    try:
        target = sqlite3.connect(dest, isolation_level=None)
        try:
            source.backup(target)
            target.execute("PRAGMA journal_mode=DELETE")
            target.execute("PRAGMA secure_delete=ON")
            tables = [
                name
                for (name,) in target.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
                if not name.startswith("sqlite_")
            ]
            redacted = []
            for name in tables:
                if _is_redacted_table(name, redact):
                    quoted = name.replace('"', '""')
                    if target.execute(f'DELETE FROM "{quoted}"').rowcount:
                        redacted.append(name)
            target.execute("VACUUM")
            return redacted
        finally:
            target.close()
    finally:
        source.close()


def _add_file(
    zf: zipfile.ZipFile,
    path: Path,
    arcname: str,
    scratch: Path,
    redacted: list[str] | None = None,
    redact_tables: tuple[str, ...] = (),
) -> int | str:
    """Add one file to *zf*. Return its size, or why it was left out.

    SQLite databases are added as a redacted snapshot (see ``_snapshot_sqlite``),
    and the tables emptied are appended to *redacted*.

    Failures before any data is written leave the zip unchanged and are
    returned as a reason. A failure part-way through raises ``ArchiveError``,
    since the zip would then hold a truncated entry.
    """
    try:
        arcname.encode("utf-8")
    except UnicodeEncodeError:
        return "its name is not valid UTF-8"

    source = path
    if _is_sqlite(path):
        source = scratch / "snapshot.db"
        source.unlink(missing_ok=True)
        try:
            emptied = _snapshot_sqlite(path, source, redact_tables)
        except sqlite3.Error as error:
            return f"could not snapshot the SQLite database ({error})"
        if redacted is not None:
            redacted.extend(emptied)

    try:
        info = zipfile.ZipInfo.from_file(path, arcname, strict_timestamps=False)
        handle = source.open("rb")
        if source != path:
            info.file_size = source.stat().st_size  # Sizes the zip64 decision.
    except OSError as error:
        return error.strerror or str(error)
    info.compress_type = zipfile.ZIP_DEFLATED

    with handle, zf.open(info, "w") as entry:
        try:
            shutil.copyfileobj(handle, entry)
        except OSError as error:
            raise ArchiveError(f"Failed while reading {path}: {error}") from error
    return info.file_size


def write_archive(
    output: Path,
    selections: list[AgentSelection],
    manifest: dict,
) -> ArchiveResult:
    """Write the selected files and ``manifest.json`` to a zip at *output*.

    Each agent's files go under a directory named after the agent, keeping their
    layout relative to the agent's session directory. SQLite databases are
    copied through SQLite's backup API, so a database in use is archived in a
    consistent state, with credential tables emptied. The zip is written to a temporary file next to *output*
    and moved into place when complete. Files that cannot be read are left out
    and dropped from the manifest's counts.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    os.close(fd)
    tmp_path = Path(tmp_name)

    skipped: list[tuple[Path, str]] = []
    entries = []
    try:
        with (
            tempfile.TemporaryDirectory() as scratch,
            zipfile.ZipFile(tmp_path, "w") as zf,
        ):
            for selection in selections:
                written: list[Path] = []
                written_bytes = 0
                for path in selection.files:
                    arcname = PurePath(
                        selection.agent.name, path.relative_to(selection.root)
                    ).as_posix()
                    emptied: list[str] = []
                    outcome = _add_file(
                        zf,
                        path,
                        arcname,
                        Path(scratch),
                        emptied,
                        selection.agent.sqlite_redact_tables,
                    )
                    if isinstance(outcome, str):
                        skipped.append((path, outcome))
                        continue
                    if emptied:
                        rel = path.relative_to(selection.root).as_posix()
                        selection.redacted_tables[rel] = emptied
                    written.append(path)
                    written_bytes += outcome
                selection.files = written
                selection.total_bytes = written_bytes
                entries.append(selection.manifest_entry())

            manifest = {**manifest, "agents": entries}
            zf.writestr(
                MANIFEST_NAME,
                json.dumps(manifest, indent=2) + "\n",
                compress_type=zipfile.ZIP_DEFLATED,
            )
        os.replace(tmp_path, output)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    return ArchiveResult(
        path=output,
        file_count=sum(len(s.files) for s in selections),
        total_bytes=sum(s.total_bytes for s in selections),
        skipped=skipped,
    )


def build_manifest(
    *,
    username: str,
    version: str,
    filters: dict,
    created_at: datetime | None = None,
) -> dict:
    """Return the manifest fields known before the archive is written."""
    created_at = created_at or datetime.now(UTC)
    return {
        "created_at": created_at.isoformat(timespec="seconds"),
        "github_username": username,
        "ssec_cli_version": version,
        "filters": filters,
    }
