"""Write selected session files to a zip archive with a manifest."""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath

from ssec_cli.sessions.selection import AgentSelection

MANIFEST_NAME = "manifest.json"

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

_SQLITE_MAGIC = b"SQLite format 3\x00"


class ArchiveError(Exception):
    """Writing the archive failed and nothing was written."""


@dataclass
class ArchiveResult:
    path: Path
    file_count: int
    total_bytes: int
    skipped: list[tuple[Path, str]]
    """Files left out while writing, with the reason."""


def _is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(_SQLITE_MAGIC)) == _SQLITE_MAGIC
    except OSError:
        return False


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
    consistent state, with credential tables emptied. The zip is written to a
    temporary file next to *output* and moved into place when complete. Files
    that cannot be read are left out and dropped from the manifest's counts.
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
