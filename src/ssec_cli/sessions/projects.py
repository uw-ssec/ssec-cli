"""Match agent sessions to the project (working directory) they were started in."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePath

PROJECT_AGENTS = frozenset({"claude-code", "codex"})
"""Agents that ``--project`` can filter. Other agents are skipped when it is set."""

# How many leading lines of a transcript to scan for the recorded working directory.
_CWD_SCAN_LINES = 50

_CASE_INSENSITIVE_PATHS = sys.platform in ("darwin", "win32")


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


def claude_project_dirs(root: Path, matcher: ProjectMatcher) -> list[Path]:
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


def codex_session_matches(path: Path, matcher: ProjectMatcher) -> bool:
    """True if *path* is a Codex rollout started in *matcher*'s project."""
    if path.suffix != ".jsonl":
        return False
    cwd = _read_cwd(path, _codex_cwd)
    return cwd is not None and matcher.matches(cwd)
