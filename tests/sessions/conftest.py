"""Shared fixtures for session archive tests."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest


@pytest.fixture()
def fake_session_dir(tmp_path: Path) -> Path:
    """Create a temporary directory tree mimicking an agent session directory."""
    session = tmp_path / "sessions"
    (session / "proj1").mkdir(parents=True)
    (session / "proj1" / "conversation.json").write_text('{"messages": []}')
    (session / "proj1" / "metadata.json").write_text('{"version": 1}')
    (session / "proj2").mkdir()
    (session / "proj2" / "conversation.json").write_text('{"messages": ["hello"]}')
    return session


def write_jsonl(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def selected_paths(selection) -> list[str]:  # type: ignore[no-untyped-def]
    """Return a selection's files relative to its root, sorted."""
    return sorted(p.relative_to(selection.root).as_posix() for p in selection.files)


def set_mtime(path: Path, when: datetime) -> None:
    ts = when.timestamp()
    os.utime(path, (ts, ts))


def make_wal_db(path: Path) -> sqlite3.Connection:
    """Create a WAL-mode database with an uncheckpointed row, left open."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES ('in-wal')")
    conn.commit()
    return conn


@pytest.fixture()
def claude_root(tmp_path: Path) -> Path:
    """A Claude Code projects directory with two projects.

    ``/work/alpha`` has a transcript and a subagent transcript. ``/work/beta`` has
    one transcript.
    """
    root = tmp_path / "claude-projects"
    alpha = root / "-work-alpha"
    write_jsonl(
        alpha / "s1.jsonl",
        [{"type": "summary", "summary": "x"}, {"type": "user", "cwd": "/work/alpha"}],
    )
    write_jsonl(alpha / "s1" / "subagents" / "agent-1.jsonl", [{"type": "user"}])
    write_jsonl(
        root / "-work-beta" / "s2.jsonl", [{"type": "user", "cwd": "/work/beta"}]
    )
    return root
