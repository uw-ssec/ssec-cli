"""Shared fixtures for session archive tests."""

from __future__ import annotations

import json
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


@pytest.fixture()
def codex_root(tmp_path: Path) -> Path:
    """A Codex sessions directory with one rollout each for ``/work/alpha`` and ``/work/beta``."""
    root = tmp_path / "codex-sessions"
    day = root / "2026" / "10" / "23"
    write_jsonl(
        day / "rollout-a.jsonl",
        [
            {"type": "session_meta", "payload": {"cwd": "/work/alpha"}},
            {"type": "event"},
        ],
    )
    write_jsonl(
        day / "rollout-b.jsonl",
        [{"type": "session_meta", "payload": {"cwd": "/work/beta"}}],
    )
    return root
