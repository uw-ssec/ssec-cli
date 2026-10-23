"""Shared fixtures for session archive tests."""

from __future__ import annotations

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
