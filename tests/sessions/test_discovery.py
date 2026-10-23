"""Tests for the session discovery module."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from ssec_cli.sessions.agents import AgentConfig
from ssec_cli.sessions.discovery import discover_agents


def _make_agent(tmp_path: Path, name: str = "test-agent") -> AgentConfig:
    """Return an AgentConfig whose platform paths all point to *tmp_path*."""
    return AgentConfig(
        name=name,
        display_name=name.replace("-", " ").title(),
        default_paths={
            "darwin": tmp_path,
            "linux": tmp_path,
            "win32": tmp_path,
        },
        env_override=f"TEST_{name.upper().replace('-', '_')}_DIR",
    )


def test_discover_existing_agent(fake_session_dir: Path) -> None:
    agent = _make_agent(fake_session_dir)
    found, skipped = discover_agents([agent])
    assert len(found) == 1
    assert found[0].agent is agent
    assert found[0].path == fake_session_dir
    assert skipped == []


def test_skip_missing_agent(tmp_path: Path) -> None:
    agent = _make_agent(tmp_path / "does_not_exist")
    found, skipped = discover_agents([agent])
    assert found == []
    assert len(skipped) == 1
    assert "not found" in skipped[0]


def test_skip_empty_agent(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    found, skipped = discover_agents([_make_agent(empty_dir)])
    assert found == []
    assert "empty" in skipped[0]


def test_skip_path_that_is_a_file(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    found, skipped = discover_agents([_make_agent(not_a_dir)])
    assert found == []
    assert "not found" in skipped[0]


def test_env_override(fake_session_dir: Path, tmp_path: Path) -> None:
    """Env var override takes precedence over the default path."""
    agent = _make_agent(tmp_path / "wrong")

    with patch.dict("os.environ", {agent.env_override: str(fake_session_dir)}):
        found, _ = discover_agents([agent])

    assert len(found) == 1
    assert found[0].path == fake_session_dir


def test_no_platform_path() -> None:
    """Agent with no path for the current platform is skipped gracefully."""
    unsupported_platform = "unsupported_os"
    agent = AgentConfig(
        name="no-path-agent",
        display_name="No Path Agent",
        default_paths={unsupported_platform: Path("~/.no-path-agent")},
        env_override="NO_PATH_AGENT_DIR",
    )
    with patch.object(sys, "platform", unsupported_platform + "_other"):
        found, skipped = discover_agents([agent])

    assert found == []
    assert "no default path" in skipped[0]
