"""Tests for agent definitions."""

from __future__ import annotations

from ssec_cli.sessions.agents import ALL_AGENTS


def test_all_agents_count() -> None:
    assert len(ALL_AGENTS) == 18


def test_agent_names_unique() -> None:
    names = [a.name for a in ALL_AGENTS]
    assert len(names) == len(set(names)), "Duplicate agent names found"


def test_agent_env_overrides_unique() -> None:
    overrides = [a.env_override for a in ALL_AGENTS]
    assert len(overrides) == len(set(overrides)), "Duplicate env_override values found"


def test_platform_paths_defined() -> None:
    for agent in ALL_AGENTS:
        assert "darwin" in agent.default_paths, f"{agent.name!r} missing 'darwin' path"
        assert "linux" in agent.default_paths, f"{agent.name!r} missing 'linux' path"
