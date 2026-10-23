"""Tests for the ``ssec archive-sessions`` command."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ssec_cli.main import app
from ssec_cli.sessions.agents import ALL_AGENTS

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_agents(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, claude_root: Path, codex_root: Path
) -> None:
    """Point every agent at an empty location except Claude Code and Codex."""
    for agent in ALL_AGENTS:
        monkeypatch.setenv(agent.env_override, str(tmp_path / "missing" / agent.name))
    monkeypatch.setenv("CLAUDE_PROJECTS_DIR", str(claude_root))
    monkeypatch.setenv("CODEX_SESSIONS_DIR", str(codex_root))
    monkeypatch.setattr(
        "ssec_cli.sessions.command.resolve_github_username",
        lambda name: name or "octocat",
    )
    monkeypatch.chdir(tmp_path)


def _zip_in(directory: Path) -> Path:
    (archive,) = directory.glob("agent-sessions-octocat-*.zip")
    return archive


def test_archive_all(tmp_path: Path) -> None:
    result = runner.invoke(app, ["archive-sessions"])
    assert result.exit_code == 0, result.output
    assert "Review the archive before you share it" in result.output

    with zipfile.ZipFile(_zip_in(tmp_path)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        top_level = {n.split("/")[0] for n in zf.namelist()}
    assert top_level == {"claude-code", "codex", "manifest.json"}
    assert manifest["filters"]["agents"] == [a.name for a in ALL_AGENTS]


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    result = runner.invoke(app, ["archive-sessions", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Dry run" in result.output
    assert "Claude Code" in result.output
    assert list(tmp_path.glob("*.zip")) == []


def test_agents_filter(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["archive-sessions", "--agents", "codex", "--username", "octocat"]
    )
    assert result.exit_code == 0, result.output

    with zipfile.ZipFile(_zip_in(tmp_path)) as zf:
        names = [n for n in zf.namelist() if n != "manifest.json"]
        manifest = json.loads(zf.read("manifest.json"))
    assert names == [
        "codex/2026/10/23/rollout-a.jsonl",
        "codex/2026/10/23/rollout-b.jsonl",
    ]
    assert manifest["filters"] == {
        "agents": ["codex"],
        "since": None,
        "until": None,
        "jsonl_only": False,
    }


def test_output_directory(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = runner.invoke(app, ["archive-sessions", "--output", str(out_dir)])
    assert result.exit_code == 0, result.output
    _zip_in(out_dir)


def test_output_file_must_not_exist(tmp_path: Path) -> None:
    existing = tmp_path / "taken.zip"
    existing.write_text("keep me")
    result = runner.invoke(app, ["archive-sessions", "--output", str(existing)])
    assert result.exit_code != 0
    assert "already exists" in result.output
    assert existing.read_text() == "keep me"


def test_unknown_agent() -> None:
    result = runner.invoke(app, ["archive-sessions", "--agents", "nope"])
    assert result.exit_code != 0
    assert "Unknown agent" in result.output


def test_bad_date() -> None:
    result = runner.invoke(app, ["archive-sessions", "--since", "yesterday"])
    assert result.exit_code != 0
    assert "is not a date" in result.output


def test_nothing_matched(tmp_path: Path) -> None:
    result = runner.invoke(app, ["archive-sessions", "--since", "2999-01-01"])
    assert result.exit_code == 0, result.output
    assert "No agent session files matched" in result.output
    assert list(tmp_path.glob("*.zip")) == []


def test_output_directory_is_created(tmp_path: Path) -> None:
    out_dir = tmp_path / "new" / "dir"
    result = runner.invoke(app, ["archive-sessions", "--output", str(out_dir)])
    assert result.exit_code == 0, result.output
    _zip_in(out_dir)
