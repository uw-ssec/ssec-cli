"""Tests for matching sessions to a project with --project."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssec_cli.sessions import projects
from ssec_cli.sessions.agents import ALL_AGENTS
from ssec_cli.sessions.projects import ProjectMatcher
from ssec_cli.sessions.selection import select_files
from tests.sessions.conftest import selected_paths, write_jsonl

AGENTS = {a.name: a for a in ALL_AGENTS}


@pytest.mark.parametrize("value", ["/work/alpha", "alpha"])
def test_project_claude_code(claude_root: Path, value: str) -> None:
    selection = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse(value)
    )
    assert selected_paths(selection) == [
        "-work-alpha/s1.jsonl",
        "-work-alpha/s1/subagents/agent-1.jsonl",
    ]


def test_project_claude_code_subdirectory_of_project(claude_root: Path) -> None:

    write_jsonl(
        claude_root / "-work-alpha-sub" / "s3.jsonl", [{"cwd": "/work/alpha/sub"}]
    )
    selection = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse("/work/alpha")
    )
    assert "-work-alpha-sub/s3.jsonl" in selected_paths(selection)

    by_name = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse("alpha")
    )
    assert "-work-alpha-sub/s3.jsonl" not in selected_paths(by_name)


def test_project_claude_code_falls_back_to_directory_name(tmp_path: Path) -> None:
    """A project directory with no recorded cwd is matched by its encoded name."""
    root = tmp_path / "projects"
    project = tmp_path / "my.repo"
    project.mkdir()
    encoded = "".join(c if c.isalnum() else "-" for c in str(project.resolve()))
    (root / encoded).mkdir(parents=True)
    (root / encoded / "s.jsonl").write_text('{"type": "summary"}\n')
    selection = select_files(
        AGENTS["claude-code"], root, project=ProjectMatcher.parse(str(project))
    )
    assert selected_paths(selection) == [f"{encoded}/s.jsonl"]


def test_project_codex(codex_root: Path) -> None:
    selection = select_files(
        AGENTS["codex"], codex_root, project=ProjectMatcher.parse("/work/beta")
    )
    assert selected_paths(selection) == ["2026/10/23/rollout-b.jsonl"]


def test_project_unsupported_agent(fake_session_dir: Path) -> None:
    with pytest.raises(ValueError):
        select_files(
            AGENTS["cursor"], fake_session_dir, project=ProjectMatcher.parse("alpha")
        )


def test_project_matcher_symlinked_path(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    matcher = ProjectMatcher.parse(str(link))
    assert matcher.matches(str(link))
    assert matcher.matches(str(real.resolve()))
    assert not matcher.matches(str(tmp_path / "other"))


@pytest.mark.parametrize("insensitive", [True, False])
def test_project_matching_case(
    monkeypatch: pytest.MonkeyPatch, insensitive: bool
) -> None:
    monkeypatch.setattr(projects, "_CASE_INSENSITIVE_PATHS", insensitive)
    assert (
        ProjectMatcher.parse("/Work/Repos/X").matches("/work/repos/x/sub")
        is insensitive
    )
    assert ProjectMatcher(name="Alpha").matches("/work/alpha") is insensitive
