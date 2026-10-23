"""Tests for GitHub username resolution."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import typer

from ssec_cli.sessions.github_user import resolve_github_username


def test_cli_arg_takes_precedence() -> None:
    result = resolve_github_username("myuser")
    assert result == "myuser"


def test_gh_cli_fallback() -> None:
    mock_result = SimpleNamespace(returncode=0, stdout="ghuser\n")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        result = resolve_github_username()
    assert result == "ghuser"
    mock_run.assert_called_once()
    call_args = mock_run.call_args[0][0]
    assert call_args[0] == "gh"


def test_git_config_fallback() -> None:
    """gh fails, git config succeeds."""

    def side_effect(cmd, **_kwargs):  # type: ignore[no-untyped-def]
        if cmd[0] == "gh":
            return SimpleNamespace(returncode=1, stdout="")
        # git config
        return SimpleNamespace(returncode=0, stdout="gituser\n")

    with patch("subprocess.run", side_effect=side_effect):
        result = resolve_github_username()

    assert result == "gituser"


def test_gh_not_installed_falls_through_to_git() -> None:
    """gh raises FileNotFoundError; git config succeeds."""

    def side_effect(cmd, **_kwargs):  # type: ignore[no-untyped-def]
        if cmd[0] == "gh":
            raise FileNotFoundError
        return SimpleNamespace(returncode=0, stdout="gituser2\n")

    with patch("subprocess.run", side_effect=side_effect):
        result = resolve_github_username()

    assert result == "gituser2"


def test_all_fail_prompts() -> None:
    """All auto-detection methods fail; typer.prompt is called."""
    failing = SimpleNamespace(returncode=1, stdout="")

    with (
        patch("subprocess.run", return_value=failing),
        patch("typer.prompt", return_value="promptuser") as mock_prompt,
    ):
        result = resolve_github_username()

    assert result == "promptuser"
    mock_prompt.assert_called_once()


def test_prompt_empty_raises() -> None:
    """If prompt returns empty string, BadParameter is raised."""
    failing = SimpleNamespace(returncode=1, stdout="")

    with (
        patch("subprocess.run", return_value=failing),
        patch("typer.prompt", return_value=""),
        pytest.raises(typer.BadParameter),
    ):
        resolve_github_username()
