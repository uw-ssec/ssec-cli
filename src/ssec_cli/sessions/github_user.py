"""GitHub username resolution.

Ported from agenthoist (https://github.com/uw-ssec/agenthoist).
"""

from __future__ import annotations

import subprocess

import typer


def resolve_github_username(cli_arg: str | None = None) -> str:
    """Resolve the GitHub username using a priority chain.

    Resolution order:
    1. ``cli_arg`` — explicit value from the CLI ``--username`` flag
    2. ``gh api user --jq .login`` — GitHub CLI (if installed and authenticated)
    3. ``git config --global github.user`` — git global config
    4. Interactive prompt via ``typer.prompt``

    Parameters
    ----------
    cli_arg:
        Explicitly provided username. If non-empty, returned immediately.

    Returns
    -------
    str
        The resolved GitHub username.

    Raises
    ------
    typer.BadParameter
        If all resolution methods fail (prompt returned empty string).
    """
    if cli_arg:
        return cli_arg

    # Try gh CLI
    try:
        result = subprocess.run(
            ["gh", "api", "user", "--jq", ".login"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            username = result.stdout.strip()
            if username:
                return username
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # gh is not installed or did not answer; fall through

    # Try git config
    try:
        result = subprocess.run(
            ["git", "config", "--global", "github.user"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            username = result.stdout.strip()
            if username:
                return username
    except FileNotFoundError:
        pass  # git is not installed; fall through

    # Interactive fallback
    username = str(typer.prompt("GitHub username")).strip()
    if not username:
        raise typer.BadParameter(
            "GitHub username could not be resolved. "
            "Pass --username, authenticate with 'gh auth login', "
            "or set 'git config --global github.user <username>'."
        )
    return username
