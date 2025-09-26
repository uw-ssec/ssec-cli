"""SSEC CLI - A CLI tool built with typer."""

import json
from datetime import datetime
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Tuple
import typer
from rich import print

app = typer.Typer(
    name="ssec-cli",
    help="A CLI tool built with typer",
    add_completion=True,
)
# console = Console()


def get_tool_version(tool_path: str) -> str:
    """
    Get the version of a tool by running common version commands.

    Args:
        tool_path: Path to the tool executable

    Returns:
        Version string or "Unknown version" if unable to determine
    """
    version_commands = [
        ["--version"],
        ["-v"],
        ["-V"],
        ["version"],
    ]

    for cmd_args in version_commands:
        try:
            result = subprocess.run(
                [tool_path] + cmd_args, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # Get first line and clean it up
                version_line = result.stdout.strip().split("\n")[0]
                return version_line
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ):
            continue

    return "Unknown version"


def is_tool_installed(tool_name: str) -> Tuple[bool, str]:
    """
    Check if a tool is installed on the system using shutil.which().

    Args:
        tool_name: Name of the tool to check (e.g., 'gh', 'docker')

    Returns:
        Tuple of (is_installed: bool, path_and_version_or_error: str)
    """
    tool_path = shutil.which(tool_name)
    if tool_path:
        version = get_tool_version(tool_path)
        return True, f"{tool_path} ({version})"
    return False, f"Tool '{tool_name}' not found in PATH"


@app.command(help="Install VSCode extensions from .vscode/extensions.json")
def install_vscode_extensions(
    repo_root: Path = typer.Argument(..., help="The name to greet"),
) -> None:
    # iterate over all entries in .vscode/extensions.json and install them
    extensions_file = repo_root / ".vscode" / "extensions.json"
    if not extensions_file.exists():
        print(f"No extensions file found at {extensions_file}")
        return

    with open(extensions_file, encoding="utf-8") as f:
        data = json.load(f)
    extensions = data.get("recommendations", [])
    for ext in extensions:
        result = None
        try:
            result = subprocess.run(
                ["code", "--install-extension", ext], check=True, stdout=subprocess.PIPE
            )
            print(f"[green] Installed extension: {ext}")
        except subprocess.CalledProcessError as e:
            print(
                f"[red] Failed to install extension {ext}: {e} {result.stdout.decode('utf-8') if result else ''}"
            )


@app.command(help="Run diagnostics on the current environment")
def diagnostics():
    """Run diagnostics on the current environment."""

    print_platform_info()
    check_tools()
    get_git_status()
    get_gh_auth_status()


def get_gh_auth_status():
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        auth_output = result.stdout.strip()
        if auth_output:
            print("\n[bold]## GitHub CLI Auth Status:[/bold]")
            print("```sh")
            print(auth_output)
            print("```")
        else:
            print("\n[bold]## GitHub CLI Auth Status:[/bold] Not authenticated.")
    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        FileNotFoundError,
    ) as e:
        print(
            f"\n[bold]## GitHub CLI Auth Status:[/bold] Unable to retrieve auth status: {e}"
        )


def print_platform_info():
    # System information
    print("[bold]## Platform [/bold]")
    print("```sh")
    print(f"Operating System: {platform.system()}")
    print(f"OS Version: {platform.release()}")
    print(f"OS Version (detailed): {platform.version()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {sys.version}")
    print("```")


def get_git_status():
    try:
        result = subprocess.run(
            ["git", "status"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        status_output = result.stdout.strip()
        if status_output:
            print("\n[bold]## Git Status:[/bold]")
            print("```sh")
            print(status_output)
            print("```")
        else:
            print("\n[bold]## Git Status:[/bold] Clean working directory.")
    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        FileNotFoundError,
    ) as e:
        print(f"\n[bold]## Git Status:[/bold] Unable to retrieve git status: {e}")


def check_tools():
    # Check for required tools
    tools_to_check = [
        "git",
        "gh",
        # "gitkraken",
        "docker",
        "python",
        "pip",
        "uv",
        "pixi",
        "code",
    ]

    print("\n[bold]## Tool availability:[/bold]")
    for tool in tools_to_check:
        is_installed, path_or_error = is_tool_installed(tool)
        if is_installed:
            print(f"- ✅ {tool}: {path_or_error}")
        else:
            print(f"- ❌ {tool}: {path_or_error}")


@app.command(help="Onboard in the current directory")
def onboard():
    cwd = Path.cwd()
    print("Onboarding in", cwd)
    install_vscode_extensions(cwd)
    onboard_file = cwd / "onboarded.md"
    with open(onboard_file, "a", encoding="utf-8") as f:
        # git github user:
        user = subprocess.run(
            "git config --get user.name".split(),
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        # get current commit id of HEAD
        commit = subprocess.run(
            "git rev-parse --short HEAD".split(),
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"- User {user} onboarded at commit {commit} on {timestamp}\n")
    print(
        f"[green]Onboarding complete! See {onboard_file} and create a pull-request with the changes."
    )


if __name__ == "__main__":
    app()
