"""Find developer tools on PATH, their versions and how they were installed."""

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ssec_cli.tools.versions import extract_version

TOOLS_TO_CHECK: tuple[str, ...] = (
    "pixi",
    "uv",
    "pip",
    "conda",
    "sigstore",
    "git",
    "gh",
    "docker",
    "python",
    "code",
    "rg",
)

VERSION_TIMEOUT = 5

_BIN_DIRS = ("bin", "condabin", "Scripts")
_SYSTEM_DIRS = (Path("/usr/bin"), Path("/bin"), Path("/usr/sbin"), Path("/sbin"))


class InstallMethod(str, Enum):
    STANDALONE = "standalone"
    HOMEBREW = "homebrew"
    PIXI_GLOBAL = "pixi-global"
    UV_TOOL = "uv-tool"
    PIPX = "pipx"
    CONDA = "conda"
    VENV = "venv"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class ToolInfo:
    name: str
    path: Path | None
    version: str | None
    method: InstallMethod
    formula: str | None = None
    env_root: Path | None = None


def _is_under(path: Path, roots: Sequence[Path]) -> bool:
    return any(path.is_relative_to(root) for root in roots)


def detect_install_method(
    name: str,
    path: Path,
    home: Path,
    resolve: Callable[[Path], Path] | None = None,
) -> tuple[InstallMethod, str | None, Path | None]:
    """Classify how `path` was installed: (method, homebrew formula, env root)."""
    homes = [home]
    try:
        if home.resolve() != home:
            homes.append(home.resolve())
    except OSError:
        pass

    # pixi global trampolines are not symlinks, so look at the unresolved path.
    if any(path.parent == h / ".pixi" / "bin" for h in homes):
        if name == "pixi":
            return InstallMethod.STANDALONE, None, None
        return InstallMethod.PIXI_GLOBAL, None, None

    # An env's own executables may be symlinks out of the env (e.g. a venv's
    # python), so classify envs on the unresolved prefix first.
    if path.parent.name in _BIN_DIRS:
        env = path.parent.parent
        if (env / "conda-meta").is_dir():
            if _is_under(env, [h / ".pixi" / "envs" for h in homes]):
                return InstallMethod.PIXI_GLOBAL, None, None
            return InstallMethod.CONDA, None, env
        if (env / "pyvenv.cfg").is_file():
            return InstallMethod.VENV, None, env

    try:
        real = resolve(path) if resolve else path.resolve()
    except (OSError, RuntimeError):
        real = path

    parts = real.parts
    if "Cellar" in parts:
        i = parts.index("Cellar")
        if i + 1 < len(parts):
            return InstallMethod.HOMEBREW, parts[i + 1], None

    if _is_under(real, [h / ".local" / "share" / "uv" / "tools" for h in homes]):
        return InstallMethod.UV_TOOL, None, None
    if _is_under(
        real,
        [h / ".local" / "pipx" / "venvs" for h in homes]
        + [h / ".local" / "share" / "pipx" / "venvs" for h in homes],
    ):
        return InstallMethod.PIPX, None, None
    if _is_under(real, [h / ".pixi" / "envs" for h in homes]):
        return InstallMethod.PIXI_GLOBAL, None, None

    if real.parent.name in _BIN_DIRS:
        prefix = real.parent.parent
        if (prefix / "conda-meta").is_dir():
            return InstallMethod.CONDA, None, prefix
        if (prefix / "pyvenv.cfg").is_file():
            return InstallMethod.VENV, None, prefix

    if real.name == "uv" and any(
        real.parent in (h / ".local" / "bin", h / ".cargo" / "bin") for h in homes
    ):
        return InstallMethod.STANDALONE, None, None

    if real.parent in _SYSTEM_DIRS or path.parent in _SYSTEM_DIRS:
        return InstallMethod.SYSTEM, None, None
    return InstallMethod.UNKNOWN, None, None


def tool_version(path: Path) -> str | None:
    """Run `<path> --version` and extract the version, or None on any failure."""
    try:
        proc = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=VERSION_TIMEOUT,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    return extract_version(f"{proc.stdout}\n{proc.stderr}")


def scan_path_tools(
    home: Path, names: Sequence[str] = TOOLS_TO_CHECK
) -> list[ToolInfo]:
    """Look up each name on PATH; `path` is None when not found."""
    tools: list[ToolInfo] = []
    for name in names:
        found = shutil.which(name)
        if not found:
            tools.append(ToolInfo(name, None, None, InstallMethod.UNKNOWN))
            continue
        path = Path(found)
        method, formula, env_root = detect_install_method(name, path, home)
        tools.append(
            ToolInfo(name, path, tool_version(path), method, formula, env_root)
        )
    return tools
