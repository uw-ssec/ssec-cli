"""Compare discovered tools, environments and pins with the advisory minimums.

Every item gets a `Finding`. UNKNOWN is used whenever the truth cannot be
established: it is never reported as fine.
"""

import shlex
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from ssec_cli.tools.advisories import (
    Advisory,
    PackageMinimum,
    load_advisories,
    minimums_by_package,
    normalize_name,
)
from ssec_cli.tools.environments import (
    EnvKind,
    PythonEnv,
    discover_environments,
    python_executable,
)
from ssec_cli.tools.finder import rg_available
from ssec_cli.tools.lockfiles import LockPin, scan_lockfiles
from ssec_cli.tools.path_tools import InstallMethod, ToolInfo, scan_path_tools
from ssec_cli.tools.versions import is_below

_PIP_KINDS = (EnvKind.PLAIN_VENV, EnvKind.FRAMEWORK, EnvKind.PYENV, EnvKind.UV_PYTHON)
_CONDA_LIKE = (EnvKind.CONDA, EnvKind.PIXI_PROJECT, EnvKind.PIXI_GLOBAL)
_PIP_MIN_PYTHON = (3, 10)
_CONDA_BINS = ("condabin/conda", "bin/conda", "Scripts/conda.exe")


class Status(str, Enum):
    OK = "ok"
    OUTDATED = "outdated"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"  # not produced in release 1


@dataclass
class Finding:
    category: Literal["tool", "environment", "lockfile"]
    item: str
    location: Path | None
    current: str | None
    minimum: str | None
    status: Status
    advisory_id: str | None = None
    fix: str | None = None
    note: str | None = None
    env_kind: EnvKind | None = None
    install_method: InstallMethod | None = None
    formula: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding]
    advisories: list[Advisory]
    used_rg: bool


def _q(path: object) -> str:
    return shlex.quote(str(path))


def _py_mm(version: str | None) -> tuple[int, int] | None:
    if not version:
        return None
    parts = version.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------- tools


def _tool_fix(t: ToolInfo) -> tuple[str | None, str | None]:
    name = t.name
    m = t.method
    if name == "pip" and m in (InstallMethod.VENV, InstallMethod.CONDA):
        return None, "see Python environments"
    if m is InstallMethod.STANDALONE and name == "pixi":
        return "pixi self-update", None
    if m is InstallMethod.STANDALONE and name == "uv":
        return "UV_SYSTEM_CERTS=true uv self update", None
    if m is InstallMethod.HOMEBREW:
        return f"brew upgrade {t.formula or name}", None
    if m is InstallMethod.PIXI_GLOBAL:
        return f"pixi global update {name}", None
    if m is InstallMethod.UV_TOOL:
        return f"uv tool upgrade {name}", None
    if m is InstallMethod.PIPX:
        return f"pipx upgrade {name}", None
    if m is InstallMethod.CONDA and name == "conda":
        return "conda update -n base conda", None
    return None, f"update {name} with the tool that installed it"


def evaluate_tool(t: ToolInfo, mins: dict[str, PackageMinimum]) -> Finding:
    mn = mins.get(normalize_name(t.name))
    base = {
        "category": "tool",
        "item": t.name,
        "location": t.path,
        "current": t.version,
        "minimum": mn.min_version if mn else None,
        "advisory_id": mn.advisory_id if mn else None,
        "install_method": t.method,
        "formula": t.formula,
    }
    if t.path is None:
        return Finding(
            **{**base, "current": None, "location": None}, status=Status.NOT_INSTALLED
        )  # type: ignore[arg-type]
    if mn is None:
        return Finding(**base, status=Status.OK, note="no advisory")  # type: ignore[arg-type]
    if t.version is None:
        return Finding(**base, status=Status.UNKNOWN, note="could not read version")  # type: ignore[arg-type]
    below = is_below(t.version, mn.min_version)
    if below is None:
        return Finding(**base, status=Status.UNKNOWN, note="could not read version")  # type: ignore[arg-type]
    if not below:
        return Finding(**base, status=Status.OK)  # type: ignore[arg-type]
    fix, note = _tool_fix(t)
    return Finding(**base, status=Status.OUTDATED, fix=fix, note=note)  # type: ignore[arg-type]


# --------------------------------------------------------- environments


def _pip_commands(
    env: PythonEnv, pkg: str, mn: PackageMinimum, pip_mn: PackageMinimum | None
) -> tuple[str | None, str | None]:
    """Fix and note for upgrading `pkg` with pip / uv pip in a plain env."""
    py = _q(python_executable(env))
    mm = _py_mm(env.python_version)
    old_python = mm is not None and mm < _PIP_MIN_PYTHON
    pip_min = (pip_mn or mn).min_version
    recreate = f"pip {pip_min} needs Python 3.10+; recreate this environment"
    if pkg == "pip":
        src = pip_mn or mn
        if not (src.fix_url and src.fix_sha256):
            return None, "advisory has no pinned pip URL"
        fix = f'{py} -m pip install "pip @ {src.fix_url}#sha256={src.fix_sha256}"'
        if mm is None:
            return fix, (
                f"could not determine Python version; pip {pip_min} needs Python 3.10+"
            )
        return (None, recreate) if old_python else (fix, None)
    req = f'"{pkg}>={mn.min_version}"'
    if env.packages is not None and "pip" in env.packages:
        if old_python:
            return None, recreate
        return f"{py} -m pip install --upgrade {req}", "upgrade pip first"
    return f"uv pip install --python {py} {req}", None


def _conda_selector(path: Path) -> str:
    if path.parent.name == "envs":
        return f"-n {shlex.quote(path.name)}"
    if any((path / rel).exists() for rel in _CONDA_BINS):
        return "-n base"
    return f"-p {_q(path)}"


def _env_fix(
    env: PythonEnv, pkg: str, mn: PackageMinimum, mins: dict[str, PackageMinimum]
) -> tuple[str | None, str | None]:
    kind = env.kind
    if kind in _PIP_KINDS:
        return _pip_commands(env, pkg, mn, mins.get("pip"))
    if kind is EnvKind.UV_PROJECT:
        if env.project is None:
            return None, "managed by uv; pip changes would be undone by uv sync"
        return (
            f"cd {_q(env.project)} && uv lock --upgrade-package {pkg} && uv sync",
            "managed by uv; pip changes would be undone by uv sync",
        )
    if kind in (EnvKind.UV_TOOL, EnvKind.PIPX):
        if env.tool_name is None:
            return None, "could not determine tool name"
        cmd = "uv tool upgrade" if kind is EnvKind.UV_TOOL else "pipx upgrade"
        return f"{cmd} {shlex.quote(env.tool_name)}", None
    if kind is EnvKind.PIXI_PROJECT:
        if env.project is None:
            return None, "managed by pixi"
        return (
            f"cd {_q(env.project)} && pixi update certifi ca-certificates pip",
            "managed by pixi",
        )
    if kind is EnvKind.PIXI_GLOBAL:
        if env.tool_name is None:
            return None, "could not determine tool name"
        return f"pixi global update {shlex.quote(env.tool_name)}", None
    if kind is EnvKind.CONDA:
        if pkg in env.conda_packages:
            return f"conda update {_conda_selector(env.path)} {pkg}", None
        fix, note = _pip_commands(env, pkg, mn, mins.get("pip"))
        extra = "env mixes pip and conda packages"
        return fix, f"{note}; {extra}" if note else extra
    if kind is EnvKind.HOMEBREW:
        mm = _py_mm(env.python_version)
        fix = f"brew upgrade python@{mm[0]}.{mm[1]}" if mm else None
        return fix, "managed by Homebrew"
    return None, "system Python; leave to the OS package manager"


def evaluate_env(e: PythonEnv, mins: dict[str, PackageMinimum]) -> list[Finding]:
    watched = ["pip", "certifi"]
    if e.kind in _CONDA_LIKE:
        watched.append("ca-certificates")
    out: list[Finding] = []
    for pkg in watched:
        mn = mins.get(pkg)
        cur = e.packages.get(pkg) if e.packages is not None else None
        base = {
            "category": "environment",
            "item": pkg,
            "location": e.path,
            "current": cur,
            "minimum": mn.min_version if mn else None,
            "advisory_id": mn.advisory_id if mn else None,
            "env_kind": e.kind,
        }
        if mn is None:
            out.append(Finding(**base, status=Status.OK, note="no advisory"))  # type: ignore[arg-type]
            continue
        if e.packages is None:
            out.append(
                Finding(
                    **base,
                    status=Status.UNKNOWN,
                    note="could not read package metadata",
                )
            )  # type: ignore[arg-type]
            continue
        if cur is None:
            out.append(Finding(**base, status=Status.NOT_INSTALLED))  # type: ignore[arg-type]
            continue
        below = is_below(cur, mn.min_version)
        if below is None:
            out.append(
                Finding(
                    **base,
                    status=Status.UNKNOWN,
                    note="could not read package metadata",
                )
            )  # type: ignore[arg-type]
        elif not below:
            out.append(Finding(**base, status=Status.OK))  # type: ignore[arg-type]
        else:
            fix, note = _env_fix(e, pkg, mn, mins)
            out.append(Finding(**base, status=Status.OUTDATED, fix=fix, note=note))  # type: ignore[arg-type]
    return out


# ------------------------------------------------------------ lockfiles


def evaluate_lockpin(p: LockPin, mins: dict[str, PackageMinimum]) -> Finding:
    mn = mins.get(normalize_name(p.package)) if p.package else None
    base = {
        "category": "lockfile",
        "item": p.package or p.lockfile.name,
        "location": p.lockfile,
        "current": p.version,
        "minimum": mn.min_version if mn else None,
        "advisory_id": mn.advisory_id if mn else None,
    }
    if p.error is not None:
        return Finding(**base, status=Status.UNKNOWN, note=p.error)  # type: ignore[arg-type]
    if mn is None:
        return Finding(**base, status=Status.OK, note="no advisory")  # type: ignore[arg-type]
    below = is_below(p.version, mn.min_version) if p.version else None
    if below is None:
        return Finding(
            **base, status=Status.UNKNOWN, note="could not read package metadata"
        )  # type: ignore[arg-type]
    if not below:
        return Finding(**base, status=Status.OK)  # type: ignore[arg-type]
    cd = f"cd {_q(p.lockfile.parent)} && "
    name = p.lockfile.name
    pkg = shlex.quote(p.package)
    if name == "pixi.lock":
        fix, note = f"{cd}pixi update {pkg}", None
    elif name == "uv.lock":
        fix, note = f"{cd}uv lock --upgrade-package {pkg}", None
    elif name == "poetry.lock":
        fix, note = f"{cd}poetry update {pkg}", None
    else:
        fix, note = None, "edit the pin"
    return Finding(**base, status=Status.OUTDATED, fix=fix, note=note)  # type: ignore[arg-type]


# ----------------------------------------------------------------- scan


def _guarded(fn, item, category, location, **extra):  # noqa: ANN001, ANN202
    try:
        res = fn()
        return res if isinstance(res, list) else [res]
    except Exception as exc:  # noqa: BLE001 - one bad item must not stop the scan
        return [
            Finding(
                category=category,
                item=item,
                location=location,
                current=None,
                minimum=None,
                status=Status.UNKNOWN,
                note=f"internal error: {exc!r}",
                **extra,
            )
        ]


def scan(home: Path, project: Path, *, full: bool = True) -> ScanResult:
    advisories = load_advisories()
    mins = minimums_by_package(advisories)
    if full:
        envs = discover_environments(home, extra_roots=[project])
    else:
        envs = discover_environments(
            home,
            extra_roots=[project],
            include_path_interpreters=False,
            search_home=False,
        )
    tools = scan_path_tools(home)
    pins = scan_lockfiles(project, recursive=full)

    findings: list[Finding] = []
    for t in tools:
        findings += _guarded(
            lambda t=t: evaluate_tool(t, mins),
            getattr(t, "name", "?"),
            "tool",
            getattr(t, "path", None),
        )
    for e in envs:
        findings += _guarded(
            lambda e=e: evaluate_env(e, mins),
            "python environment",
            "environment",
            getattr(e, "path", None),
            env_kind=getattr(e, "kind", None),
        )
    for p in pins:
        findings += _guarded(
            lambda p=p: evaluate_lockpin(p, mins),
            getattr(p, "package", "") or "lockfile",
            "lockfile",
            getattr(p, "lockfile", None),
        )
    return ScanResult(findings=findings, advisories=advisories, used_rg=rg_available())
