"""Discover Python environments on the machine and classify them.

Everything is read from metadata on disk (`pyvenv.cfg`, `*.dist-info`,
`conda-meta/*.json`). An environment's own Python is never executed; the only
interpreters run are `python`/`python3` on PATH that are not inside a
discovered environment.
"""

import glob
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ssec_cli.tools.advisories import normalize_name
from ssec_cli.tools.finder import find_files
from ssec_cli.tools.versions import extract_version, parse_version

MARKERS = ["**/pyvenv.cfg", "**/conda-meta/history"]

_SYSTEM_PLACES: tuple[str, ...] = (
    "/Library/Frameworks/Python.framework/Versions/*",
    "/opt/homebrew/opt/python@*/Frameworks/Python.framework/Versions/*",
    "/usr/local/opt/python@*/Frameworks/Python.framework/Versions/*",
)
_HOME_PLACES: tuple[str, ...] = (".pyenv/versions/*", ".local/share/uv/python/*")
# Poetry keeps its venvs in cache dirs that the marker search excludes.
_POETRY_PLACES: tuple[str, ...] = (
    "Library/Caches/pypoetry/virtualenvs/*",
    ".cache/pypoetry/virtualenvs/*",
)
_HOMEBREW_PREFIXES = ("/opt/homebrew", "/usr/local/Cellar", "/usr/local/opt")
_SYSTEM_PREFIXES = ("/usr", "/System", "/Library/Developer")

_PROBE = (
    "import sys,sysconfig,json;"
    "print(json.dumps({'prefix':sys.prefix,"
    "'purelib':sysconfig.get_paths()['purelib'],"
    "'platlib':sysconfig.get_paths()['platlib'],"
    "'usersite':__import__('site').getusersitepackages(),"
    "'stdlib':sysconfig.get_paths()['stdlib'],"
    "'version':'%d.%d.%d'%sys.version_info[:3]}))"
)


class EnvKind(str, Enum):
    PLAIN_VENV = "plain_venv"
    UV_PROJECT = "uv_project"
    UV_TOOL = "uv_tool"
    PIPX = "pipx"
    PIXI_PROJECT = "pixi_project"
    PIXI_GLOBAL = "pixi_global"
    CONDA = "conda"
    FRAMEWORK = "framework"
    PYENV = "pyenv"
    UV_PYTHON = "uv_python"
    HOMEBREW = "homebrew"
    SYSTEM = "system"


@dataclass
class PythonEnv:
    path: Path
    kind: EnvKind
    python_version: str | None
    # normalized name -> version; None means the metadata could not be read
    packages: dict[str, str] | None
    conda_packages: set[str] = field(default_factory=set)
    project: Path | None = None
    tool_name: str | None = None
    externally_managed: bool = False


def _under(path: Path, prefixes: Iterable[str]) -> bool:
    s = str(path)
    return any(s == p or s.startswith(p + "/") for p in prefixes)


def _cfg(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = (path / "pyvenv.cfg").read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip().lower()] = value.strip()
    return out


def classify_env(path: Path, home: Path) -> EnvKind:
    parent, grand = path.parent, path.parent.parent
    if parent.name == "envs" and grand.name == ".pixi":
        return EnvKind.PIXI_GLOBAL if grand.parent == home else EnvKind.PIXI_PROJECT
    if parent.name == "solve-group-envs" and grand.name == ".pixi":
        return EnvKind.PIXI_PROJECT
    # A conda install is conda wherever it lives (e.g. pyenv's miniforge3-*).
    if (path / "conda-meta").is_dir():
        return EnvKind.CONDA
    if parent.name == "tools" and grand.name == "uv":
        return EnvKind.UV_TOOL
    if parent.name == "venvs" and grand.name == "pipx":
        return EnvKind.PIPX
    if parent.name == "python" and grand.name == "uv":
        return EnvKind.UV_PYTHON
    if ".pyenv" in path.parts and "versions" in path.parts:
        return EnvKind.PYENV
    if (path / "pyvenv.cfg").is_file():
        # `uv sync` only manages `.venv`; any other uv-made venv is plain.
        if (
            path.name == ".venv"
            and "uv" in _cfg(path)
            and (parent / "uv.lock").is_file()
        ):
            return EnvKind.UV_PROJECT
        return EnvKind.PLAIN_VENV
    if _under(path, _HOMEBREW_PREFIXES):
        return EnvKind.HOMEBREW
    if "Python.framework" in path.parts:
        return EnvKind.FRAMEWORK
    if _under(path, _SYSTEM_PREFIXES):
        return EnvKind.SYSTEM
    return EnvKind.PLAIN_VENV


def _site_dirs(path: Path) -> list[Path]:
    dirs = []
    for lib in ("lib", "lib64"):
        dirs += [
            Path(p) for p in glob.glob(str(path / lib / "python*" / "site-packages"))
        ]
    win = path / "Lib" / "site-packages"
    if win.is_dir():
        dirs.append(win)
    return sorted(d for d in dirs if d.is_dir())


def _lower(a: str, b: str) -> str:
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return a
    return a if pa[0] <= pb[0] else b


def _scan_site_dirs(dirs: Iterable[Path]) -> dict[str, str]:
    """Read name->version from dist-info/egg-info dir names.

    If a name shows up twice, keep the lower version so a stale copy is
    never hidden behind a newer one. Raises OSError if a dir is unreadable.
    """
    found: dict[str, str] = {}
    for d in dirs:
        # OSError propagates: an unreadable dir must not look like "empty".
        for entry in os.listdir(d):
            stem, ext = os.path.splitext(entry)
            if ext not in (".dist-info", ".egg-info"):
                continue
            name, sep, rest = stem.partition("-")
            version = rest.split("-")[0]
            if not sep or not name or not version:
                continue
            key = normalize_name(name)
            found[key] = _lower(found[key], version) if key in found else version
    return found


_WATCHED_PREFIXES = ("pip-", "certifi-", "ca-certificates-")


def _read_conda_meta(path: Path) -> tuple[dict[str, str], str | None] | None:
    """Return (name->version, python version), or None if there is no conda-meta.

    Raises OSError/ValueError if conda-meta is unreadable or a file for a
    watched package is corrupt; other corrupt entries are skipped.
    """
    meta = path / "conda-meta"
    if not meta.is_dir():
        return None
    out: dict[str, str] = {}
    py: str | None = None
    for entry in sorted(os.listdir(meta)):
        if not entry.endswith(".json"):
            continue
        watched = entry.startswith(_WATCHED_PREFIXES)
        try:
            data = json.loads((meta / entry).read_text())
            name, version = str(data["name"]), str(data["version"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            if watched:
                if isinstance(e, (KeyError, TypeError)):
                    raise ValueError(f"bad conda-meta file {entry}") from e
                raise
            continue
        out[normalize_name(name)] = version
        if name == "python":
            py = version
    return out, py


def read_env_packages(path: Path) -> tuple[dict[str, str] | None, set[str]]:
    """Return (packages, conda_packages).

    packages is None when no metadata could be read, and {} when the
    environment is readable but empty. dist-info wins over conda-meta, since
    that is what Python imports (pip may have replaced a conda package).
    """
    try:
        conda = _read_conda_meta(path)
        sites = _site_dirs(path)
        if conda is None and not sites:
            return None, set()
        packages = dict(conda[0]) if conda else {}
        packages.update(_scan_site_dirs(sites))
    except (OSError, ValueError):
        return None, set()
    return packages, set(conda[0]) if conda else set()


def _externally_managed(path: Path) -> bool:
    """True if the env's stdlib dir carries a PEP 668 EXTERNALLY-MANAGED marker.

    pip ignores the marker inside a virtual environment, so venvs never count.
    """
    if (path / "pyvenv.cfg").is_file():
        return False
    patterns = [
        path / "lib" / "python*" / "EXTERNALLY-MANAGED",
        path / "lib64" / "python*" / "EXTERNALLY-MANAGED",
        path / "Lib" / "EXTERNALLY-MANAGED",
    ]
    return any(glob.glob(str(p)) for p in patterns)


def _version_from_dirname(path: Path) -> str | None:
    m = re.search(r"\d+(?:\.\d+)+", path.name)
    return m.group(0) if m else None


def _python_version(path: Path) -> str | None:
    cfg = _cfg(path)
    for key in ("version", "version_info"):
        if key in cfg and (v := extract_version(cfg[key])):
            return v
    try:
        conda = _read_conda_meta(path)
    except (OSError, ValueError):
        conda = None
    if conda and conda[1]:
        return conda[1]
    libs = sorted(glob.glob(str(path / "lib" / "python[0-9]*")))
    for lib in libs:
        if v := extract_version(Path(lib).name):
            return v
    return _version_from_dirname(path)


def _build_env(path: Path, home: Path) -> PythonEnv:
    kind = classify_env(path, home)
    packages, conda_pkgs = read_env_packages(path)
    project: Path | None = None
    tool_name: str | None = None
    if kind == EnvKind.PIXI_PROJECT:
        project = path.parent.parent.parent
    elif kind == EnvKind.UV_PROJECT:
        project = path.parent
    elif kind in (EnvKind.UV_TOOL, EnvKind.PIPX, EnvKind.PIXI_GLOBAL):
        tool_name = path.name
    return PythonEnv(
        path=path,
        kind=kind,
        python_version=_python_version(path),
        packages=packages,
        conda_packages=conda_pkgs,
        project=project,
        tool_name=tool_name,
        externally_managed=_externally_managed(path),
    )


def python_executable(env: PythonEnv) -> Path:
    """Path of the environment's interpreter (may not exist for broken envs)."""
    root = env.path
    for rel in ("bin/python", "Scripts/python.exe", "python.exe", "bin/python3"):
        if (root / rel).exists():
            return root / rel
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _known_places(home: Path) -> list[Path]:
    patterns = [str(home / p) for p in _HOME_PLACES] + list(_SYSTEM_PLACES)
    out: list[Path] = []
    for pattern in patterns:
        for hit in sorted(glob.glob(pattern)):
            p = Path(hit)
            if p.name != "Current" and p.is_dir():
                out.append(p)
    venv_patterns = [str(home / p) for p in _POETRY_PLACES]
    if poetry := os.environ.get("POETRY_VIRTUALENVS_PATH"):
        venv_patterns.append(str(Path(poetry).expanduser() / "*"))
    for pattern in venv_patterns:
        for hit in sorted(glob.glob(pattern)):
            p = Path(hit)
            if (p / "pyvenv.cfg").is_file():
                out.append(p)
    return out


def _conda_env_list() -> list[Path]:
    if shutil.which("conda") is None:
        return []
    try:
        proc = subprocess.run(
            ["conda", "env", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        envs = json.loads(proc.stdout).get("envs", [])
    except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
        return []
    return [Path(e) for e in envs if isinstance(e, str) and Path(e).is_dir()]


def _marker_roots(markers: Sequence[Path]) -> list[Path]:
    roots = []
    for m in markers:
        # <env>/pyvenv.cfg or <env>/conda-meta/history
        roots.append(m.parent.parent if m.name == "history" else m.parent)
    return roots


def _path_executables() -> list[Path]:
    seen: list[Path] = []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        for name in ("python3", "python"):
            hit = shutil.which(name, path=d)
            if hit and Path(hit) not in seen:
                seen.append(Path(hit))
    return seen


def _probe_interpreter(exe: Path, home: Path) -> PythonEnv | None:
    try:
        proc = subprocess.run(
            [str(exe), "-I", "-c", _PROBE],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        info = json.loads(proc.stdout)
        prefix = Path(info["prefix"])
        purelib, stdlib = Path(info["purelib"]), Path(info["stdlib"])
        version = str(info["version"])
    except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, TypeError):
        # Can't ask it; still report the install so it is shown as UNKNOWN.
        real = exe.resolve()
        base = (
            real.parent.parent
            if real.parent.name in ("bin", "Scripts")
            else real.parent
        )
        return PythonEnv(base, classify_env(base, home), None, None)
    managed = (stdlib / "EXTERNALLY-MANAGED").exists()
    sites = [purelib]
    for extra in (info.get("platlib"), info.get("usersite")):
        if isinstance(extra, str) and Path(extra).is_dir():
            sites.append(Path(extra))
    debian = prefix / "lib" / "python3" / "dist-packages"
    if debian.is_dir():
        sites.append(debian)
    try:
        packages = _scan_site_dirs(sites) if purelib.is_dir() else None
    except OSError:
        packages = None
    if _under(prefix, _HOMEBREW_PREFIXES):
        kind = EnvKind.HOMEBREW
    elif managed or _under(prefix, _SYSTEM_PREFIXES):
        kind = EnvKind.SYSTEM
    else:
        kind = classify_env(prefix, home)
    return PythonEnv(prefix, kind, version, packages, set(), None, None, managed)


def discover_environments(
    home: Path,
    extra_roots: Sequence[Path] = (),
    include_path_interpreters: bool = True,
    search_home: bool = True,
) -> list[PythonEnv]:
    roots = ([home] if search_home else []) + list(extra_roots)
    candidates = _marker_roots(find_files(roots, MARKERS))
    if search_home:
        candidates += _known_places(home)
        candidates += _conda_env_list()

    envs: dict[Path, PythonEnv] = {}
    for c in candidates:
        key = c.resolve()
        if key not in envs and c.is_dir():
            envs[key] = _build_env(c, home)

    if include_path_interpreters:
        for exe in _path_executables():
            ancestors = {*exe.parents, *exe.resolve().parents}
            if any(k in ancestors for k in envs):
                continue
            env = _probe_interpreter(exe, home)
            if env is not None and env.path.resolve() not in envs:
                envs[env.path.resolve()] = env

    return sorted(envs.values(), key=lambda e: str(e.path))
