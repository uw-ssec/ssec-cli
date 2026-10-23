"""Find lockfiles and report the pinned versions of watched packages."""

import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ssec_cli.tools.advisories import normalize_name
from ssec_cli.tools.finder import DEFAULT_EXCLUDES, find_files

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

WATCHED = ("certifi", "pip", "ca-certificates")

LOCKFILE_PATTERNS = ("pixi.lock", "uv.lock", "poetry.lock", "requirements*.txt")
LOCK_EXCLUDES = (*DEFAULT_EXCLUDES, ".pixi", ".venv", "venv")

_PIXI_LINE = re.compile(r"^\s*-\s*(conda|pypi):\s*(\S+)\s*$")
_LEGACY_KIND = re.compile(r"^\s*-\s*kind:\s*(conda|pypi)\s*$")
_LEGACY_FIELD = re.compile(r"^\s+(name|version):\s*(\S+)\s*$")
_CONDA_FILE = re.compile(r"^(?P<name>.+)-(?P<ver>[^-]+)-[^-]+\.(conda|tar\.bz2)$")
_PYPI_FILE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)(-.*\.whl|\.tar\.gz|\.zip)$")
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*===?\s*([^\s;#\\]+)")


@dataclass
class LockPin:
    lockfile: Path
    package: str
    version: str | None
    error: str | None = None


def _pixi_pins(text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for line in text.splitlines():
        m = _PIXI_LINE.match(line)
        if not m:
            continue
        kind, url = m.groups()
        filename = re.split(r"[?#]", url)[0].rstrip("/").rsplit("/", 1)[-1]
        fm = (_CONDA_FILE if kind == "conda" else _PYPI_FILE).match(filename)
        if fm:
            found.add((normalize_name(fm["name"]), fm["ver"]))
    return found


def _pixi_legacy_pins(text: str) -> set[tuple[str, str]]:
    """Pins from legacy (v3-v5) `- kind: conda|pypi` blocks."""
    found: set[tuple[str, str]] = set()
    fields: dict[str, str] | None = None
    for line in text.splitlines():
        if _LEGACY_KIND.match(line):
            fields = {}
            continue
        m = _LEGACY_FIELD.match(line)
        if fields is not None and m:
            fields[m[1]] = m[2].strip("\"'")
            if len(fields) == 2:
                found.add((normalize_name(fields["name"]), fields["version"]))
                fields = None
    return found


def _toml_pins(text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for pkg in tomllib.loads(text).get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            found.add((normalize_name(name), version))
    return found


def _requirements_pins(text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for line in text.splitlines():
        m = _REQ_LINE.match(line)
        if m:
            found.add((normalize_name(m[1]), m[2]))
    return found


def parse_lockfile(path: Path, packages: Sequence[str] = WATCHED) -> list[LockPin]:
    """One pin per distinct (package, version); one error pin if unparsable."""
    try:
        text = path.read_text(encoding="utf-8-sig")
        if path.name == "pixi.lock":
            found = _pixi_pins(text) | _pixi_legacy_pins(text)
            if not found:
                return [LockPin(path, "", None, "unrecognised pixi.lock format")]
        elif path.suffix == ".lock":
            found = _toml_pins(text)
        else:
            found = _requirements_pins(text)
    except Exception as exc:  # noqa: BLE001 - any failure means "unknown"
        return [LockPin(path, "", None, f"{type(exc).__name__}: {exc}")]
    wanted = {normalize_name(p) for p in packages}
    return [LockPin(path, n, v) for n, v in sorted(found) if n in wanted]


def scan_lockfiles(root: Path, recursive: bool = True) -> list[LockPin]:
    if recursive:
        files = find_files(
            [root], [f"**/{p}" for p in LOCKFILE_PATTERNS], excludes=LOCK_EXCLUDES
        )
    else:
        files = sorted(
            f for p in LOCKFILE_PATTERNS for f in root.glob(p) if f.is_file()
        )
    pins: list[LockPin] = []
    for f in files:
        pins.extend(parse_lockfile(f))
    return pins
