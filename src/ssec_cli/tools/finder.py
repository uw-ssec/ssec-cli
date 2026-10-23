"""Find files by glob under a set of roots, using ripgrep when available."""

import fnmatch
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    "node_modules",
    ".Trash",
    "Library/Caches",
    "Library/Containers",
    "Library/Group Containers",
    ".cache",
    ".npm",
    ".cargo/registry",
    ".rustup",
    "go/pkg",
    "site-packages",
)

RG_MISSING_NOTE = (
    "Note: ripgrep (rg) not found; using a slower built-in search. "
    "Install it with `pixi global install ripgrep` or `brew install ripgrep`."
)

_note_printed = False


def rg_available() -> bool:
    return shutil.which("rg") is not None


def _note_once() -> None:
    global _note_printed
    if not _note_printed:
        _note_printed = True
        print(RG_MISSING_NOTE, file=sys.stderr)


def _find_rg(
    root: Path, patterns: Sequence[str], excludes: Sequence[str]
) -> list[Path]:
    cmd = ["rg", "--files", "--hidden", "--no-ignore", "--no-messages", "--no-follow"]
    for p in patterns:
        cmd += ["--glob", p]
    for e in excludes:
        cmd += ["--glob", f"!**/{e}/**"]
    try:
        proc = subprocess.run(
            cmd, cwd=root, capture_output=True, timeout=120, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    # Exit codes 0, 1 (no match) and 2 (partial errors) are all usable.
    out = proc.stdout.decode("utf-8", errors="surrogateescape")
    return [root / line for line in out.splitlines() if line]


def _matches(rel: str, patterns: Sequence[str]) -> bool:
    for p in patterns:
        if fnmatch.fnmatchcase(rel, p):
            return True
        if p.startswith("**/") and fnmatch.fnmatchcase(rel, p[3:]):
            return True
    return False


def _is_excluded(rel_dir: str, excludes: Sequence[str]) -> bool:
    for e in excludes:
        if rel_dir == e or rel_dir.endswith("/" + e):
            return True
    return False


def _find_walk(
    root: Path, patterns: Sequence[str], excludes: Sequence[str]
) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(
        root, onerror=lambda e: None, followlinks=False
    ):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [d for d in dirnames if not _is_excluded(prefix + d, excludes)]
        for name in filenames:
            if _matches(prefix + name, patterns):
                found.append(Path(dirpath) / name)
    return found


def find_files(
    roots: list[Path],
    patterns: list[str],
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    use_rg: bool | None = None,
) -> list[Path]:
    """Return sorted, de-duplicated files under roots matching any glob."""
    if use_rg is None:
        use_rg = rg_available()
        if not use_rg:
            _note_once()
    results: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        finder = _find_rg if use_rg else _find_walk
        results.update(finder(root, patterns, excludes))
    return sorted(results)
