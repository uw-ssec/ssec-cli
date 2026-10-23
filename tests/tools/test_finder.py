import os
import subprocess
import sys
from pathlib import Path

import pytest

from ssec_cli.tools.finder import find_files, rg_available

PATTERNS = ["**/pyvenv.cfg", "**/conda-meta/history", "**/requirements*.txt"]

backends = [
    False,
    pytest.param(
        True, marks=pytest.mark.skipif(not rg_available(), reason="rg not installed")
    ),
]


def touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    return path


@pytest.mark.parametrize("use_rg", backends)
def test_finds_patterns(tmp_path, use_rg):
    expected = [
        touch(tmp_path / "a/.venv/pyvenv.cfg"),
        touch(tmp_path / "b/.pixi/envs/default/conda-meta/history"),
        touch(tmp_path / "c/requirements-dev.txt"),
    ]
    found = find_files([tmp_path], PATTERNS, use_rg=use_rg)
    assert found == sorted(expected)


@pytest.mark.parametrize("use_rg", backends)
def test_respects_excludes(tmp_path, use_rg):
    touch(tmp_path / "node_modules/x/pyvenv.cfg")
    keep = touch(tmp_path / "ok/pyvenv.cfg")
    assert find_files([tmp_path], PATTERNS, use_rg=use_rg) == [keep]


@pytest.mark.parametrize("use_rg", backends)
def test_hidden_and_gitignored_found(tmp_path, use_rg):
    (tmp_path / ".gitignore").write_text(".hidden\n")
    f = touch(tmp_path / ".hidden/pyvenv.cfg")
    assert find_files([tmp_path], PATTERNS, use_rg=use_rg) == [f]


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions as non-root",
)
@pytest.mark.parametrize("use_rg", backends)
def test_walk_skips_unreadable_dir(tmp_path, use_rg):
    f = touch(tmp_path / "good/pyvenv.cfg")
    bad = tmp_path / "bad"
    bad.mkdir()
    bad.chmod(0o000)
    try:
        assert find_files([tmp_path], PATTERNS, use_rg=use_rg) == [f]
    finally:
        bad.chmod(0o755)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
@pytest.mark.parametrize("use_rg", backends)
def test_walk_does_not_follow_symlink_loops(tmp_path, use_rg):
    f = touch(tmp_path / "pyvenv.cfg")
    (tmp_path / "loop").symlink_to(".")
    assert find_files([tmp_path], PATTERNS, use_rg=use_rg) == [f]


@pytest.mark.parametrize("use_rg", backends)
def test_missing_root_and_dedupe(tmp_path, use_rg):
    f = touch(tmp_path / "pyvenv.cfg")
    found = find_files([tmp_path, tmp_path, tmp_path / "nope"], PATTERNS, use_rg=use_rg)
    assert found == [f]


@pytest.mark.parametrize("use_rg", backends)
def test_extra_excludes(tmp_path, use_rg):
    touch(tmp_path / ".pixi/envs/uv.lock")
    keep = touch(tmp_path / "proj/uv.lock")
    found = find_files([tmp_path], ["**/uv.lock"], excludes=(".pixi",), use_rg=use_rg)
    assert found == [keep]


@pytest.mark.parametrize("use_rg", backends)
def test_star_does_not_span_directories(tmp_path, use_rg):
    touch(tmp_path / "requirements/base.txt")
    touch(tmp_path / "requirements-x/foo.txt")
    keep = touch(tmp_path / "sub/requirements-dev.txt")
    assert find_files([tmp_path], ["**/requirements*.txt"], use_rg=use_rg) == [keep]


@pytest.mark.parametrize("use_rg", backends)
def test_bare_pattern_matches_any_depth(tmp_path, use_rg):
    a = touch(tmp_path / "pixi.lock")
    b = touch(tmp_path / "x/y/pixi.lock")
    assert find_files([tmp_path], ["pixi.lock"], use_rg=use_rg) == sorted([a, b])


@pytest.mark.parametrize("use_rg", backends)
def test_default_excludes_multi_component(tmp_path, use_rg):
    touch(tmp_path / "Library/Caches/x/pyvenv.cfg")
    touch(tmp_path / ".cargo/registry/x/pyvenv.cfg")
    keep = touch(tmp_path / "Library/ok/pyvenv.cfg")
    assert find_files([tmp_path], PATTERNS, use_rg=use_rg) == [keep]


@pytest.mark.skipif(not rg_available(), reason="rg not installed")
@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("rg", 1), OSError("boom")])
def test_rg_failure_falls_back_to_walk(tmp_path, monkeypatch, exc):
    f = touch(tmp_path / "a/pyvenv.cfg")

    def boom(*args, **kwargs):
        raise exc

    monkeypatch.setattr(subprocess, "run", boom)
    assert find_files([tmp_path], PATTERNS, use_rg=True) == [f]
