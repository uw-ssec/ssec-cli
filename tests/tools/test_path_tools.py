import os
import stat
from pathlib import Path

import pytest

from ssec_cli.tools import path_tools
from ssec_cli.tools.path_tools import (
    InstallMethod,
    detect_install_method,
    scan_path_tools,
    tool_version,
)


def _touch(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")
    return p


def _script(p: Path, body: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


def test_detect_install_method(tmp_path, home):
    conda = tmp_path / "miniconda"
    (conda / "conda-meta").mkdir(parents=True)
    venv = tmp_path / "venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    cases = [
        ("pixi", home / ".pixi/bin/pixi", InstallMethod.STANDALONE, None, None),
        ("ruff", home / ".pixi/bin/ruff", InstallMethod.PIXI_GLOBAL, None, None),
        ("uv", home / ".local/bin/uv", InstallMethod.STANDALONE, None, None),
        ("uv", home / ".cargo/bin/uv", InstallMethod.STANDALONE, None, None),
        (
            "x",
            home / ".local/share/uv/tools/x/bin/x",
            InstallMethod.UV_TOOL,
            None,
            None,
        ),
        ("x", home / ".local/pipx/venvs/x/bin/x", InstallMethod.PIPX, None, None),
        ("x", home / ".local/share/pipx/venvs/x/bin/x", InstallMethod.PIPX, None, None),
        ("conda", conda / "bin/conda", InstallMethod.CONDA, None, conda),
        ("pip", venv / "bin/pip", InstallMethod.VENV, None, venv),
        ("pip3", Path("/usr/bin/pip3"), InstallMethod.SYSTEM, None, None),
        ("foo", tmp_path / "opt/foo", InstallMethod.UNKNOWN, None, None),
    ]
    for name, path, method, formula, root in cases:
        assert detect_install_method(name, path, home) == (method, formula, root), path


@pytest.mark.parametrize(
    "prefix",
    ["/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"],
)
def test_homebrew_formula(home, prefix):
    path = Path(prefix) / "bin/uv"
    real = Path(prefix) / "Cellar/uv/0.13.4/bin/uv"
    got = detect_install_method("uv", path, home, resolve=lambda p: real)
    assert got == (InstallMethod.HOMEBREW, "uv", None)


def test_homebrew_symlink(tmp_path, home):
    real = _touch(tmp_path / "opt/homebrew/Cellar/uv/0.13.4/bin/uv")
    link = tmp_path / "opt/homebrew/bin/uv"
    link.parent.mkdir(parents=True)
    link.symlink_to(os.path.relpath(real, link.parent))
    assert detect_install_method("uv", link, home) == (
        InstallMethod.HOMEBREW,
        "uv",
        None,
    )


def test_pipx_symlink_in_local_bin(home):
    real = _touch(home / ".local/pipx/venvs/black/bin/black")
    link = home / ".local/bin/black"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    assert detect_install_method("black", link, home)[0] is InstallMethod.PIPX


def test_uv_tool_symlink_in_local_bin(home):
    real = _touch(home / ".local/share/uv/tools/ruff/bin/ruff")
    link = home / ".local/bin/ruff"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    assert detect_install_method("ruff", link, home)[0] is InstallMethod.UV_TOOL


def test_standalone_uv_real_file(home):
    p = _touch(home / ".local/bin/uv")
    assert detect_install_method("uv", p, home)[0] is InstallMethod.STANDALONE


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    "body, expected",
    [
        ("echo 'pip 26.2.2 from /x (python 3.12)'", "26.2.2"),
        ("echo 'uv 0.13.4 (Homebrew 2026-10-21)'", "0.13.4"),
        ("echo 'git version 2.50.1' >&2", "2.50.1"),
        ("", None),
        ("echo 'tool 1.2.3'; exit 1", None),
    ],
)
def test_extract_version_variants(tmp_path, body, expected):
    assert tool_version(_script(tmp_path / "t", body)) == expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_version_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(path_tools, "VERSION_TIMEOUT", 0.5)
    assert tool_version(_script(tmp_path / "slow", "sleep 10")) is None


def test_version_oserror(tmp_path):
    assert tool_version(tmp_path / "nope") is None
    noexec = _touch(tmp_path / "noexec")
    assert tool_version(noexec) is None  # PermissionError


def test_missing_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    [info] = scan_path_tools(tmp_path, ["definitely-not-a-tool"])
    assert info.path is None and info.version is None
    assert info.method is InstallMethod.UNKNOWN


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_scan_finds_tool(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    _script(bindir / "mytool", "echo 'mytool 3.4.5'")
    monkeypatch.setenv("PATH", str(bindir))
    [info] = scan_path_tools(tmp_path / "home", ["mytool"])
    assert info.path == bindir / "mytool"
    assert info.version == "3.4.5"


def test_venv_python_symlinked_to_homebrew_is_venv(tmp_path, home):
    real = _touch(tmp_path / "opt/homebrew/Cellar/python@3.12/3.12.1/bin/python3.12")
    venv = tmp_path / "proj/.venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x\n")
    (venv / "bin/python").symlink_to(real)
    got = detect_install_method("python", venv / "bin/python", home)
    assert got == (InstallMethod.VENV, None, venv)


def test_pixi_env_is_pixi_global(home):
    env = home / ".pixi/envs/x"
    (env / "conda-meta").mkdir(parents=True)
    p = _touch(env / "bin/x")
    assert detect_install_method("x", p, home) == (
        InstallMethod.PIXI_GLOBAL,
        None,
        None,
    )


def test_condabin_conda(tmp_path, home):
    prefix = tmp_path / "miniconda3"
    (prefix / "conda-meta").mkdir(parents=True)
    p = _touch(prefix / "condabin/conda")
    assert detect_install_method("conda", p, home) == (
        InstallMethod.CONDA,
        None,
        prefix,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_version_non_utf8_output(tmp_path):
    t = _script(tmp_path / "bad", "printf '\\377\\376\\n'; echo 'tool 1.2.3'")
    assert tool_version(t) == "1.2.3"
