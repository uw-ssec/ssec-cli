import json
import os
import subprocess
from pathlib import Path

import pytest

from ssec_cli.tools import environments
from ssec_cli.tools.environments import (
    EnvKind,
    PythonEnv,
    classify_env,
    discover_environments,
    python_executable,
    read_env_packages,
)

from conftest import make_conda_env, make_framework, make_venv


REAL_KNOWN_PLACES = environments._known_places


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """Never touch the real machine: no known places, no PATH, no conda."""
    monkeypatch.setattr(environments, "_known_places", lambda home: [])
    monkeypatch.setattr(environments.shutil, "which", lambda *a, **k: None)

    def boom(*a, **k):
        raise AssertionError(f"unexpected subprocess: {a}")

    monkeypatch.setattr(environments.subprocess, "run", boom)


def test_classify(tmp_path, monkeypatch):
    home = tmp_path
    uvp = make_venv(home / "proj" / ".venv", uv=True)
    (home / "proj" / "uv.lock").write_text("")
    assert classify_env(uvp, home) == EnvKind.UV_PROJECT
    plain = make_venv(home / "other" / ".venv", uv=True)
    assert classify_env(plain, home) == EnvKind.PLAIN_VENV
    cases = {
        ".local/share/uv/tools/ruff": EnvKind.UV_TOOL,
        ".local/pipx/venvs/black": EnvKind.PIPX,
        ".local/share/pipx/venvs/black": EnvKind.PIPX,
        "proj/.pixi/envs/default": EnvKind.PIXI_PROJECT,
        ".pixi/envs/ruff": EnvKind.PIXI_GLOBAL,
        "proj/.pixi/solve-group-envs/default-1a2b": EnvKind.PIXI_PROJECT,
        "miniforge3/envs/x": EnvKind.CONDA,
        ".pyenv/versions/3.12.1": EnvKind.PYENV,
        ".local/share/uv/python/cpython-3.12.1-macos-aarch64-none": EnvKind.UV_PYTHON,
    }
    for rel, kind in cases.items():
        p = home / rel
        if kind == EnvKind.CONDA:
            make_conda_env(p, {})
        else:
            p.mkdir(parents=True)
        assert classify_env(p, home) == kind, rel
    fw = Path("/Library/Frameworks/Python.framework/Versions/3.12")
    assert classify_env(fw, home) == EnvKind.FRAMEWORK
    brew = Path(
        "/opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12"
    )
    assert classify_env(brew, home) == EnvKind.HOMEBREW
    cask = Path("/opt/homebrew/Caskroom/miniforge/base")
    with monkeypatch.context() as m:
        m.setattr(Path, "is_dir", lambda self: self == cask / "conda-meta")
        assert classify_env(cask, home) == EnvKind.CONDA
    assert classify_env(Path("/usr"), home) == EnvKind.SYSTEM


def test_read_packages_venv(tmp_path):
    venv = make_venv(tmp_path / "v", pkgs={"pip": "24.0", "Typing_Extensions": "4.1"})
    pkgs, conda = read_env_packages(venv)
    assert pkgs == {"pip": "24.0", "typing-extensions": "4.1"}
    assert conda == set()


def test_read_packages_windows_layout(tmp_path):
    venv = make_venv(tmp_path / "v", windows=True)
    pkgs, _ = read_env_packages(venv)
    assert pkgs == {"pip": "24.0", "certifi": "2025.8.3"}


def test_packages_none_vs_empty(tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "pyvenv.cfg").write_text("version = 3.12.1\n")
    assert read_env_packages(bare)[0] is None
    empty = make_venv(tmp_path / "empty", pkgs={})
    assert read_env_packages(empty)[0] == {}
    env = discover_environments(tmp_path, include_path_interpreters=False)
    by_name = {e.path.name: e for e in env}
    assert by_name["bare"].packages is None
    assert by_name["empty"].packages == {}


def test_conda_env_tracks_conda_vs_pip(tmp_path):
    env = make_conda_env(
        tmp_path / "c",
        {"certifi": "2025.8.3", "ca-certificates": "2025.9.9"},
        pip_pkgs={"pip": "24.0"},
    )
    pkgs, conda = read_env_packages(env)
    assert pkgs["certifi"] == "2025.8.3"
    assert pkgs["ca-certificates"] == "2025.9.9"
    assert pkgs["pip"] == "24.0"
    assert "certifi" in conda and "pip" not in conda


def test_pip_dist_info_overrides_stale_conda_meta(tmp_path):
    env = make_conda_env(tmp_path / "c", {"pip": "23.0"}, pip_pkgs={"pip": "24.0"})
    pkgs, conda = read_env_packages(env)
    assert pkgs["pip"] == "24.0"
    assert "pip" in conda


def test_discover_finds_all_and_dedupes(tmp_path, monkeypatch):
    home = tmp_path
    make_venv(home / "proj" / ".venv", uv=True)
    (home / "proj" / "uv.lock").write_text("")
    make_venv(home / "plain" / ".venv")
    make_venv(home / ".local/share/uv/tools/ruff")
    make_venv(home / ".local/pipx/venvs/black")
    make_conda_env(home / "proj2" / ".pixi/envs/default", {"certifi": "2025.8.3"})
    make_conda_env(home / ".pixi/envs/ruff", {})
    conda_env = make_conda_env(home / "miniforge3/envs/x", {"certifi": "2025.8.3"})
    make_venv(home / ".pyenv/versions/3.12.1")
    outside = make_conda_env(
        tmp_path.parent / (tmp_path.name + "_ext") / "envs" / "y", {}
    )

    monkeypatch.setattr(
        environments.shutil,
        "which",
        lambda name, *a, **k: "/bin/conda" if name == "conda" else None,
    )
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        assert kw.get("timeout")
        out = json.dumps({"envs": [str(conda_env), str(outside)]})
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(environments.subprocess, "run", fake_run)
    envs = discover_environments(home, include_path_interpreters=False)
    kinds = sorted(e.kind.value for e in envs)
    assert calls and calls[0][:3] == ["conda", "env", "list"]
    assert kinds == sorted(
        [
            "uv_project",
            "plain_venv",
            "uv_tool",
            "pipx",
            "pixi_project",
            "pixi_global",
            "conda",
            "pyenv",
            "conda",
        ]
    )
    assert len({e.path.resolve() for e in envs}) == len(envs)
    proj = next(e for e in envs if e.kind == EnvKind.PIXI_PROJECT)
    assert proj.project == home / "proj2"
    assert next(e for e in envs if e.kind == EnvKind.PIXI_GLOBAL).tool_name == "ruff"
    assert (
        next(e for e in envs if e.kind == EnvKind.UV_PROJECT).project == home / "proj"
    )
    assert next(e for e in envs if e.kind == EnvKind.PYENV).python_version == "3.12.1"


def test_known_places_found(tmp_path, monkeypatch):
    fw = make_framework(tmp_path / "fw", "3.11")
    monkeypatch.setattr(environments, "_known_places", lambda home: [fw])
    envs = discover_environments(tmp_path / "home", include_path_interpreters=False)
    assert [e.path for e in envs] == [fw]
    assert envs[0].python_version == "3.11"
    assert envs[0].packages == {"pip": "24.0"}


def test_known_places_globbing(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".pyenv/versions/3.12.1").mkdir(parents=True)
    (home / ".local/share/uv/python/cpython-3.12").mkdir(parents=True)
    monkeypatch.setattr(environments, "_SYSTEM_PLACES", ())
    monkeypatch.delenv("POETRY_VIRTUALENVS_PATH", raising=False)
    names = sorted(p.name for p in REAL_KNOWN_PLACES(home))
    assert names == ["3.12.1", "cpython-3.12"]


def test_search_home_false(tmp_path, monkeypatch):
    home = tmp_path / "home"
    make_venv(home / "elsewhere" / ".venv")
    project = home / "project"
    make_conda_env(project / ".pixi/envs/default", {})
    monkeypatch.setattr(environments, "_known_places", lambda h: pytest.fail("known"))
    envs = discover_environments(
        home, extra_roots=[project], include_path_interpreters=False, search_home=False
    )
    assert [e.kind for e in envs] == [EnvKind.PIXI_PROJECT]
    assert envs[0].project == project


def test_externally_managed(tmp_path):
    env = make_framework(tmp_path / "fw", "3.12")
    assert read_ext(env) is False
    (env / "lib" / "python3.12" / "EXTERNALLY-MANAGED").write_text("[x]\n")
    assert read_ext(env) is True


def read_ext(env: Path) -> bool:
    return environments._externally_managed(env)


def test_path_interpreters(tmp_path, monkeypatch):
    home = tmp_path / "home"
    inside = make_venv(home / "v")
    prefix = tmp_path / "usr_local"
    stdlib = prefix / "lib" / "python3.12"
    purelib = stdlib / "site-packages"
    purelib.mkdir(parents=True)
    (purelib / "pip-23.0.dist-info").mkdir()
    (stdlib / "EXTERNALLY-MANAGED").write_text("")
    exe = prefix / "bin" / "python3"
    exe.parent.mkdir()
    exe.write_text("")

    monkeypatch.setenv(
        "PATH", f"{inside / 'bin'}{__import__('os').pathsep}{exe.parent}"
    )
    monkeypatch.setattr(
        environments.shutil,
        "which",
        lambda name, path=None, **k: (
            str(Path(path) / name) if path and (Path(path) / name).exists() else None
        ),
    )
    ran = []

    def fake_run(cmd, **kw):
        ran.append(cmd)
        assert "-I" in cmd and kw["timeout"] == 5
        out = json.dumps(
            {
                "prefix": str(prefix),
                "purelib": str(purelib),
                "stdlib": str(stdlib),
                "version": "3.12.4",
            }
        )
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(environments.subprocess, "run", fake_run)
    envs = discover_environments(home)
    # The interpreter inside the discovered venv is never executed.
    assert [c[0] for c in ran] == [str(exe)]
    sysenv = next(e for e in envs if e.path == prefix)
    assert sysenv.kind == EnvKind.SYSTEM
    assert sysenv.externally_managed is True
    assert sysenv.python_version == "3.12.4"
    assert sysenv.packages == {"pip": "23.0"}
    assert len(envs) == 2


def test_python_executable(tmp_path):
    posix = make_venv(tmp_path / "p")
    win = make_venv(tmp_path / "w", windows=True)

    def mk(p):
        return PythonEnv(p, EnvKind.PLAIN_VENV, None, {}, set(), None, None, False)

    assert python_executable(mk(posix)) == posix / "bin" / "python"
    assert python_executable(mk(win)) == win / "Scripts" / "python.exe"


def test_unreadable_site_dir_is_none(tmp_path):
    venv = make_venv(tmp_path / "v")
    site = venv / "lib" / "python3.12" / "site-packages"
    site.chmod(0)
    try:
        if os.access(site, os.R_OK):
            pytest.skip("cannot make directory unreadable (root?)")
        assert read_env_packages(venv)[0] is None
    finally:
        site.chmod(0o755)


@pytest.mark.parametrize(
    "body", ["{not json", "{}", "[]", '"x"', '{"name": "certifi"}']
)
def test_corrupt_watched_conda_meta_is_none(tmp_path, body):
    env = make_conda_env(tmp_path / "c", {"certifi": "2025.8.3"})
    (env / "conda-meta" / "certifi-2025.8.3-h0_0.json").write_text(body)
    assert read_env_packages(env)[0] is None
    found = discover_environments(tmp_path, include_path_interpreters=False)
    assert [e.packages for e in found] == [None]


def test_corrupt_unrelated_conda_meta_is_skipped(tmp_path):
    env = make_conda_env(tmp_path / "c", {"certifi": "2025.8.3"})
    (env / "conda-meta" / "numpy-1.0-h0_0.json").write_text("{not json")
    pkgs, _ = read_env_packages(env)
    assert pkgs is not None and pkgs["certifi"] == "2025.8.3"


def test_lib64_site_packages(tmp_path):
    venv = make_venv(tmp_path / "v", pkgs={})
    site64 = venv / "lib64" / "python3.12" / "site-packages"
    (site64 / "certifi-2024.1.1.dist-info").mkdir(parents=True)
    assert read_env_packages(venv)[0] == {"certifi": "2024.1.1"}


def test_probe_usersite_lowest_wins(tmp_path, monkeypatch):
    prefix = tmp_path / "py"
    purelib = prefix / "lib" / "python3.12" / "site-packages"
    user = tmp_path / "usersite"
    (purelib / "certifi-2025.8.3.dist-info").mkdir(parents=True)
    (user / "certifi-2023.1.1.dist-info").mkdir(parents=True)
    exe = prefix / "bin" / "python3"
    exe.parent.mkdir()
    exe.write_text("")
    info = {
        "prefix": str(prefix),
        "purelib": str(purelib),
        "platlib": str(purelib),
        "usersite": str(user),
        "stdlib": str(prefix / "lib" / "python3.12"),
        "version": "3.12.4",
    }
    monkeypatch.setattr(
        environments.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, json.dumps(info), ""),
    )
    env = environments._probe_interpreter(exe, tmp_path / "home")
    assert env.packages == {"certifi": "2023.1.1"}


def test_solve_group_env_is_pixi_project_with_project_set(tmp_path):
    from ssec_cli.tools.environments import _build_env

    p = tmp_path / "proj/.pixi/solve-group-envs/default-1a2b"
    make_conda_env(p, {"pip": "25.0"})
    e = _build_env(p, tmp_path)
    assert e.kind == EnvKind.PIXI_PROJECT
    assert e.project == tmp_path / "proj"


def test_classify_conda_under_pyenv_is_conda(tmp_path):
    home = tmp_path
    mf = make_conda_env(home / ".pyenv/versions/miniforge3-24.3.0-0", {})
    assert classify_env(mf, home) == EnvKind.CONDA
    # Pixi rules still come first, even though pixi envs carry conda-meta.
    px = make_conda_env(home / "proj/.pixi/envs/default", {})
    assert classify_env(px, home) == EnvKind.PIXI_PROJECT
    sg = make_conda_env(home / "proj/.pixi/solve-group-envs/default-1", {})
    assert classify_env(sg, home) == EnvKind.PIXI_PROJECT
    gl = make_conda_env(home / ".pixi/envs/ruff", {})
    assert classify_env(gl, home) == EnvKind.PIXI_GLOBAL
    # A plain pyenv version without conda-meta is still pyenv.
    plain = home / ".pyenv/versions/3.12.1"
    plain.mkdir(parents=True)
    assert classify_env(plain, home) == EnvKind.PYENV


def test_uv_venv_not_named_dot_venv_is_plain(tmp_path):
    home = tmp_path
    agent = make_venv(home / ".hermes/hermes-agent/venv", uv=True)
    (home / ".hermes/hermes-agent/uv.lock").write_text("")
    assert classify_env(agent, home) == EnvKind.PLAIN_VENV
    envs = discover_environments(home, include_path_interpreters=False)
    e = next(x for x in envs if x.path == agent)
    assert (e.kind, e.project) == (EnvKind.PLAIN_VENV, None)
    proj = make_venv(home / ".hermes/hermes-agent/.venv", uv=True)
    assert classify_env(proj, home) == EnvKind.UV_PROJECT


def _uv_python(root: Path, managed: bool = True) -> Path:
    stdlib = root / "lib" / "python3.12"
    (stdlib / "site-packages" / "pip-25.0.dist-info").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "bin" / "python3.12").write_text("")
    if managed:
        (stdlib / "EXTERNALLY-MANAGED").write_text("[externally-managed]\n")
    return root


def test_discovery_sets_externally_managed_for_uv_python(tmp_path, monkeypatch):
    home = tmp_path / "home"
    uvpy = _uv_python(home / ".local/share/uv/python/cpython-3.12.1-macos")
    monkeypatch.setattr(environments, "_known_places", lambda h: [uvpy])
    envs = discover_environments(home, include_path_interpreters=False)
    assert [(e.kind, e.externally_managed) for e in envs] == [(EnvKind.UV_PYTHON, True)]


def test_discovery_sets_externally_managed_for_marker_found_env(tmp_path):
    env = make_conda_env(tmp_path / "c", {"certifi": "2025.8.3"})
    (env / "lib" / "python3.12" / "EXTERNALLY-MANAGED").write_text("")
    make_conda_env(tmp_path / "d", {"certifi": "2025.8.3"})
    envs = {
        e.path.name: e
        for e in discover_environments(tmp_path, include_path_interpreters=False)
    }
    assert envs["c"].externally_managed is True
    assert envs["d"].externally_managed is False


def test_externally_managed_windows_and_lib64(tmp_path):
    win = tmp_path / "win"
    (win / "Lib").mkdir(parents=True)
    (win / "Lib" / "EXTERNALLY-MANAGED").write_text("")
    assert environments._externally_managed(win) is True
    l64 = tmp_path / "l64"
    (l64 / "lib64" / "python3.12").mkdir(parents=True)
    (l64 / "lib64" / "python3.12" / "EXTERNALLY-MANAGED").write_text("")
    assert environments._externally_managed(l64) is True


def test_venv_is_never_externally_managed(tmp_path):
    # pip skips the PEP 668 check inside a virtual environment.
    venv = make_venv(tmp_path / "v")
    (venv / "lib" / "python3.12" / "EXTERNALLY-MANAGED").write_text("")
    assert environments._externally_managed(venv) is False


def test_known_places_finds_poetry_venvs(tmp_path, monkeypatch):
    home = tmp_path / "home"
    mac = make_venv(home / "Library/Caches/pypoetry/virtualenvs/app-AbC-py3.12")
    lin = make_venv(home / ".cache/pypoetry/virtualenvs/lib-XyZ-py3.11", py="3.11")
    (home / ".cache/pypoetry/virtualenvs/not-a-venv").mkdir()
    custom = tmp_path / "poetry-venvs"
    mine = make_venv(custom / "tool-123-py3.12")
    (custom / "junk").mkdir()
    monkeypatch.setattr(environments, "_SYSTEM_PLACES", ())
    monkeypatch.setenv("POETRY_VIRTUALENVS_PATH", str(custom))
    assert sorted(REAL_KNOWN_PLACES(home)) == sorted([mac, lin, mine])
    monkeypatch.delenv("POETRY_VIRTUALENVS_PATH")
    assert sorted(REAL_KNOWN_PLACES(home)) == sorted([mac, lin])


def test_poetry_venvs_discovered_and_classified(tmp_path, monkeypatch):
    home = tmp_path / "home"
    pv = make_venv(home / "Library/Caches/pypoetry/virtualenvs/app-AbC-py3.12")
    monkeypatch.setattr(environments, "_SYSTEM_PLACES", ())
    monkeypatch.setattr(environments, "_HOME_PLACES", ())
    monkeypatch.delenv("POETRY_VIRTUALENVS_PATH", raising=False)
    monkeypatch.setattr(environments, "_known_places", REAL_KNOWN_PLACES)
    envs = discover_environments(home, include_path_interpreters=False)
    assert [(e.path, e.kind) for e in envs] == [(pv, EnvKind.PLAIN_VENV)]
    assert envs[0].packages == {"pip": "24.0", "certifi": "2025.8.3"}
