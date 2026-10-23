from dataclasses import replace
from pathlib import Path

import pytest

from ssec_cli.tools import evaluate as ev
from ssec_cli.tools.advisories import load_advisories, minimums_by_package
from ssec_cli.tools.environments import EnvKind, PythonEnv
from ssec_cli.tools.evaluate import (
    Status,
    evaluate_env,
    evaluate_lockpin,
    evaluate_tool,
    scan,
)
from ssec_cli.tools.lockfiles import LockPin
from ssec_cli.tools.path_tools import InstallMethod, ToolInfo

MINS = minimums_by_package(load_advisories())
PIP = MINS["pip"]
PIP_FIX = f'"pip @ {PIP.fix_url}#sha256={PIP.fix_sha256}"'
OLD = {"pip": "25.0", "certifi": "2025.1.1", "ca-certificates": "2025.1.1"}
GOOD = {"pip": "26.2.2", "certifi": "2026.10.19", "ca-certificates": "2026.10.19"}


def env(kind, path="/e/venv", packages=None, py="3.12.1", **kw):
    return PythonEnv(
        path=Path(path),
        kind=kind,
        python_version=py,
        packages=dict(OLD) if packages is None else packages,
        **kw,
    )


def by_item(findings):
    return {f.item: f for f in findings}


def tool(name, method, version="0.0.1", formula=None, path="/x/bin/t"):
    return ToolInfo(name, Path(path) if path else None, version, method, formula)


# ------------------------------------------------------------ tools


@pytest.mark.parametrize(
    ("name", "method", "formula", "fix", "note"),
    [
        ("pixi", InstallMethod.STANDALONE, None, "pixi self-update", None),
        (
            "uv",
            InstallMethod.STANDALONE,
            None,
            "UV_SYSTEM_CERTS=true uv self update",
            None,
        ),
        ("uv", InstallMethod.HOMEBREW, "uv", "brew upgrade uv", None),
        ("pixi", InstallMethod.HOMEBREW, None, "brew upgrade pixi", None),
        (
            "sigstore",
            InstallMethod.PIXI_GLOBAL,
            None,
            "pixi global update sigstore",
            None,
        ),
        ("sigstore", InstallMethod.UV_TOOL, None, "uv tool upgrade sigstore", None),
        ("sigstore", InstallMethod.PIPX, None, "pipx upgrade sigstore", None),
        (
            "conda",
            InstallMethod.CONDA,
            None,
            None,
            "update conda with the tool that installed it",
        ),
        ("pip", InstallMethod.VENV, None, None, "see Python environments"),
        ("pip", InstallMethod.CONDA, None, None, "see Python environments"),
        (
            "uv",
            InstallMethod.UNKNOWN,
            None,
            None,
            "update uv with the tool that installed it",
        ),
        (
            "uv",
            InstallMethod.SYSTEM,
            None,
            None,
            "update uv with the tool that installed it",
        ),
    ],
)
def test_tool_outdated_rows(name, method, formula, fix, note):
    f = evaluate_tool(tool(name, method, formula=formula), MINS)
    assert (f.status, f.fix, f.note) == (Status.OUTDATED, fix, note)
    assert f.category == "tool" and f.install_method is method
    assert f.advisory_id == MINS[name].advisory_id
    assert f.formula == formula


def test_tool_ok():
    f = evaluate_tool(tool("uv", InstallMethod.STANDALONE, version="0.13.4"), MINS)
    assert (f.status, f.fix, f.minimum) == (Status.OK, None, "0.13.4")


def test_tool_version_unreadable_is_unknown():
    f = evaluate_tool(tool("uv", InstallMethod.STANDALONE, version=None), MINS)
    assert (f.status, f.fix, f.note) == (Status.UNKNOWN, None, "could not read version")


def test_tool_version_unparsable_is_unknown():
    f = evaluate_tool(tool("uv", InstallMethod.STANDALONE, version="weird"), MINS)
    assert f.status is Status.UNKNOWN


def test_tool_not_on_path():
    f = evaluate_tool(tool("uv", InstallMethod.UNKNOWN, version=None, path=None), MINS)
    assert (f.status, f.location, f.fix, f.current) == (
        Status.NOT_INSTALLED,
        None,
        None,
        None,
    )


def test_conda_tool_targets_its_own_install_by_path(tmp_path):
    (tmp_path / "condabin").mkdir()
    (tmp_path / "condabin" / "conda").touch()
    t = ToolInfo(
        "conda",
        tmp_path / "condabin" / "conda",
        "0.0.1",
        InstallMethod.CONDA,
        None,
        tmp_path,
    )
    f = evaluate_tool(t, MINS)
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        f"{tmp_path}/condabin/conda update -p {tmp_path} conda",
        None,
    )


def test_no_advisory_tool_has_no_status():
    f = evaluate_tool(tool("git", InstallMethod.SYSTEM, version="2.1"), MINS)
    assert f.status.value == "no_advisory"
    assert (f.status, f.minimum, f.fix, f.note) == (
        Status.NO_ADVISORY,
        None,
        None,
        "no advisory",
    )


# ------------------------------------------------------------- envs


@pytest.mark.parametrize(
    "kind", [EnvKind.PLAIN_VENV, EnvKind.FRAMEWORK, EnvKind.PYENV, EnvKind.UV_PYTHON]
)
def test_pip_kinds(kind):
    f = by_item(evaluate_env(env(kind), MINS))
    assert set(f) == {"pip", "certifi"}
    assert f["pip"].status is Status.OUTDATED
    assert f["pip"].fix == f"/e/venv/bin/python -m pip install {PIP_FIX}"
    assert f["pip"].note is None
    assert (
        f["certifi"].fix
        == '/e/venv/bin/python -m pip install --upgrade "certifi>=2026.10.19"'
    )
    assert f["certifi"].note == "upgrade pip first"
    assert f["pip"].env_kind is kind and f["pip"].location == Path("/e/venv")


def test_certifi_without_pip_uses_uv():
    f = by_item(
        evaluate_env(env(EnvKind.PLAIN_VENV, packages={"certifi": "2025.1.1"}), MINS)
    )
    assert (
        f["certifi"].fix
        == 'uv pip install --python /e/venv/bin/python "certifi>=2026.10.19"'
    )
    assert f["certifi"].note is None
    assert f["pip"].status is Status.NOT_INSTALLED and f["pip"].fix is None


def test_python_path_is_quoted():
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, path="/e/my venv"), MINS))
    assert f["pip"].fix.startswith("'/e/my venv/bin/python' -m pip install ")


def test_old_python_cannot_have_new_pip():
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, py="3.9.18"), MINS))
    assert f["pip"].status is Status.OUTDATED and f["pip"].fix is None
    assert f["pip"].note == "pip 26.2.2 needs Python 3.10+; recreate this environment"


def test_old_python_certifi_with_pip_is_not_fixable():
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, py="3.9.18"), MINS))["certifi"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        None,
        "pip 26.2.2 needs Python 3.10+; recreate this environment",
    )


def test_old_python_certifi_without_pip_uses_uv():
    e = env(EnvKind.PLAIN_VENV, py="3.9.18", packages={"certifi": "2025.1.1"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert f.fix == 'uv pip install --python /e/venv/bin/python "certifi>=2026.10.19"'
    assert f.note is None


def test_unpinned_pip_advisory_gives_no_fix():
    mins = dict(MINS)
    mins["pip"] = replace(PIP, fix_url=None, fix_sha256=None)
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV), mins))["pip"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        None,
        "advisory has no pinned pip URL",
    )


def test_pixi_solve_group_env_gets_pixi_fix():
    e = env(
        EnvKind.PIXI_PROJECT,
        path="/p/.pixi/solve-group-envs/default-abc",
        project=Path("/p"),
        conda_packages={"pip"},
    )
    f = by_item(evaluate_env(e, MINS))["pip"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        "cd /p && pixi update pip",
        "managed by pixi",
    )


def test_python_3_10_is_new_enough():
    assert by_item(evaluate_env(env(EnvKind.PLAIN_VENV, py="3.10.0"), MINS))["pip"].fix


def test_unknown_python_version_still_gives_pip_fix():
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, py=None), MINS))["pip"]
    assert f.fix == f"/e/venv/bin/python -m pip install {PIP_FIX}"
    assert f.note == "could not determine Python version; pip 26.2.2 needs Python 3.10+"


def test_uv_project():
    f = by_item(evaluate_env(env(EnvKind.UV_PROJECT, project=Path("/p/my proj")), MINS))
    note = "managed by uv; pip changes would be undone by uv sync"
    for item in ("pip", "certifi"):
        assert f[item].fix == (
            f"cd '/p/my proj' && uv lock --upgrade-package {item} && uv sync"
        )
        assert f[item].note == note


def test_uv_tool_env():
    f = by_item(evaluate_env(env(EnvKind.UV_TOOL, tool_name="sigstore"), MINS))
    for item in ("pip", "certifi"):
        assert (f[item].status, f[item].fix, f[item].note) == (
            Status.OUTDATED,
            "uv tool upgrade sigstore",
            None,
        )


def test_pipx_env_uses_runpip():
    f = by_item(evaluate_env(env(EnvKind.PIPX, tool_name="my tool"), MINS))
    assert (f["certifi"].status, f["certifi"].fix, f["certifi"].note) == (
        Status.OUTDATED,
        "pipx runpip 'my tool' install --upgrade \"certifi>=2026.10.19\"",
        None,
    )
    assert (f["pip"].status, f["pip"].fix, f["pip"].note) == (
        Status.OUTDATED,
        f"pipx runpip 'my tool' install {PIP_FIX}",
        None,
    )


def test_pipx_env_unpinned_pip_has_no_fix():
    mins = dict(MINS)
    mins["pip"] = replace(PIP, fix_url=None, fix_sha256=None)
    f = by_item(evaluate_env(env(EnvKind.PIPX, tool_name="black"), mins))["pip"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        None,
        "advisory has no pinned pip URL",
    )


def test_pixi_project():
    f = by_item(evaluate_env(env(EnvKind.PIXI_PROJECT, project=Path("/p")), MINS))
    assert set(f) == {"pip", "certifi", "ca-certificates"}
    for item, x in f.items():
        assert (x.status, x.fix, x.note) == (
            Status.OUTDATED,
            f"cd /p && pixi update {item}",
            "managed by pixi",
        )


def test_pixi_project_ca_certificates_only():
    pkgs = {**GOOD, "ca-certificates": "2025.1.1"}
    e = env(EnvKind.PIXI_PROJECT, project=Path("/p q"), packages=pkgs)
    out = [f for f in evaluate_env(e, MINS) if f.status is Status.OUTDATED]
    assert [(f.item, f.fix, f.note) for f in out] == [
        (
            "ca-certificates",
            "cd '/p q' && pixi update ca-certificates",
            "managed by pixi",
        )
    ]


def test_pixi_global():
    f = by_item(evaluate_env(env(EnvKind.PIXI_GLOBAL, tool_name="sigstore"), MINS))
    assert "ca-certificates" in f
    assert (f["certifi"].fix, f["certifi"].note) == (
        "pixi global update sigstore",
        None,
    )


def test_conda_installed_packages():
    e = env(
        EnvKind.CONDA,
        path="/c/envs/science",
        conda_packages={"pip", "certifi", "ca-certificates"},
    )
    f = by_item(evaluate_env(e, MINS))
    # No conda binary at /c, so the conda on PATH runs it, but still by path.
    for item in ("pip", "certifi", "ca-certificates"):
        assert (f[item].status, f[item].fix, f[item].note) == (
            Status.OUTDATED,
            f"conda update -p /c/envs/science {item}",
            None,
        )


def _touch(p):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch()


def test_conda_base_with_own_condabin(tmp_path):
    _touch(tmp_path / "condabin" / "conda")
    _touch(tmp_path / "bin" / "conda")
    e = env(EnvKind.CONDA, path=str(tmp_path), conda_packages={"certifi"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        f"{tmp_path}/condabin/conda update -p {tmp_path} certifi",
        None,
    )


def test_conda_base_with_only_bin_conda(tmp_path):
    _touch(tmp_path / "bin" / "conda")
    e = env(EnvKind.CONDA, path=str(tmp_path), conda_packages={"certifi"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert f.fix == f"{tmp_path}/bin/conda update -p {tmp_path} certifi"


def test_conda_named_env_uses_root_conda(tmp_path):
    _touch(tmp_path / "condabin" / "conda")
    foo = tmp_path / "envs" / "foo"
    foo.mkdir(parents=True)
    e = env(EnvKind.CONDA, path=str(foo), conda_packages={"certifi"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        f"{tmp_path}/condabin/conda update -p {foo} certifi",
        None,
    )


def test_conda_named_env_without_root_conda_falls_back(tmp_path):
    foo = tmp_path / "envs" / "foo"
    foo.mkdir(parents=True)
    e = env(EnvKind.CONDA, path=str(foo), conda_packages={"certifi"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert (f.status, f.fix, f.note) == (
        Status.OUTDATED,
        f"conda update -p {foo} certifi",
        None,
    )


def test_conda_binary_path_with_space_is_quoted(tmp_path):
    root = tmp_path / "my conda"
    _touch(root / "condabin" / "conda")
    foo = root / "envs" / "foo"
    foo.mkdir(parents=True)
    e = env(EnvKind.CONDA, path=str(foo), conda_packages={"certifi"})
    f = by_item(evaluate_env(e, MINS))["certifi"]
    assert f.fix == f"'{root}/condabin/conda' update -p '{foo}' certifi"


def test_conda_env_outside_envs_dir_uses_prefix():
    e = env(EnvKind.CONDA, path="/c/miniconda3", conda_packages={"certifi"})
    assert (
        by_item(evaluate_env(e, MINS))["certifi"].fix
        == "conda update -p /c/miniconda3 certifi"
    )


def test_conda_prefix_with_space_is_quoted():
    e = env(EnvKind.CONDA, path="/c/my env", conda_packages={"certifi"})
    assert (
        by_item(evaluate_env(e, MINS))["certifi"].fix
        == "conda update -p '/c/my env' certifi"
    )


def test_conda_pip_installed_package():
    e = env(
        EnvKind.CONDA, path="/c/envs/science", conda_packages={"pip", "ca-certificates"}
    )
    c = by_item(evaluate_env(e, MINS))["certifi"]
    assert (
        c.fix
        == '/c/envs/science/bin/python -m pip install --upgrade "certifi>=2026.10.19"'
    )
    assert c.note == "upgrade pip first; env mixes pip and conda packages"


def test_upgrade_pip_first_only_when_pip_outdated():
    pkgs = {"pip": GOOD["pip"], "certifi": "2025.1.1"}
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, packages=pkgs), MINS))
    assert (f["certifi"].status, f["certifi"].fix, f["certifi"].note) == (
        Status.OUTDATED,
        '/e/venv/bin/python -m pip install --upgrade "certifi>=2026.10.19"',
        None,
    )
    assert f["pip"].status is Status.OK


def test_conda_pip_certifi_with_current_pip_has_no_upgrade_pip_note():
    e = env(
        EnvKind.CONDA,
        path="/c/envs/science",
        packages={"pip": GOOD["pip"], "certifi": "2025.1.1", "ca-certificates": "1"},
        conda_packages={"pip", "ca-certificates"},
    )
    c = by_item(evaluate_env(e, MINS))["certifi"]
    assert c.note == "env mixes pip and conda packages"


EM_NOTE = (
    "externally managed Python; pip will refuse to change it — "
    "update environments created from it instead"
)


@pytest.mark.parametrize(
    "kind", [EnvKind.PLAIN_VENV, EnvKind.FRAMEWORK, EnvKind.PYENV, EnvKind.UV_PYTHON]
)
def test_externally_managed_gets_no_pip_fix(kind):
    e = env(kind, path="/u/uv/python/cpython-3.12", externally_managed=True)
    f = by_item(evaluate_env(e, MINS))
    for item in ("pip", "certifi"):
        assert (f[item].status, f[item].fix, f[item].note) == (
            Status.OUTDATED,
            None,
            EM_NOTE,
        )


def test_externally_managed_conda_pip_branch_gets_no_fix():
    e = env(
        EnvKind.CONDA,
        path="/c",
        conda_packages={"ca-certificates"},
        externally_managed=True,
    )
    f = by_item(evaluate_env(e, MINS))
    for item in ("pip", "certifi"):
        assert (f[item].status, f[item].fix, f[item].note) == (
            Status.OUTDATED,
            None,
            EM_NOTE,
        )
    # conda-installed packages are still updated with conda.
    assert f["ca-certificates"].fix == "conda update -p /c ca-certificates"


def test_system_outdated():
    f = by_item(evaluate_env(env(EnvKind.SYSTEM, path="/usr"), MINS))
    assert (f["pip"].status, f["pip"].fix, f["pip"].note) == (
        Status.OUTDATED,
        None,
        "system Python; leave to the OS package manager",
    )


def test_homebrew_outdated():
    f = by_item(evaluate_env(env(EnvKind.HOMEBREW, py="3.12.4"), MINS))
    assert (f["pip"].status, f["pip"].fix, f["pip"].note) == (
        Status.OUTDATED,
        "brew upgrade python@3.12",
        "managed by Homebrew",
    )


def test_homebrew_without_version_has_no_fix():
    f = by_item(evaluate_env(env(EnvKind.HOMEBREW, py=None), MINS))
    assert f["pip"].fix is None and f["pip"].note == "managed by Homebrew"


@pytest.mark.parametrize("kind", list(EnvKind))
def test_up_to_date_is_ok(kind):
    for f in evaluate_env(env(kind, packages=dict(GOOD)), MINS):
        assert (f.status, f.fix, f.note) == (Status.OK, None, None)


@pytest.mark.parametrize("kind", list(EnvKind))
def test_broken_venv_is_unknown(kind):
    fs = evaluate_env(PythonEnv(Path("/e"), kind, None, None), MINS)
    assert {f.item for f in fs} >= {"pip", "certifi"}
    for f in fs:
        assert (f.status, f.fix, f.note) == (
            Status.UNKNOWN,
            None,
            "could not read package metadata",
        )


def test_absent_package_in_readable_env_is_not_installed():
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV, packages={"pip": "26.2.2"}), MINS))
    assert (f["certifi"].status, f["certifi"].fix, f["certifi"].note) == (
        Status.NOT_INSTALLED,
        None,
        None,
    )


def test_unparsable_version_is_unknown():
    f = by_item(
        evaluate_env(
            env(EnvKind.PLAIN_VENV, packages={"pip": "x", "certifi": "y"}), MINS
        )
    )
    assert f["pip"].status is Status.UNKNOWN
    assert f["pip"].note == "could not read package metadata"


# --------------------------------------------------------- lockfiles


@pytest.mark.parametrize(
    ("fname", "pkg", "fix", "note"),
    [
        ("pixi.lock", "certifi", "cd /p && pixi update certifi", None),
        ("pixi.lock", "pip", "cd /p && pixi update pip", None),
        ("uv.lock", "certifi", "cd /p && uv lock --upgrade-package certifi", None),
        ("poetry.lock", "certifi", "cd /p && poetry update certifi", None),
        ("requirements.txt", "certifi", None, "edit the pin"),
        ("requirements-dev.txt", "pip", None, "edit the pin"),
    ],
)
def test_lockpin_outdated(fname, pkg, fix, note):
    f = evaluate_lockpin(LockPin(Path("/p") / fname, pkg, "1.0"), MINS)
    assert (f.status, f.fix, f.note) == (Status.OUTDATED, fix, note)
    assert f.category == "lockfile" and f.location == Path("/p") / fname
    assert f.minimum == MINS[pkg].min_version


def test_lockpin_cd_quotes_dir():
    f = evaluate_lockpin(LockPin(Path("/p q/uv.lock"), "certifi", "1.0"), MINS)
    assert f.fix == "cd '/p q' && uv lock --upgrade-package certifi"


def test_lockpin_ok():
    f = evaluate_lockpin(LockPin(Path("/p/uv.lock"), "certifi", "2026.10.19"), MINS)
    assert (f.status, f.fix) == (Status.OK, None)


def test_lockpin_without_advisory_is_no_advisory():
    f = evaluate_lockpin(LockPin(Path("/p/uv.lock"), "numpy", "1.0"), MINS)
    assert (f.status, f.fix, f.note) == (Status.NO_ADVISORY, None, "no advisory")


def test_env_package_without_advisory_is_no_advisory():
    mins = {k: v for k, v in MINS.items() if k != "certifi"}
    f = by_item(evaluate_env(env(EnvKind.PLAIN_VENV), mins))["certifi"]
    assert (f.status, f.fix, f.note) == (Status.NO_ADVISORY, None, "no advisory")


def test_lockpin_error_is_unknown():
    f = evaluate_lockpin(LockPin(Path("/p/pixi.lock"), "", None, "bad toml"), MINS)
    assert (f.status, f.fix, f.note) == (Status.UNKNOWN, None, "bad toml")
    assert f.item == "pixi.lock"


# -------------------------------------------------------------- scan


def _patch(monkeypatch, envs=(), tools=(), pins=()):
    calls = {}

    def d(*a, **k):
        calls["env"] = (a, k)
        return list(envs)

    def t(*a, **k):
        calls["tools"] = (a, k)
        return list(tools)

    def p(*a, **k):
        calls["pins"] = (a, k)
        return list(pins)

    monkeypatch.setattr(ev, "discover_environments", d)
    monkeypatch.setattr(ev, "scan_path_tools", t)
    monkeypatch.setattr(ev, "scan_lockfiles", p)
    return calls


def test_scan_full(monkeypatch):
    calls = _patch(
        monkeypatch,
        envs=[env(EnvKind.PLAIN_VENV)],
        tools=[tool("uv", InstallMethod.STANDALONE)],
        pins=[LockPin(Path("/p/uv.lock"), "certifi", "1.0")],
    )
    monkeypatch.setattr(ev, "rg_available", lambda: True)
    res = scan(Path("/h"), Path("/p"))
    assert calls["env"] == ((Path("/h"),), {"extra_roots": [Path("/p")]})
    assert calls["tools"] == ((Path("/h"),), {})
    assert calls["pins"] == ((Path("/p"),), {"recursive": True})
    assert [f.category for f in res.findings] == [
        "tool",
        "environment",
        "environment",
        "lockfile",
    ]
    assert res.used_rg is True and res.advisories


def test_scan_not_full(monkeypatch):
    calls = _patch(monkeypatch)
    monkeypatch.setattr(ev, "rg_available", lambda: False)
    res = scan(Path("/h"), Path("/p"), full=False)
    assert calls["env"] == (
        (Path("/h"),),
        {
            "extra_roots": [Path("/p")],
            "include_path_interpreters": False,
            "search_home": False,
        },
    )
    assert calls["tools"] == ((Path("/h"),), {})
    assert calls["pins"] == ((Path("/p"),), {"recursive": False})
    assert res.findings == [] and res.used_rg is False


@pytest.mark.parametrize("project", [Path("/h"), Path("/h/work/p")])
def test_scan_full_skips_project_inside_home(monkeypatch, project):
    calls = _patch(monkeypatch)
    monkeypatch.setattr(ev, "rg_available", lambda: True)
    scan(Path("/h"), project)
    assert calls["env"] == ((Path("/h"),), {"extra_roots": []})
    assert calls["pins"] == ((project,), {"recursive": True})


def test_scan_survives_a_bad_item(monkeypatch):
    _patch(
        monkeypatch,
        envs=[env(EnvKind.PLAIN_VENV, path="/e/bad")],
        tools=[
            tool("uv", InstallMethod.STANDALONE),
            tool("pixi", InstallMethod.STANDALONE),
        ],
        pins=[LockPin(Path("/p/uv.lock"), "certifi", "1.0")],
    )
    real_tool = ev.evaluate_tool

    def bad_tool(t, mins):
        if t.name == "uv":
            raise ValueError("boom")
        return real_tool(t, mins)

    def bad_env(e, mins):
        raise RuntimeError("env boom")

    monkeypatch.setattr(ev, "evaluate_tool", bad_tool)
    monkeypatch.setattr(ev, "evaluate_env", bad_env)
    res = scan(Path("/h"), Path("/p"))
    bad = [f for f in res.findings if f.note and f.note.startswith("internal error")]
    assert [(f.category, f.item, f.status) for f in bad] == [
        ("tool", "uv", Status.UNKNOWN),
        ("environment", "python environment", Status.UNKNOWN),
    ]
    assert bad[0].note == "internal error: ValueError('boom')"
    assert bad[1].location == Path("/e/bad") and bad[1].env_kind is EnvKind.PLAIN_VENV
    ok = [f for f in res.findings if f not in bad]
    assert {f.item for f in ok} == {"pixi", "certifi"}
