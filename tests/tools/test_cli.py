import json
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from ssec_cli.main import app
from ssec_cli.tools import cli as tools_cli
from ssec_cli.tools import report
from ssec_cli.tools.advisories import Advisory
from ssec_cli.tools.environments import EnvKind
from ssec_cli.tools.evaluate import Finding, ScanResult, Status
from ssec_cli.tools.path_tools import InstallMethod

runner = CliRunner()
HOME = Path.home()
LONG_FIX = "cd " + str(HOME / "a" / ("deep" * 30)) + " && " + "x" * 90 + " pip"


def _adv() -> Advisory:
    return Advisory(
        id="ADV-1",
        title="Test advisory title",
        date="2026-01-01",
        urls=["https://example.org/adv-1", "https://example.org/second"],
        minimums=[],
    )


def _f(category, item, status, **kw) -> Finding:
    return Finding(
        category=category,
        item=item,
        location=kw.pop("location", None),
        current=kw.pop("current", None),
        minimum=kw.pop("minimum", None),
        status=status,
        **kw,
    )


def _result(extra=()) -> ScanResult:
    fs = [
        _f(
            "tool",
            "uv",
            Status.OUTDATED,
            location=HOME / "bin" / "uv",
            current="0.1",
            minimum="0.2",
            fix="uv self update",
            install_method=InstallMethod.STANDALONE,
        ),
        _f("tool", "pip", Status.NOT_INSTALLED),
        _f("tool", "git", Status.OK, location=HOME / "bin" / "git", current="9"),
        _f(
            "environment",
            "pip",
            Status.OUTDATED,
            location=HOME / "e1",
            current="24.0",
            minimum="26.2.2",
            fix=LONG_FIX,
            env_kind=EnvKind.PLAIN_VENV,
        ),
        _f(
            "environment",
            "certifi",
            Status.UNKNOWN,
            location=HOME / "e4",
            note="no metadata",
            env_kind=EnvKind.PLAIN_VENV,
        ),
        _f(
            "environment",
            "pip",
            Status.OK,
            location=HOME / "e2",
            current="30",
            env_kind=EnvKind.CONDA,
        ),
        _f(
            "environment",
            "pip",
            Status.NOT_INSTALLED,
            location=HOME / "e3",
            env_kind=EnvKind.CONDA,
        ),
        _f(
            "lockfile",
            "certifi",
            Status.OUTDATED,
            location=HOME / "p" / "pixi.lock",
            current="1",
            minimum="2",
            fix=LONG_FIX,
        ),
        _f("lockfile", "pip", Status.OK, location=HOME / "q" / "uv.lock", current="9"),
        *extra,
    ]
    return ScanResult(findings=fs, advisories=[_adv()], used_rg=True)


def _patch(monkeypatch, result):
    monkeypatch.setattr(tools_cli, "scan", lambda *a, **k: result)


def test_check_renders_three_sections(monkeypatch):
    _patch(monkeypatch, _result())
    r = runner.invoke(app, ["tools", "check"])
    assert r.exit_code == 0
    for s in (
        "Tools on PATH",
        "Python environments",
        "Lockfiles",
        "Test advisory title",
        "https://example.org/adv-1",
        "docker build --no-cache",
        "python -m pip install --upgrade pip",
    ):
        assert s in r.output


def test_check_json_is_valid(monkeypatch):
    res = _result()
    _patch(monkeypatch, res)
    r = runner.invoke(app, ["tools", "check", "--json"])
    data = json.loads(r.output)
    assert len(data["advisories"]) == 1
    assert len(data["findings"]) == len(res.findings)
    assert all(
        not (x["location"] or "").startswith(str(HOME)) for x in data["findings"]
    )
    assert data["findings"][0]["location"].startswith("~/")
    assert data["findings"][0]["status"] == "outdated"


def test_fail_on_outdated_exit_code(monkeypatch):
    _patch(monkeypatch, _result())
    assert runner.invoke(app, ["tools", "check", "--fail-on-outdated"]).exit_code == 1
    assert runner.invoke(app, ["tools", "check"]).exit_code == 0
    ok = ScanResult(
        [_f("tool", "git", Status.OK), _f("tool", "pip", Status.NOT_INSTALLED)],
        [_adv()],
        True,
    )
    _patch(monkeypatch, ok)
    assert runner.invoke(app, ["tools", "check", "--fail-on-outdated"]).exit_code == 0


def test_unknown_never_green(monkeypatch):
    _patch(monkeypatch, _result())
    out = runner.invoke(app, ["tools", "check"]).output
    assert "UNKNOWN" in out
    assert "1 unknown" in out
    assert "3 outdated" in out


def test_long_fix_not_wrapped_and_numbered_once():
    con = Console(width=80, record=True, force_terminal=False)
    report.render(_result(), con, HOME)
    text = con.export_text()
    expected = LONG_FIX.replace(str(HOME), str(HOME))
    assert f"[2] {expected}" in text  # identical commands share one number
    assert text.count(expected) == 2  # once per Fixes block (env + lockfile tables)
    assert "[1] uv self update" in text


def test_grouping_and_collapse_lines():
    con = Console(width=120, record=True, force_terminal=False)
    report.render(_result(), con, HOME)
    text = con.export_text()
    assert "pip 24.0 → 26.2.2" in text
    assert "certifi ? (unknown)" in text
    assert "+ 2 environments up to date or without pip/certifi" in text
    assert "+ 1 lockfiles up to date" in text
    assert "not on PATH: pip" in text
    assert "~/e1" in text


def test_rg_note_and_json_quiet(monkeypatch):
    res = _result()
    res.used_rg = False
    _patch(monkeypatch, res)
    assert "ripgrep" in runner.invoke(app, ["tools", "check"]).output
    out = runner.invoke(app, ["tools", "check", "--json"]).output
    assert "ripgrep" not in out and "Containers" not in out
    json.loads(out)


def test_display_path():
    assert report.display_path(HOME / "x", HOME) == "~/x"
    assert report.display_path(HOME, HOME) == "~"
    assert report.display_path(Path("/etc/x"), HOME) == "/etc/x"
    assert report.display_path(None, HOME) == ""
