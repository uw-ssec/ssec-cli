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


def test_multiline_rows_separated_and_unbroken():
    fs = []
    for env in ("e10", "e11"):
        fs.append(
            _f(
                "environment",
                "pip",
                Status.OUTDATED,
                location=HOME / env,
                current="24.0",
                minimum="26.2.2",
                fix="fixpip " + env,
                note="shared note",
                env_kind=EnvKind.PLAIN_VENV,
            )
        )
        fs.append(
            _f(
                "environment",
                "certifi",
                Status.OUTDATED,
                location=HOME / env,
                current="2026.5.20",
                minimum="2026.10.19",
                fix="fixcert " + env,
                note="shared note",
                env_kind=EnvKind.PLAIN_VENV,
            )
        )
    con = Console(width=120, record=True, force_terminal=False)
    report.render(ScanResult(fs, [_adv()], True), con, HOME)
    text = con.export_text()
    assert text.count("pip 24.0 → 26.2.2") == 2
    assert text.count("certifi 2026.5.20 → 2026.10.19") == 2
    lines = text.splitlines()
    first = next(i for i, l in enumerate(lines) if "~/e10" in l)
    second = next(i for i, l in enumerate(lines) if "~/e11" in l)
    assert any(l.startswith("├") for l in lines[first:second])


def test_fix_cell_refs_before_notes():
    fs = [
        _f(
            "environment",
            "pip",
            Status.OUTDATED,
            location=HOME / "e",
            fix="cmd-a",
            note="managed by uv",
            env_kind=EnvKind.UV_PROJECT,
        ),
        _f(
            "environment",
            "certifi",
            Status.OUTDATED,
            location=HOME / "e",
            fix="cmd-b",
            note="managed by uv",
            env_kind=EnvKind.UV_PROJECT,
        ),
    ]
    con = Console(width=120, record=True, force_terminal=False)
    report.render(ScanResult(fs, [_adv()], True), con, HOME)
    text = con.export_text()
    assert "[1] [2]" in text
    assert text.count("managed by uv") == 1


def test_homebrew_formula_shown_and_in_json(monkeypatch):
    r = _result(
        [
            _f(
                "tool",
                "gh",
                Status.OK,
                location=Path("/x/gh"),
                current="1",
                install_method=InstallMethod.HOMEBREW,
                formula="gh",
            )
        ]
    )
    _patch(monkeypatch, r)
    assert "homebrew (gh)" in runner.invoke(app, ["tools", "check"]).output
    data = json.loads(runner.invoke(app, ["tools", "check", "--json"]).output)
    assert any(x["formula"] == "gh" for x in data["findings"])


def _no_advisory_result() -> ScanResult:
    return _result(
        [
            _f(
                "tool",
                name,
                Status.NO_ADVISORY,
                location=Path(f"/usr/bin/{name}"),
                current="2.0",
                note="no advisory",
                install_method=InstallMethod.SYSTEM,
            )
            for name in ("gh", "docker", "rg")
        ]
    )


def test_no_advisory_shown_as_na_and_not_counted():
    con = Console(width=160, record=True, force_terminal=False)
    report.render(_no_advisory_result(), con, HOME)
    text = con.export_text()
    rows = [line for line in text.splitlines() if "/usr/bin/docker" in line]
    assert len(rows) == 1 and "n/a" in rows[0]
    assert "OK" not in rows[0] and "no advisory" not in rows[0]
    # Same counts as without the three no-advisory tools.
    assert report.summary_line(_no_advisory_result().findings) == report.summary_line(
        _result().findings
    )
    assert "3 outdated · 1 unknown · 3 ok · 2 not installed" in text


def test_no_advisory_is_dim_na():
    assert report._status_text(Status.NO_ADVISORY).plain == "n/a"
    assert str(report._status_text(Status.NO_ADVISORY).style) == "dim"


def test_no_advisory_json_and_fail_on_outdated(monkeypatch):
    res = ScanResult(
        [_f("tool", "git", Status.NO_ADVISORY, location=Path("/usr/bin/git"))],
        [_adv()],
        True,
    )
    _patch(monkeypatch, res)
    r = runner.invoke(app, ["tools", "check", "--fail-on-outdated"])
    assert r.exit_code == 0
    assert "0 outdated · 0 unknown · 0 ok · 0 not installed" in r.output
    data = json.loads(runner.invoke(app, ["tools", "check", "--json"]).output)
    assert data["findings"][0]["status"] == "no_advisory"


def test_nonexistent_path_is_an_error(monkeypatch, tmp_path):
    _patch(monkeypatch, _result())
    missing = tmp_path / "typo"
    r = runner.invoke(app, ["tools", "check", "--path", str(missing)])
    assert r.exit_code != 0
    assert "does not exist" in r.output


def test_file_path_is_an_error(monkeypatch, tmp_path):
    _patch(monkeypatch, _result())
    f = tmp_path / "file.txt"
    f.write_text("")
    r = runner.invoke(app, ["tools", "check", "--path", str(f)])
    assert r.exit_code != 0


def test_relative_path_is_resolved(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(
        tools_cli, "scan", lambda home, path, **k: seen.append(path) or _result()
    )
    (tmp_path / "proj").mkdir()
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["tools", "check", "--path", "proj"])
    assert r.exit_code == 0
    assert seen == [(tmp_path / "proj").resolve()]
