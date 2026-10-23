from pathlib import Path

from ssec_cli import main
from ssec_cli.tools.evaluate import Finding, ScanResult, Status

POINTER = "Run `ssec tools check` for the full report across all environments."
CLEAR = "No outdated tools found in PATH or this project."
HOME = Path("/home/u")


def _f(item, status, location=None, current="1.0", minimum="2.0", **kw):
    return Finding(
        category="tool",
        item=item,
        location=location,
        current=current,
        minimum=minimum,
        status=status,
        **kw,
    )


def _patch(monkeypatch, findings):
    calls = []

    def fake_scan(home, project, *, full=True):
        calls.append(full)
        return ScanResult(findings=findings, advisories=[], used_rg=False)

    monkeypatch.setattr(main, "scan", fake_scan)
    return calls


def test_summary_lists_only_outdated(monkeypatch, capsys):
    calls = _patch(
        monkeypatch,
        [
            _f("oldtool", Status.OUTDATED, HOME / "proj/.venv"),
            _f("goodtool", Status.OK, HOME / "x"),
        ],
    )
    main.print_tool_versions_summary(HOME, HOME / "proj")
    out = capsys.readouterr().out
    assert calls == [False]
    assert "## Tool versions" in out
    assert "oldtool" in out
    assert "1.0 → 2.0" in out
    assert "~/proj/.venv" in out
    assert "goodtool" not in out
    assert CLEAR not in out
    assert out.rstrip().endswith(POINTER)


def test_summary_all_clear(monkeypatch, capsys):
    _patch(monkeypatch, [_f("goodtool", Status.OK)])
    main.print_tool_versions_summary(HOME, HOME)
    out = capsys.readouterr().out
    assert "## Tool versions" in out
    assert CLEAR in out
    assert out.rstrip().endswith(POINTER)


def test_summary_unknown_is_flagged_not_clear(monkeypatch, capsys):
    _patch(
        monkeypatch,
        [
            _f(
                "mystery",
                Status.UNKNOWN,
                None,
                current=None,
                minimum=None,
                fix="rm /abs/x",
                note="secret note",
            )
        ],
    )
    main.print_tool_versions_summary(HOME, HOME)
    out = capsys.readouterr().out
    assert "mystery" in out
    assert "unknown" in out
    assert "PATH" in out
    assert CLEAR not in out
    assert "rm /abs/x" not in out
    assert "secret note" not in out


def test_summary_no_fix_in_output(monkeypatch, capsys):
    _patch(
        monkeypatch, [_f("t", Status.OUTDATED, HOME / "e", fix="pip install /abs/p")]
    )
    main.print_tool_versions_summary(HOME, HOME)
    assert "/abs/p" not in capsys.readouterr().out


def test_summary_scan_failure(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(main, "scan", boom)
    main.print_tool_versions_summary(HOME, HOME)
    out = capsys.readouterr().out
    assert "## Tool versions" in out
    assert "Unable to check tool versions: kaboom" in out


def test_summary_location_is_not_markup(monkeypatch, capsys):
    _patch(monkeypatch, [_f("[bold]x[/bold]", Status.OUTDATED, HOME / "a[red]b")])
    main.print_tool_versions_summary(HOME, HOME)
    out = capsys.readouterr().out
    assert "~/a[red]b" in out
    assert "[bold]x[/bold]" in out


def test_diagnostics_calls_summary_last(monkeypatch):
    order = []
    for name in (
        "print_platform_info",
        "check_tools",
        "get_git_status",
        "get_gh_auth_status",
    ):
        monkeypatch.setattr(main, name, lambda n=name: order.append(n))
    monkeypatch.setattr(
        main, "print_tool_versions_summary", lambda h, p: order.append("tv")
    )
    main.diagnostics()
    assert order[-1] == "tv"


def test_check_tools_lists_rg(monkeypatch, capsys):
    monkeypatch.setattr(main, "is_tool_installed", lambda t: (True, f"/bin/{t}"))
    main.check_tools()
    assert "rg" in capsys.readouterr().out


def test_summary_ignores_no_advisory(monkeypatch, capsys):
    _patch(
        monkeypatch,
        [_f("git", Status.NO_ADVISORY, HOME / "bin/git", minimum=None)],
    )
    main.print_tool_versions_summary(HOME, HOME)
    out = capsys.readouterr().out
    assert "git" not in out
    assert CLEAR in out
