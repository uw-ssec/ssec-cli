"""Render a `ScanResult` as rich tables or JSON."""

import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ssec_cli.tools.evaluate import Finding, ScanResult, Status
from ssec_cli.tools.finder import RG_MISSING_NOTE

REMINDERS = (
    "Containers: rebuild images with the layer cache disabled "
    "(e.g. docker build --no-cache).",
    'New virtual environments: run "python -m pip install --upgrade pip" right '
    "after creating one, until CPython ships a fixed ensurepip.",
)

_STYLE = {
    Status.OK: ("OK", "green"),
    Status.OUTDATED: ("OUTDATED", "bold red"),
    Status.UNKNOWN: ("UNKNOWN", "yellow"),
    Status.SKIPPED: ("SKIPPED", "dim"),
    Status.NOT_INSTALLED: ("not installed", "dim"),
    Status.NO_ADVISORY: ("n/a", "dim"),
}
_QUIET_NOTES = (Status.OK, Status.NO_ADVISORY)
_RANK = {Status.OUTDATED: 0, Status.UNKNOWN: 1}


def display_path(p: Path | None, home: Path) -> str:
    if p is None:
        return ""
    try:
        rel = p.relative_to(home)
    except ValueError:
        return str(p)
    return "~" if str(rel) == "." else f"~/{rel}"


def _status_text(s: Status) -> Text:
    label, style = _STYLE[s]
    return Text(label, style=style)


def to_json(result: ScanResult, home: Path) -> str:
    findings = []
    for f in result.findings:
        findings.append(
            {
                "category": f.category,
                "item": f.item,
                "location": display_path(f.location, home) if f.location else None,
                "current": f.current,
                "minimum": f.minimum,
                "status": f.status.value,
                "advisory_id": f.advisory_id,
                "fix": f.fix,
                "note": f.note,
                "env_kind": f.env_kind.value if f.env_kind else None,
                "install_method": f.install_method.value if f.install_method else None,
                "formula": f.formula,
            }
        )
    advisories = [
        {"id": a.id, "title": a.title, "date": a.date, "urls": a.urls}
        for a in result.advisories
    ]
    return json.dumps(
        {"advisories": advisories, "findings": findings, "used_rg": result.used_rg},
        indent=2,
    )


class _Fixes:
    """Global numbering of distinct fix commands."""

    def __init__(self) -> None:
        self.numbers: dict[str, int] = {}

    def ref(self, cmd: str) -> int:
        return self.numbers.setdefault(cmd, len(self.numbers) + 1)


def _fix_cell(findings: list[Finding], fixes: _Fixes, used: dict[int, str]) -> Text:
    refs: list[str] = []
    notes: list[str] = []
    for f in findings:
        if f.fix:
            n = fixes.ref(f.fix)
            used[n] = f.fix
            if f"[{n}]" not in refs:
                refs.append(f"[{n}]")
        if f.note and f.status not in _QUIET_NOTES and f.note not in notes:
            notes.append(f.note)
    return Text("\n".join(filter(None, [" ".join(refs), "; ".join(notes)])))


def _print_fixes(console: Console, used: dict[int, str]) -> None:
    if not used:
        return
    console.print("Fixes:", style="bold")
    for n in sorted(used):
        console.print(f"[{n}] {used[n]}", soft_wrap=True, highlight=False, markup=False)


def _by_location(findings: list[Finding]) -> dict[Path | None, list[Finding]]:
    groups: dict[Path | None, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.location, []).append(f)
    return groups


def _detail(f: Finding) -> str:
    if f.status is Status.OUTDATED:
        return f"{f.item} {f.current} → {f.minimum}"
    return f"{f.item} {f.current or '?'} (unknown)"


def _grouped_table(
    title: str,
    category: str,
    findings: list[Finding],
    console: Console,
    home: Path,
    fixes: _Fixes,
    collapse_text: str,
) -> None:
    groups = _by_location(findings)
    flagged = []
    quiet = 0
    for loc, fs in groups.items():
        bad = [f for f in fs if f.status in _RANK]
        if bad:
            flagged.append((loc, bad))
        else:
            quiet += 1
    flagged.sort(key=lambda g: min(_RANK[f.status] for f in g[1]))
    table = Table(title=title, title_justify="left", show_lines=True)
    table.add_column("Item", no_wrap=True)
    table.add_column("Location", overflow="fold")
    if category == "environment":
        table.add_column("Kind")
    table.add_column("Status")
    table.add_column("Fix / note")
    used: dict[int, str] = {}
    for loc, bad in flagged:
        worst = min((f.status for f in bad), key=lambda s: _RANK[s])
        row = [Text("\n".join(_detail(f) for f in bad)), Text(display_path(loc, home))]
        if category == "environment":
            kind = bad[0].env_kind
            row.append(Text(kind.value if kind else ""))
        row += [_status_text(worst), _fix_cell(bad, fixes, used)]
        table.add_row(*row)
    if flagged:
        console.print(table)
    else:
        console.print(Text(f"{title}: nothing outdated or unknown.", style="bold"))
    if quiet:
        console.print(f"+ {quiet} {collapse_text}", style="dim", markup=False)
    _print_fixes(console, used)
    console.print()


def _installed_via(f: Finding) -> str:
    if not f.install_method:
        return ""
    via = f.install_method.value
    return f"{via} ({f.formula})" if f.formula else via


def _tools_table(
    findings: list[Finding], console: Console, home: Path, fixes: _Fixes
) -> None:
    shown = [f for f in findings if f.status is not Status.NOT_INSTALLED]
    missing = [f.item for f in findings if f.status is Status.NOT_INSTALLED]
    shown.sort(key=lambda f: _RANK.get(f.status, 2))
    table = Table(title="Tools on PATH", title_justify="left")
    table.add_column("Item")
    table.add_column("Location", overflow="fold")
    for c in ("Installed via", "Current", "Minimum", "Status"):
        table.add_column(c)
    table.add_column("Fix / note")
    used: dict[int, str] = {}
    for f in shown:
        table.add_row(
            Text(f.item),
            Text(display_path(f.location, home)),
            Text(_installed_via(f)),
            Text(f.current or ""),
            Text(f.minimum or ""),
            _status_text(f.status),
            _fix_cell([f], fixes, used),
        )
    if shown:
        console.print(table)
    else:
        console.print(Text("Tools on PATH", style="bold"))
    if missing:
        console.print(f"not on PATH: {', '.join(missing)}", style="dim", markup=False)
    _print_fixes(console, used)
    console.print()


def summary_line(findings: list[Finding]) -> str:
    # NO_ADVISORY items are listed without a status, so they are not counted.
    c = Counter(f.status for f in findings)
    parts = [
        f"{c[Status.OUTDATED]} outdated",
        f"{c[Status.UNKNOWN]} unknown",
        f"{c[Status.OK]} ok",
        f"{c[Status.NOT_INSTALLED]} not installed",
    ]
    if c[Status.SKIPPED]:
        parts.append(f"{c[Status.SKIPPED]} skipped")
    return " · ".join(parts)


def render(result: ScanResult, console: Console, home: Path) -> None:
    fixes = _Fixes()
    by_cat = {"tool": [], "environment": [], "lockfile": []}
    for f in result.findings:
        by_cat[f.category].append(f)
    _tools_table(by_cat["tool"], console, home, fixes)
    _grouped_table(
        "Python environments",
        "environment",
        by_cat["environment"],
        console,
        home,
        fixes,
        "environments up to date or without pip/certifi",
    )
    _grouped_table(
        "Lockfiles",
        "lockfile",
        by_cat["lockfile"],
        console,
        home,
        fixes,
        "lockfiles up to date",
    )
    console.print(summary_line(result.findings), style="bold", markup=False)
    for a in result.advisories:
        console.print(f"\n{a.title} ({a.date})", style="bold", markup=False)
        for u in a.urls:
            console.print(f"  {u}", soft_wrap=True, highlight=False, markup=False)
    console.print()
    for r in REMINDERS:
        console.print(r, soft_wrap=True, markup=False, highlight=False)
    if not result.used_rg:
        console.print(RG_MISSING_NOTE, style="dim", markup=False, highlight=False)
