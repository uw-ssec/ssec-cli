"""Tests for selecting session files and writing the archive."""

from __future__ import annotations

import json
import os
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ssec_cli.sessions import archive
from ssec_cli.sessions.agents import ALL_AGENTS
from ssec_cli.sessions.archive import (
    MANIFEST_NAME,
    ArchiveError,
    ProjectMatcher,
    TimeWindow,
    build_manifest,
    parse_time_bound,
    select_files,
    write_archive,
)

AGENTS = {a.name: a for a in ALL_AGENTS}


def _rel(selection) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(p.relative_to(selection.root).as_posix() for p in selection.files)


def _set_mtime(path: Path, when: datetime) -> None:
    ts = when.timestamp()
    os.utime(path, (ts, ts))


# --- whole-directory selection ---------------------------------------------


def test_select_all_files(fake_session_dir: Path) -> None:
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    assert _rel(selection) == [
        "proj1/conversation.json",
        "proj1/metadata.json",
        "proj2/conversation.json",
    ]
    assert selection.total_bytes == sum(p.stat().st_size for p in selection.files)


def test_jsonl_only(fake_session_dir: Path) -> None:
    (fake_session_dir / "proj1" / "s.jsonl").write_text("{}\n")
    selection = select_files(AGENTS["cursor"], fake_session_dir, jsonl_only=True)
    assert _rel(selection) == ["proj1/s.jsonl"]


@pytest.mark.parametrize(
    "name",
    [
        "auth.json",
        "mcp-auth.json",
        "oauth_creds.json",
        "mcp-oauth-tokens.json",
        "google_accounts.json",
        "settings.json",
        "id.pem",
        ".env",
        ".env.local",
        "token.json",
        "id_rsa",
        "Credentials.JSON",
    ],
)
def test_credential_files_are_excluded(fake_session_dir: Path, name: str) -> None:
    (fake_session_dir / name).write_text("secret")
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    assert name not in _rel(selection)
    assert selection.excluded_credentials == 1


def test_symlinks_are_not_followed(fake_session_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (fake_session_dir / "link-file").symlink_to(outside / "secret.txt")
    (fake_session_dir / "link-dir").symlink_to(outside, target_is_directory=True)
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    assert not any("link" in p for p in _rel(selection))


# --- time window -------------------------------------------------------------


def test_time_window(fake_session_dir: Path) -> None:
    old = fake_session_dir / "proj1" / "conversation.json"
    new = fake_session_dir / "proj2" / "conversation.json"
    _set_mtime(old, datetime(2026, 1, 15, 12).astimezone())
    _set_mtime(new, datetime(2026, 6, 15, 12).astimezone())
    _set_mtime(
        fake_session_dir / "proj1" / "metadata.json", datetime(2025, 1, 1).astimezone()
    )

    window = TimeWindow(
        start=parse_time_bound("2026-01-01", end=False),
        end=parse_time_bound("2026-03-01", end=True),
    )
    assert _rel(select_files(AGENTS["cursor"], fake_session_dir, window=window)) == [
        "proj1/conversation.json"
    ]

    since_only = TimeWindow(start=parse_time_bound("2026-02-01", end=False))
    assert _rel(
        select_files(AGENTS["cursor"], fake_session_dir, window=since_only)
    ) == ["proj2/conversation.json"]


def test_until_date_includes_whole_day() -> None:
    end = parse_time_bound("2026-06-15", end=True)
    assert TimeWindow(end=end).contains(
        datetime(2026, 6, 15, 23, 59).astimezone().timestamp()
    )
    assert not TimeWindow(end=end).contains(
        datetime(2026, 6, 16, 0, 0, 1).astimezone().timestamp()
    )


def test_parse_time_bound_with_timezone() -> None:
    assert (
        parse_time_bound("2026-06-15T00:00:00+00:00", end=False)
        == datetime(2026, 6, 15, tzinfo=UTC).timestamp()
    )


def test_parse_time_bound_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_time_bound("last tuesday", end=False)


# --- project filter ----------------------------------------------------------


@pytest.mark.parametrize("value", ["/work/alpha", "alpha"])
def test_project_claude_code(claude_root: Path, value: str) -> None:
    selection = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse(value)
    )
    assert _rel(selection) == [
        "-work-alpha/s1.jsonl",
        "-work-alpha/s1/subagents/agent-1.jsonl",
    ]


def test_project_claude_code_subdirectory_of_project(claude_root: Path) -> None:
    from tests.sessions.conftest import write_jsonl

    write_jsonl(
        claude_root / "-work-alpha-sub" / "s3.jsonl", [{"cwd": "/work/alpha/sub"}]
    )
    selection = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse("/work/alpha")
    )
    assert "-work-alpha-sub/s3.jsonl" in _rel(selection)

    by_name = select_files(
        AGENTS["claude-code"], claude_root, project=ProjectMatcher.parse("alpha")
    )
    assert "-work-alpha-sub/s3.jsonl" not in _rel(by_name)


def test_project_claude_code_falls_back_to_directory_name(tmp_path: Path) -> None:
    """A project directory with no recorded cwd is matched by its encoded name."""
    root = tmp_path / "projects"
    project = tmp_path / "my.repo"
    project.mkdir()
    encoded = "".join(c if c.isalnum() else "-" for c in str(project.resolve()))
    (root / encoded).mkdir(parents=True)
    (root / encoded / "s.jsonl").write_text('{"type": "summary"}\n')
    selection = select_files(
        AGENTS["claude-code"], root, project=ProjectMatcher.parse(str(project))
    )
    assert _rel(selection) == [f"{encoded}/s.jsonl"]


def test_project_codex(codex_root: Path) -> None:
    selection = select_files(
        AGENTS["codex"], codex_root, project=ProjectMatcher.parse("/work/beta")
    )
    assert _rel(selection) == ["2026/10/23/rollout-b.jsonl"]


def test_project_unsupported_agent(fake_session_dir: Path) -> None:
    with pytest.raises(ValueError):
        select_files(
            AGENTS["cursor"], fake_session_dir, project=ProjectMatcher.parse("alpha")
        )


def test_project_matcher_symlinked_path(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    matcher = ProjectMatcher.parse(str(link))
    assert matcher.matches(str(link))
    assert matcher.matches(str(real.resolve()))
    assert not matcher.matches(str(tmp_path / "other"))


# --- writing -----------------------------------------------------------------


def test_write_archive(claude_root: Path, codex_root: Path, tmp_path: Path) -> None:
    selections = [
        select_files(AGENTS["claude-code"], claude_root),
        select_files(AGENTS["codex"], codex_root),
    ]
    manifest = build_manifest(
        username="octocat",
        version="1.2.3",
        filters={"jsonl_only": False},
        created_at=datetime(2026, 10, 23, 12, tzinfo=UTC),
    )
    output = tmp_path / "out" / "archive.zip"

    result = write_archive(output, selections, manifest)

    assert result.path == output
    assert result.file_count == 5
    assert result.skipped == []
    assert list(output.parent.iterdir()) == [output], "temporary file left behind"

    with zipfile.ZipFile(output) as zf:
        names = sorted(zf.namelist())
        written = json.loads(zf.read(MANIFEST_NAME))
        assert (
            zf.read("codex/2026/10/23/rollout-b.jsonl")
            == (codex_root / "2026/10/23/rollout-b.jsonl").read_bytes()
        )

    assert names == [
        "claude-code/-work-alpha/s1.jsonl",
        "claude-code/-work-alpha/s1/subagents/agent-1.jsonl",
        "claude-code/-work-beta/s2.jsonl",
        "codex/2026/10/23/rollout-a.jsonl",
        "codex/2026/10/23/rollout-b.jsonl",
        MANIFEST_NAME,
    ]
    assert written["created_at"] == "2026-10-23T12:00:00+00:00"
    assert written["github_username"] == "octocat"
    assert written["ssec_cli_version"] == "1.2.3"
    assert written["filters"] == {"jsonl_only": False}
    assert [a["name"] for a in written["agents"]] == ["claude-code", "codex"]
    assert written["agents"][0]["source_path"] == str(claude_root)
    assert written["agents"][1]["file_count"] == 2
    assert written["agents"][1]["total_bytes"] == sum(
        p.stat().st_size for p in codex_root.rglob("*.jsonl")
    )


def test_write_archive_skips_unreadable_files(
    fake_session_dir: Path, tmp_path: Path
) -> None:
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    vanished = fake_session_dir / "proj2" / "conversation.json"
    vanished.unlink()

    result = write_archive(
        tmp_path / "a.zip",
        [selection],
        build_manifest(username="u", version="0", filters={}),
    )

    assert [path for path, _ in result.skipped] == [vanished]
    assert result.file_count == 2
    with zipfile.ZipFile(result.path) as zf:
        assert json.loads(zf.read(MANIFEST_NAME))["agents"][0]["file_count"] == 2


def test_write_archive_cleans_up_on_failure(
    fake_session_dir: Path, tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    selection = select_files(AGENTS["cursor"], fake_session_dir)

    def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt

    monkeypatch.setattr(zipfile.ZipFile, "writestr", boom)
    out_dir = tmp_path / "out"
    with pytest.raises(KeyboardInterrupt):
        write_archive(
            out_dir / "a.zip",
            [selection],
            build_manifest(username="u", version="0", filters={}),
        )
    assert list(out_dir.iterdir()) == []


# --- review fixes ------------------------------------------------------------


def test_session_subpaths_limit_gemini_to_chats(tmp_path: Path) -> None:
    root = tmp_path / "gemini"
    chat = root / "tmp" / "abc123" / "chats" / "session-1.json"
    chat.parent.mkdir(parents=True)
    chat.write_text("{}")
    (root / "settings.json").write_text('{"mcpServers": {"x": {"env": {"K": "v"}}}}')
    (root / "mcp-oauth-tokens.json").write_text("{}")
    (root / "extensions").mkdir()
    (root / "extensions" / "notes.md").write_text("x")

    selection = select_files(AGENTS["gemini-cli"], root)
    assert _rel(selection) == ["tmp/abc123/chats/session-1.json"]


def test_session_subpaths_opencode(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    (root / "snapshot" / "abc").mkdir(parents=True)
    (root / "snapshot" / "abc" / "HEAD").write_text("ref")
    (root / "log").mkdir()
    (root / "log" / "opencode.log").write_text("x")
    (root / "storage" / "session").mkdir(parents=True)
    (root / "storage" / "session" / "s.json").write_text("{}")
    (root / "auth.json").write_text("{}")
    (root / "opencode.db").write_bytes(b"x")

    selection = select_files(AGENTS["opencode"], root)
    assert _rel(selection) == ["opencode.db", "storage/session/s.json"]


def _make_wal_db(path: Path) -> sqlite3.Connection:
    """Create a WAL-mode database with an uncheckpointed row, left open."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t VALUES ('in-wal')")
    conn.commit()
    return conn


def test_sqlite_database_is_snapshotted_with_wal(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    root.mkdir()
    conn = _make_wal_db(root / "opencode.db")
    try:
        assert (root / "opencode.db-wal").stat().st_size > 0
        selection = select_files(AGENTS["opencode"], root)
        assert _rel(selection) == ["opencode.db"]

        result = write_archive(
            tmp_path / "a.zip",
            [selection],
            build_manifest(username="u", version="0", filters={}),
        )
    finally:
        conn.close()

    with zipfile.ZipFile(result.path) as zf:
        assert "opencode/opencode.db-wal" not in zf.namelist()
        (tmp_path / "restored.db").write_bytes(zf.read("opencode/opencode.db"))
    restored = sqlite3.connect(tmp_path / "restored.db")
    assert restored.execute("SELECT v FROM t").fetchall() == [("in-wal",)]
    restored.close()


def test_sqlite_wal_counts_toward_time_window(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    root.mkdir()
    conn = _make_wal_db(root / "opencode.db")
    try:
        _set_mtime(root / "opencode.db", datetime(2020, 1, 1).astimezone())
        window = TimeWindow(start=parse_time_bound("2026-01-01", end=False))
        selection = select_files(AGENTS["opencode"], root, window=window)
    finally:
        conn.close()
    assert _rel(selection) == ["opencode.db"]


def test_time_window_keeps_claude_sessions_whole(claude_root: Path) -> None:
    alpha = claude_root / "-work-alpha"
    _set_mtime(alpha / "s1.jsonl", datetime(2020, 1, 1).astimezone())
    _set_mtime(
        alpha / "s1" / "subagents" / "agent-1.jsonl", datetime(2026, 6, 1).astimezone()
    )
    _set_mtime(
        claude_root / "-work-beta" / "s2.jsonl", datetime(2020, 1, 1).astimezone()
    )

    window = TimeWindow(start=parse_time_bound("2026-01-01", end=False))
    selection = select_files(AGENTS["claude-code"], claude_root, window=window)
    assert _rel(selection) == [
        "-work-alpha/s1.jsonl",
        "-work-alpha/s1/subagents/agent-1.jsonl",
    ]


def test_until_basic_date_format_includes_whole_day() -> None:
    assert parse_time_bound("20261023", end=True) == parse_time_bound(
        "2026-10-23", end=True
    )


@pytest.mark.parametrize("insensitive", [True, False])
def test_project_matching_case(
    monkeypatch: pytest.MonkeyPatch, insensitive: bool
) -> None:
    monkeypatch.setattr(archive, "_CASE_INSENSITIVE_PATHS", insensitive)
    assert (
        ProjectMatcher.parse("/Work/Repos/X").matches("/work/repos/x/sub")
        is insensitive
    )
    assert ProjectMatcher(name="Alpha").matches("/work/alpha") is insensitive


def test_unreadable_directories_are_reported(fake_session_dir: Path) -> None:
    locked = fake_session_dir / "proj2"
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running with permissions that ignore chmod")
        selection = select_files(AGENTS["cursor"], fake_session_dir)
    finally:
        locked.chmod(0o755)
    assert selection.unreadable_dirs == [locked]
    assert _rel(selection) == ["proj1/conversation.json", "proj1/metadata.json"]


def test_unencodable_name_is_skipped(tmp_path: Path) -> None:
    source = tmp_path / "f.jsonl"
    source.write_text("{}")
    with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
        outcome = archive._add_file(zf, source, "agent/bad-\udcff.jsonl", tmp_path)
        assert isinstance(outcome, str)
        assert zf.namelist() == []


def test_failure_mid_copy_aborts_archive(
    fake_session_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selection = select_files(AGENTS["cursor"], fake_session_dir)

    def failing_copy(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(archive.shutil, "copyfileobj", failing_copy)
    out_dir = tmp_path / "out"
    with pytest.raises(ArchiveError, match="Failed while reading"):
        write_archive(
            out_dir / "a.zip",
            [selection],
            build_manifest(username="u", version="0", filters={}),
        )
    assert list(out_dir.iterdir()) == []


def test_sqlite_credential_tables_are_emptied(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    root.mkdir()
    conn = sqlite3.connect(root / "opencode.db")
    conn.executescript(
        """
        CREATE TABLE account (email TEXT, access_token TEXT);
        INSERT INTO account VALUES ('me@example.com', 'tok-SECRET-1');
        CREATE TABLE control_account (access_token TEXT);
        INSERT INTO control_account VALUES ('tok-SECRET-2');
        CREATE TABLE session_share (secret TEXT);
        INSERT INTO session_share VALUES ('tok-SECRET-3');
        CREATE TABLE credential (value TEXT);
        CREATE TABLE message (data TEXT);
        INSERT INTO message VALUES ('hello');
        """
    )
    conn.commit()
    conn.close()

    selection = select_files(AGENTS["opencode"], root)
    result = write_archive(
        tmp_path / "a.zip",
        [selection],
        build_manifest(username="u", version="0", filters={}),
    )

    with zipfile.ZipFile(result.path) as zf:
        raw = zf.read("opencode/opencode.db")
        manifest = json.loads(zf.read(MANIFEST_NAME))
    assert b"tok-SECRET" not in raw
    assert b"me@example.com" not in raw
    (tmp_path / "restored.db").write_bytes(raw)
    restored = sqlite3.connect(tmp_path / "restored.db")
    assert restored.execute("SELECT data FROM message").fetchall() == [("hello",)]
    assert restored.execute("SELECT count(*) FROM account").fetchone() == (0,)
    restored.close()
    assert manifest["agents"][0]["redacted_sqlite_tables"] == {
        "opencode.db": ["account", "control_account", "session_share"]
    }
