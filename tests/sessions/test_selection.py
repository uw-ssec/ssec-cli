"""Tests for choosing which session files go into an archive."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ssec_cli.sessions.agents import ALL_AGENTS
from ssec_cli.sessions.selection import TimeWindow, parse_time_bound, select_files
from tests.sessions.conftest import make_wal_db, selected_paths, set_mtime

AGENTS = {a.name: a for a in ALL_AGENTS}


def test_select_all_files(fake_session_dir: Path) -> None:
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    assert selected_paths(selection) == [
        "proj1/conversation.json",
        "proj1/metadata.json",
        "proj2/conversation.json",
    ]
    assert selection.total_bytes == sum(p.stat().st_size for p in selection.files)


def test_jsonl_only(fake_session_dir: Path) -> None:
    (fake_session_dir / "proj1" / "s.jsonl").write_text("{}\n")
    selection = select_files(AGENTS["cursor"], fake_session_dir, jsonl_only=True)
    assert selected_paths(selection) == ["proj1/s.jsonl"]


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
    assert name not in selected_paths(selection)
    assert selection.excluded_credentials == 1


def test_symlinks_are_not_followed(fake_session_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (fake_session_dir / "link-file").symlink_to(outside / "secret.txt")
    (fake_session_dir / "link-dir").symlink_to(outside, target_is_directory=True)
    selection = select_files(AGENTS["cursor"], fake_session_dir)
    assert not any("link" in p for p in selected_paths(selection))


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
    assert selected_paths(selection) == [
        "proj1/conversation.json",
        "proj1/metadata.json",
    ]


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
    assert selected_paths(selection) == ["tmp/abc123/chats/session-1.json"]


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
    assert selected_paths(selection) == ["opencode.db", "storage/session/s.json"]


def test_time_window(fake_session_dir: Path) -> None:
    old = fake_session_dir / "proj1" / "conversation.json"
    new = fake_session_dir / "proj2" / "conversation.json"
    set_mtime(old, datetime(2026, 1, 15, 12).astimezone())
    set_mtime(new, datetime(2026, 6, 15, 12).astimezone())
    set_mtime(
        fake_session_dir / "proj1" / "metadata.json", datetime(2025, 1, 1).astimezone()
    )

    window = TimeWindow(
        start=parse_time_bound("2026-01-01", end=False),
        end=parse_time_bound("2026-03-01", end=True),
    )
    assert selected_paths(
        select_files(AGENTS["cursor"], fake_session_dir, window=window)
    ) == ["proj1/conversation.json"]

    since_only = TimeWindow(start=parse_time_bound("2026-02-01", end=False))
    assert selected_paths(
        select_files(AGENTS["cursor"], fake_session_dir, window=since_only)
    ) == ["proj2/conversation.json"]


def test_time_window_keeps_claude_sessions_whole(claude_root: Path) -> None:
    alpha = claude_root / "-work-alpha"
    set_mtime(alpha / "s1.jsonl", datetime(2020, 1, 1).astimezone())
    set_mtime(
        alpha / "s1" / "subagents" / "agent-1.jsonl", datetime(2026, 6, 1).astimezone()
    )
    set_mtime(
        claude_root / "-work-beta" / "s2.jsonl", datetime(2020, 1, 1).astimezone()
    )

    window = TimeWindow(start=parse_time_bound("2026-01-01", end=False))
    selection = select_files(AGENTS["claude-code"], claude_root, window=window)
    assert selected_paths(selection) == [
        "-work-alpha/s1.jsonl",
        "-work-alpha/s1/subagents/agent-1.jsonl",
    ]


def test_sqlite_wal_counts_toward_time_window(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    root.mkdir()
    conn = make_wal_db(root / "opencode.db")
    try:
        set_mtime(root / "opencode.db", datetime(2020, 1, 1).astimezone())
        window = TimeWindow(start=parse_time_bound("2026-01-01", end=False))
        selection = select_files(AGENTS["opencode"], root, window=window)
    finally:
        conn.close()
    assert selected_paths(selection) == ["opencode.db"]


def test_until_date_includes_whole_day() -> None:
    end = parse_time_bound("2026-06-15", end=True)
    assert TimeWindow(end=end).contains(
        datetime(2026, 6, 15, 23, 59).astimezone().timestamp()
    )
    assert not TimeWindow(end=end).contains(
        datetime(2026, 6, 16, 0, 0, 1).astimezone().timestamp()
    )


def test_until_basic_date_format_includes_whole_day() -> None:
    assert parse_time_bound("20261023", end=True) == parse_time_bound(
        "2026-10-23", end=True
    )


def test_parse_time_bound_with_timezone() -> None:
    assert (
        parse_time_bound("2026-06-15T00:00:00+00:00", end=False)
        == datetime(2026, 6, 15, tzinfo=UTC).timestamp()
    )


def test_parse_time_bound_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_time_bound("last tuesday", end=False)
