"""Tests for writing session files to a zip archive."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ssec_cli.sessions import writer
from ssec_cli.sessions.agents import ALL_AGENTS
from ssec_cli.sessions.selection import select_files
from ssec_cli.sessions.writer import (
    MANIFEST_NAME,
    ArchiveError,
    build_manifest,
    write_archive,
)
from tests.sessions.conftest import make_wal_db, selected_paths

AGENTS = {a.name: a for a in ALL_AGENTS}


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


def test_failure_mid_copy_aborts_archive(
    fake_session_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selection = select_files(AGENTS["cursor"], fake_session_dir)

    def failing_copy(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(writer.shutil, "copyfileobj", failing_copy)
    out_dir = tmp_path / "out"
    with pytest.raises(ArchiveError, match="Failed while reading"):
        write_archive(
            out_dir / "a.zip",
            [selection],
            build_manifest(username="u", version="0", filters={}),
        )
    assert list(out_dir.iterdir()) == []


def test_unencodable_name_is_skipped(tmp_path: Path) -> None:
    source = tmp_path / "f.jsonl"
    source.write_text("{}")
    with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
        outcome = writer._add_file(zf, source, "agent/bad-\udcff.jsonl", tmp_path)
        assert isinstance(outcome, str)
        assert zf.namelist() == []


def test_sqlite_database_is_snapshotted_with_wal(tmp_path: Path) -> None:
    root = tmp_path / "opencode"
    root.mkdir()
    conn = make_wal_db(root / "opencode.db")
    try:
        assert (root / "opencode.db-wal").stat().st_size > 0
        selection = select_files(AGENTS["opencode"], root)
        assert selected_paths(selection) == ["opencode.db"]

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
