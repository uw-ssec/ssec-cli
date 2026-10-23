import shutil
from pathlib import Path

from ssec_cli.tools.lockfiles import parse_lockfile, scan_lockfiles

DATA = Path(__file__).parent / "data"


def _pairs(pins):
    return {(p.package, p.version) for p in pins}


def test_pixi_lock():
    pins = parse_lockfile(DATA / "pixi.lock")
    assert _pairs(pins) == {
        ("ca-certificates", "2025.8.3"),
        ("certifi", "2025.8.3"),
        ("certifi", "2026.10.19"),
    }
    assert len(pins) == 3
    assert all(p.error is None for p in pins)


def test_uv_lock():
    pins = parse_lockfile(DATA / "uv.lock")
    assert [(p.package, p.version) for p in pins] == [("certifi", "2025.8.3")]


def test_poetry_lock():
    pins = parse_lockfile(DATA / "poetry.lock")
    assert [(p.package, p.version) for p in pins] == [("certifi", "2025.8.3")]


def test_requirements_only_exact_pins():
    pins = parse_lockfile(DATA / "requirements.txt")
    assert [(p.package, p.version) for p in pins] == [("certifi", "2025.8.3")]


def test_malformed_uv_lock_is_unknown():
    pins = parse_lockfile(DATA / "bad_uv.lock")
    assert len(pins) == 1
    assert pins[0].error
    assert pins[0].package == ""
    assert pins[0].version is None
    assert pins[0].lockfile == DATA / "bad_uv.lock"


def test_scan_recurses_and_skips_envs(tmp_path):
    (tmp_path / "sub").mkdir()
    shutil.copy(DATA / "uv.lock", tmp_path / "sub" / "uv.lock")
    env = tmp_path / ".pixi" / "envs" / "x"
    env.mkdir(parents=True)
    shutil.copy(DATA / "requirements.txt", env / "requirements.txt")
    pins = scan_lockfiles(tmp_path)
    assert {p.lockfile for p in pins} == {tmp_path / "sub" / "uv.lock"}


def test_scan_non_recursive_ignores_subdirs(tmp_path):
    (tmp_path / "sub").mkdir()
    shutil.copy(DATA / "uv.lock", tmp_path / "sub" / "uv.lock")
    shutil.copy(DATA / "requirements.txt", tmp_path / "requirements-dev.txt")
    pins = scan_lockfiles(tmp_path, recursive=False)
    assert {p.lockfile for p in pins} == {tmp_path / "requirements-dev.txt"}


def test_unreadable_file_is_error(tmp_path):
    (tmp_path / "uv.lock").write_bytes(b"\xff\xfe\x00bad")
    pins = parse_lockfile(tmp_path / "uv.lock")
    assert len(pins) == 1 and pins[0].error
