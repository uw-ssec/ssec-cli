# `ssec tools check` (Release 1) Implementation Plan

> [!NOTE] > **AI assistance disclosure:** Claude Code
> (`claude-code:claude-opus-5-5`) drafted this plan from the approved design.
> The maintainer reviews it before execution.

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `ssec tools check`, a read-only report of tool, Python
environment and lockfile versions compared with bundled security-advisory
minimums, plus a "Tool versions" summary in `ssec diagnostics`.

**Architecture:** A new `ssec_cli.tools` package splits the work into four
stages: **discover** (find files, environments, tools and lockfiles, producing
raw facts), **evaluate** (compare the facts with `advisories.toml`, producing
`Finding`s with a status and a fix command), **render** (rich tables or JSON),
and the **CLI** (a typer sub-app). Discovery and the env classification are kept
separate from evaluation, so release 2 (`ssec tools update`) can reuse the scan
and turn each `Finding.fix` into an action.

**Tech Stack:** Python ≥ 3.10, typer, rich, `tomllib` (`tomli` on 3.10), ripgrep
(optional at runtime), pytest.

**Spec:** `docs/superpowers/specs/2026-10-23-tools-check-update-design.md`
(release 1 only; the `update` section is out of scope here).

## Global Constraints

- `requires-python = ">=3.10"`. Runtime deps: stdlib, `typer`, `rich`, and
  `tomli; python_version < "3.11"`. Nothing else, not even `packaging`, which
  isn't in the runtime env.
- Strictly read-only: never write, chmod or delete any scanned file, and make no
  network calls.
- Read package versions from metadata (`*.dist-info`, `conda-meta/*.json`) and
  never run an environment's Python. The only interpreters ever executed are
  `python`/`python3` found on `PATH` that aren't inside a discovered env (Task
  3), and those only with `-I -c` and a 5 s timeout.
- Every `subprocess.run` has a `timeout` (5 s for `--version` calls, 120 s for
  `rg`).
- `rg` is optional. When it isn't on `PATH`, fall back to `os.walk` and print
  this note once:
  `Note: ripgrep (rg) not found; using a slower built-in search. Install it with \`pixi
  global install ripgrep\` or \`brew install ripgrep\`.`
- macOS and Linux must fully work. Windows must not crash: handle the `Scripts/`
  / `Lib/site-packages` layout, and report anything unsupported as `UNKNOWN`
  with note `unsupported on Windows`.
- UNKNOWN is never displayed or counted as fine.
- Show paths under home as `~/…` in all output.
- Commits use the trailer `Assisted-by: claude-code:<model>`, never an AI
  `Co-Authored-By`. Run `pixi exec pre-commit run --all-files` before the PR.

## Review Focus

1. **Unreadable or looping directories in a home-directory scan** (permission
   denied, symlink loops, a vanished file): skip them silently and keep
   scanning. Test: `test_walk_skips_unreadable_dir` in Task 2.
2. **Broken environments** (a `pyvenv.cfg` with no `site-packages`, a
   half-deleted conda env): report pip/certifi as `UNKNOWN`, never
   `NOT_INSTALLED` or `OK`. Test: `test_broken_venv_is_unknown` in Task 6.
3. **Odd `--version` output** (`uv 0.13.4 (Homebrew 2026-10-21)`,
   `pip 26.2.2 from /x (python 3.12)`, empty output, a hang): extract the
   version, or report UNKNOWN after the timeout. Test:
   `test_extract_version_variants` in Task 4.
4. **Version strings with suffixes** (`26.2.2.post1`, `26.2.2rc1`, `2026.10.19`,
   `0.13.4+local`): compare correctly against minimums. Test:
   `test_is_below_edge_cases` in Task 1.
5. **A malformed lockfile** (invalid TOML or truncated YAML): one UNKNOWN row
   for that file, and the scan continues. Test:
   `test_malformed_uv_lock_is_unknown` in Task 5.

---

## File Structure

| File                                 | Responsibility                                                 |
| ------------------------------------ | -------------------------------------------------------------- |
| `pyproject.toml`                     | python floor, runtime deps, ship `advisories.toml`, pytest cfg |
| `pixi.toml`                          | add `ripgrep`                                                  |
| `src/ssec_cli/advisories.toml`       | bundled advisory data                                          |
| `src/ssec_cli/tools/__init__.py`     | empty package marker                                           |
| `src/ssec_cli/tools/versions.py`     | version parsing / comparison                                   |
| `src/ssec_cli/tools/advisories.py`   | load `advisories.toml`                                         |
| `src/ssec_cli/tools/finder.py`       | `rg` search with `os.walk` fallback                            |
| `src/ssec_cli/tools/environments.py` | discover, classify and read Python environments                |
| `src/ssec_cli/tools/path_tools.py`   | tools on `PATH`, their versions and install methods            |
| `src/ssec_cli/tools/lockfiles.py`    | find and parse lockfiles                                       |
| `src/ssec_cli/tools/evaluate.py`     | `Finding`, `Status`, `scan()`, fix commands                    |
| `src/ssec_cli/tools/report.py`       | rich and JSON output                                           |
| `src/ssec_cli/tools/cli.py`          | `tools_app` typer sub-app with `check`                         |
| `src/ssec_cli/main.py`               | register `tools`, add diagnostics summary                      |
| `README.md`                          | document `ssec tools check`                                    |
| `tests/tools/…`                      | one test module per source module, plus `conftest.py` fixtures |

---

### Task 1: Packaging, advisory data and version comparison

**Files:**

- Modify: `pyproject.toml`, `pixi.toml`
- Create: `src/ssec_cli/advisories.toml`, `src/ssec_cli/tools/__init__.py`,
  `src/ssec_cli/tools/versions.py`, `src/ssec_cli/tools/advisories.py`
- Test: `tests/tools/test_versions.py`, `tests/tools/test_advisories.py`

**Interfaces:**

- Produces:

  - `versions.parse_version(text: str) -> tuple[tuple[int, ...], bool] | None`:
    the release numbers and `is_prerelease`. `None` if no leading number is
    found.
  - `versions.is_below(current: str, minimum: str) -> bool | None`: `None` when
    either side can't be parsed.
  - `versions.extract_version(text: str) -> str | None`: the first
    `\d+(\.\d+)+[0-9A-Za-z.+-]*` token.
  - `advisories.PackageMinimum(package: str, min_version: str, advisory_id: str, fix_url: str | None = None, fix_sha256: str | None = None)`
    (frozen dataclass)
  - `advisories.Advisory(id: str, title: str, date: str, urls: list[str], minimums: list[PackageMinimum])`
  - `advisories.load_advisories(path: Path | None = None) -> list[Advisory]`
    (default: the bundled file, via `importlib.resources`)
  - `advisories.minimums_by_package(advs: list[Advisory]) -> dict[str, PackageMinimum]`:
    the highest minimum per normalized package name (PEP 503: lowercase, runs of
    `-_.` become `-`).
  - `advisories.normalize_name(name: str) -> str`

- [ ] **Step 1: Packaging.** In `pyproject.toml`, set
      `requires-python = ">=3.10"`, set
      `dependencies = ["typer>=0.9.0", "rich", "tomli>=1.1; python_version < '3.11'"]`,
      remove the 3.8/3.9 classifiers and add 3.13/3.14, and add
      `[tool.pytest.ini_options] testpaths = ["tests"]`. In `pixi.toml`, add
      `ripgrep = "*"` under `[dependencies]` and `python = ">=3.10,<3.15"`.
      Hatch includes non-Python files under `packages`, so nothing else is
      needed. Step 7 confirms the wheel contains `advisories.toml`.

- [ ] **Step 2: Write `src/ssec_cli/advisories.toml`.**

```toml
schema_version = 1

[[advisory]]
id = "2026-10-emudhra-emsign"
title = "eMudhra / emSign CA private keys compromised; emSign root removed from CA bundles"
date = "2026-10-20"
urls = [
  "https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576",
  "https://github.com/pypa/pip/issues/14374",
]

[[advisory.minimum]]
package = "certifi"
min_version = "2026.10.19"

[[advisory.minimum]]
package = "ca-certificates"
min_version = "VERIFY"   # see Step 3

[[advisory.minimum]]
package = "pip"
min_version = "26.2.2"
fix_url = "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl"
fix_sha256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"

[[advisory.minimum]]
package = "uv"
min_version = "0.13.4"

[[advisory.minimum]]
package = "sigstore"
min_version = "4.5.1"

[[advisory.minimum]]
package = "conda"
min_version = "26.9.4"

[[advisory.minimum]]
package = "pixi"
min_version = "0.82.1"
```

- [ ] **Step 3: Verify the pinned values. Do not skip this.**

  - Re-fetch `https://pypi.org/pypi/pip/26.2.2/json` and confirm the
    `bdist_wheel` `url` and `digests.sha256` match Step 2 exactly.
  - For `ca-certificates`, find the first conda-forge version whose bundle no
    longer contains emSign. Check `conda-forge/ca-certificates-feedstock`
    commits/PRs from 2026-10-18 on, and the version list at
    `https://api.anaconda.org/package/conda-forge/ca-certificates`. Write that
    version in place of `VERIFY`. If it can't be confirmed from the feedstock,
    **stop and ask the maintainer**. Don't guess.

- [ ] **Step 4: Write the failing tests.**

```python
# tests/tools/test_versions.py
from ssec_cli.tools.versions import is_below, extract_version, parse_version

def test_is_below_basic():
    assert is_below("26.2.1", "26.2.2") is True
    assert is_below("26.2.2", "26.2.2") is False
    assert is_below("26.10", "26.9.4") is False
    assert is_below("2025.8.3", "2026.10.19") is True

def test_is_below_edge_cases():
    assert is_below("26.2.2.post1", "26.2.2") is False
    assert is_below("26.2.2rc1", "26.2.2") is True     # pre-release of the minimum is below it
    assert is_below("0.13.4+local", "0.13.4") is False
    assert is_below("26.2", "26.2.0") is False          # zero-padding
    assert is_below("garbage", "1.0") is None

def test_extract_version():
    assert extract_version("pip 26.2.2 from /x/site-packages/pip (python 3.12)") == "26.2.2"
    assert extract_version("uv 0.13.4 (Homebrew 2026-10-21)") == "0.13.4"
    assert extract_version("") is None
```

```python
# tests/tools/test_advisories.py
from ssec_cli.tools.advisories import load_advisories, minimums_by_package, normalize_name

def test_bundled_file_loads_and_has_emsign():
    advs = load_advisories()
    assert advs[0].id == "2026-10-emudhra-emsign"
    mins = minimums_by_package(advs)
    assert mins["pip"].min_version == "26.2.2"
    assert mins["pip"].fix_sha256 and len(mins["pip"].fix_sha256) == 64
    assert mins["certifi"].min_version == "2026.10.19"
    assert all(m.min_version != "VERIFY" for m in mins.values())

def test_highest_minimum_wins(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text(
        'schema_version = 1\n'
        '[[advisory]]\nid="a"\ntitle="A"\ndate="2026-01-01"\nurls=[]\n'
        '[[advisory.minimum]]\npackage="certifi"\nmin_version="1.0"\n'
        '[[advisory]]\nid="b"\ntitle="B"\ndate="2026-02-01"\nurls=[]\n'
        '[[advisory.minimum]]\npackage="Certifi"\nmin_version="2.0"\n'
    )
    mins = minimums_by_package(load_advisories(f))
    assert mins["certifi"].min_version == "2.0"
    assert mins["certifi"].advisory_id == "b"

def test_normalize_name():
    assert normalize_name("Ca_Certificates") == "ca-certificates"
```

- [ ] **Step 5:** Run `pixi run -e dev pytest tests/tools -q`. Expected: FAIL
      (ImportError).
- [ ] **Step 6: Implement `versions.py` and `advisories.py`** with the
      signatures above. Comparison: zero-pad the release tuples to equal length
      and compare them. If they're equal, the current version is below the
      minimum only when it's a pre-release (`a`, `b`, `rc`, `dev` right after
      the release digits) and the minimum isn't. Ignore `post` / `+local`
      suffixes. Import `tomllib`, falling back to `tomli`.
- [ ] **Step 7:** Run the tests, expect PASS. Then run
      `pixi exec --spec hatch hatch build -t wheel` and
      `unzip -l dist/*.whl | grep advisories.toml`. Expected: one line. Delete
      `dist/`.
- [ ] **Step 8: Commit:**
      `feat(tools): bundle advisory data and version comparison`

---

### Task 2: File finder with ripgrep and fallback

**Files:** Create `src/ssec_cli/tools/finder.py`. Test:
`tests/tools/test_finder.py`.

**Interfaces:**

- Produces:

  - `finder.DEFAULT_EXCLUDES: tuple[str, ...]` =
    `(".git", "node_modules", ".Trash", "Library/Caches", "Library/Containers", "Library/Group Containers", ".cache", ".npm", ".cargo/registry", ".rustup", "go/pkg", "site-packages")`.
    Excluding `site-packages` stops the search from walking into installed
    packages. `.pixi` and venv directories are **not** excluded.
  - `finder.find_files(roots: list[Path], patterns: list[str], excludes: Sequence[str] = DEFAULT_EXCLUDES, use_rg: bool | None = None) -> list[Path]`:
    returns files whose path relative to a root matches any glob pattern (rg
    glob syntax, e.g. `**/pyvenv.cfg`, `**/conda-meta/history`,
    `**/requirements*.txt`). The result is sorted, has no duplicates, and skips
    roots that don't exist. `use_rg=None` means auto-detect.
  - `finder.rg_available() -> bool`

- [ ] **Step 1: Failing tests** in `test_finder.py`, each run with both
      `use_rg=False` and (`pytest.mark.skipif(not rg_available())`)
      `use_rg=True` via parametrize:
  - `test_finds_patterns`: in `tmp_path`, create `a/.venv/pyvenv.cfg`,
    `b/.pixi/envs/default/conda-meta/history` and `c/requirements-dev.txt`.
    Assert all three are found with the patterns above.
  - `test_respects_excludes`: `node_modules/x/pyvenv.cfg` is not found.
  - `test_hidden_and_gitignored_found`: `.hidden/pyvenv.cfg` plus a `.gitignore`
    containing `.hidden` is still found.
  - `test_walk_skips_unreadable_dir` (POSIX only): create a dir with mode
    `0o000` next to a findable file. The file is still found and nothing raises.
    Restore the mode in `finally`.
  - `test_walk_does_not_follow_symlink_loops`: `loop -> .`. The search
    terminates.
- [ ] **Step 2:** Run, expect FAIL.
- [ ] **Step 3: Implement.** rg command:
      `rg --files --hidden --no-ignore --no-messages --no-follow` plus
      `--glob <p>` for each pattern and `--glob !**/<e>/**` for each exclude,
      run with `cwd=root`, `timeout=120`. Exit codes 0, 1 and 2 are all usable
      (2 = partial errors). The fallback is
      `os.walk(root, onerror=lambda e: None, followlinks=False)`, pruning
      excluded dirs in place and matching with `fnmatch` against the `/`-joined
      relative path (with a `**/` prefix that also matches zero dirs).
- [ ] **Step 4:** Run, expect PASS.
- [ ] **Step 5: Commit:**
      `feat(tools): add file finder with ripgrep and os.walk fallback`

---

### Task 3: Python environment discovery and classification

**Files:** Create `src/ssec_cli/tools/environments.py`. Test:
`tests/tools/test_environments.py`, plus a fixture builder in
`tests/tools/conftest.py`.

**Interfaces:**

- Consumes: `finder.find_files`, `advisories.normalize_name`,
  `versions.extract_version`.
- Produces:

  - `class EnvKind(str, Enum)`: `PLAIN_VENV`, `UV_PROJECT`, `UV_TOOL`, `PIPX`,
    `PIXI_PROJECT`, `PIXI_GLOBAL`, `CONDA`, `FRAMEWORK`, `PYENV`, `UV_PYTHON`,
    `HOMEBREW`, `SYSTEM`
  - `@dataclass PythonEnv`: `path: Path`, `kind: EnvKind`,
    `python_version: str | None`, `packages: dict[str, str] | None` (normalized
    name to version, `None` if the site-packages/conda-meta couldn't be read),
    `conda_packages: set[str]` (names installed by conda),
    `project: Path | None` (the pixi/uv project root), `tool_name: str | None`
    (uv tool / pipx / pixi global name), `externally_managed: bool`
  - `discover_environments(home: Path, extra_roots: list[Path] = [], include_path_interpreters: bool = True) -> list[PythonEnv]`
  - `classify_env(path: Path, home: Path) -> EnvKind` (pure, path and marker
    based)
  - `read_env_packages(path: Path) -> tuple[dict[str, str] | None, set[str]]`
  - `python_executable(env: PythonEnv) -> Path` (`bin/python` on POSIX,
    `python.exe` / `Scripts/python.exe` on Windows; used in fix text and by
    release 2)

- [ ] **Step 1: Fixture builder** in `conftest.py`:
      `make_venv(root, *, uv=False, pkgs={"pip": "24.0", "certifi": "2025.8.3"}, py="3.12", windows=False)`,
      `make_conda_env(root, pkgs, pip_pkgs={})` (writes
      `conda-meta/<name>-<ver>-<build>.json` with `{"name","version"}` and
      `conda-meta/history`, and puts `pip_pkgs` only as dist-info) and
      `make_framework(root, version)`.
- [ ] **Step 2: Failing tests:**
  - `test_classify`: one case per kind, built in `tmp_path` as home:
    - `proj/.venv` + `pyvenv.cfg` with `uv = 0.13.4` + `proj/uv.lock` →
      `UV_PROJECT`
    - the same without `uv.lock` → `PLAIN_VENV`
    - `.local/share/uv/tools/ruff` → `UV_TOOL`
    - `.local/pipx/venvs/black` and `.local/share/pipx/venvs/black` → `PIPX`
    - `proj/.pixi/envs/default` → `PIXI_PROJECT`
    - `.pixi/envs/ruff` → `PIXI_GLOBAL`
    - `miniforge3/envs/x` → `CONDA`
    - `.pyenv/versions/3.12.1` → `PYENV`
    - `.local/share/uv/python/cpython-3.12…` → `UV_PYTHON`
  - `test_read_packages_venv`: versions are read from `pip-24.0.dist-info` and
    `certifi-2025.8.3.dist-info`, with names normalized.
  - `test_read_packages_windows_layout`: the same via `Lib/site-packages`.
  - `test_conda_env_tracks_conda_vs_pip`: certifi installed by conda is in
    `conda_packages`, and pip installed by pip is in `packages` but not in
    `conda_packages`.
  - `test_discover_finds_all_and_dedupes`: a home with one of each kind is
    discovered once each. A conda env that is both under home and listed by
    `conda env list` (monkeypatch the subprocess call) appears once.
  - `test_externally_managed`: a stdlib dir containing `EXTERNALLY-MANAGED` →
    `externally_managed=True`.
- [ ] **Step 3:** Run, expect FAIL.
- [ ] **Step 4: Implement.**
  - **Discovery:** call
    `find_files([home, *extra_roots], ["**/pyvenv.cfg", "**/conda-meta/history"])`
    and take each match's env root.
  - **Known places:** add `/Library/Frameworks/Python.framework/Versions/*`
    (skip `Current`), `~/.pyenv/versions/*`, `~/.local/share/uv/python/*`, and
    Homebrew `/opt/homebrew/opt/python@*/Frameworks/Python.framework/Versions/*`
    and `/usr/local/opt/python@*/…`, then merge `conda env list --json` when
    `conda` is on `PATH`.
  - **PATH interpreters:** when `include_path_interpreters`, for each `python3`
    / `python` on `PATH` whose resolved prefix isn't already discovered, run
    `<exe> -I -c "import sys,sysconfig,json;print(json.dumps({'prefix':sys.prefix,'purelib':sysconfig.get_paths()['purelib'],'stdlib':sysconfig.get_paths()['stdlib'],'version':'%d.%d.%d'%sys.version_info[:3]}))"`
    with a 5 s timeout. Classify it as `SYSTEM` if its prefix is under `/usr`,
    `/System` or `/Library/Developer`, or if its stdlib has
    `EXTERNALLY-MANAGED`. Classify Homebrew prefixes (`/opt/homebrew`,
    `/usr/local/Cellar`, `/usr/local/opt`) as `HOMEBREW`.
  - **Python version:** from `pyvenv.cfg` `version`/`version_info`, else the
    conda-meta `python-*.json`, else a `lib/pythonX.Y` dir name, else the
    framework/pyenv dir name.
  - Dedupe by `path.resolve()`.
- [ ] **Step 5:** Run, expect PASS.
- [ ] **Step 6: Commit:**
      `feat(tools): discover and classify Python environments`

---

### Task 4: Tools on PATH and install method

**Files:** Create `src/ssec_cli/tools/path_tools.py`. Test:
`tests/tools/test_path_tools.py`.

**Interfaces:**

- Consumes: `versions.extract_version`.
- Produces:

  - `TOOLS_TO_CHECK: tuple[str, ...]` =
    `("pixi", "uv", "pip", "conda", "sigstore", "git", "gh", "docker", "python", "code", "rg")`
  - `class InstallMethod(str, Enum)`: `STANDALONE`, `HOMEBREW`, `PIXI_GLOBAL`,
    `UV_TOOL`, `PIPX`, `CONDA`, `VENV`, `SYSTEM`, `UNKNOWN`
  - `@dataclass ToolInfo`: `name: str`, `path: Path | None`,
    `version: str | None`, `method: InstallMethod`, `formula: str | None` (the
    Homebrew formula name), `env_root: Path | None` (the conda/venv prefix)
  - `detect_install_method(name: str, path: Path, home: Path) -> tuple[InstallMethod, str | None, Path | None]`
    (pure)
  - `tool_version(path: Path) -> str | None` (`--version` with a 5 s timeout,
    then `extract_version` on stdout+stderr)
  - `scan_path_tools(home: Path, names: Sequence[str] = TOOLS_TO_CHECK) -> list[ToolInfo]`
    (`path=None` when not found)

- [ ] **Step 1: Failing tests:**
  - `test_detect_install_method`, table-driven:
    - `~/.pixi/bin/pixi` → `STANDALONE`
    - `~/.pixi/bin/ruff` → `PIXI_GLOBAL`
    - `/opt/homebrew/bin/uv` (resolving to
      `/opt/homebrew/Cellar/uv/0.13.4/bin/uv`) → `HOMEBREW` with formula `uv`.
      Use a symlink in `tmp_path`, or make the function take a `resolve`
      callable.
    - `~/.local/bin/uv` and `~/.cargo/bin/uv` → `STANDALONE`
    - `~/.local/share/uv/tools/x/bin/x` → `UV_TOOL`
    - `~/.local/pipx/venvs/x/bin/x` → `PIPX`
    - `<prefix with conda-meta>/bin/conda` → `CONDA` with `env_root`
    - `<prefix with pyvenv.cfg>/bin/pip` → `VENV`
    - `/usr/bin/pip3` → `SYSTEM`
    - anything else → `UNKNOWN`
  - `test_extract_version_variants`: use a fake executable script in `tmp_path`
    (POSIX) that prints each sample: `pip 26.2.2 from /x (python 3.12)` →
    `26.2.2`, `uv 0.13.4 (Homebrew 2026-10-21)` → `0.13.4`, empty output →
    `None`, and a script that sleeps 10 s → `None` (monkeypatch the timeout to
    0.5 s).
  - `test_missing_tool`: a name not on `PATH` gives `path=None, version=None`.
- [ ] **Step 2:** Run, expect FAIL.
- [ ] **Step 3: Implement** using `shutil.which` and `Path.resolve()` for the
      Cellar check. Put the timeout in a module constant `VERSION_TIMEOUT = 5`.
- [ ] **Step 4:** Run, expect PASS.
- [ ] **Step 5: Commit:**
      `feat(tools): detect tools on PATH, versions and install methods`

---

### Task 5: Lockfile scanning

**Files:** Create `src/ssec_cli/tools/lockfiles.py`. Test:
`tests/tools/test_lockfiles.py`, fixtures in `tests/tools/data/`.

**Interfaces:**

- Consumes: `finder.find_files`, `advisories.normalize_name`.
- Produces:

  - `WATCHED = ("certifi", "pip", "ca-certificates")`
  - `@dataclass LockPin`: `lockfile: Path`, `package: str`,
    `version: str | None`, `error: str | None` (set, with `package=""`, when the
    file couldn't be parsed)
  - `parse_lockfile(path: Path, packages: Sequence[str] = WATCHED) -> list[LockPin]`:
    one pin per distinct (package, version) in the file
  - `scan_lockfiles(root: Path, recursive: bool = True) -> list[LockPin]`:
    patterns `pixi.lock`, `uv.lock`, `poetry.lock`, `requirements*.txt` (with
    `**/` when recursive). It uses `DEFAULT_EXCLUDES` plus `.pixi`, `.venv` and
    `venv`.

- [ ] **Step 1: Fixtures:** in `tests/tools/data/`, add trimmed real-format
      samples. `pixi.lock` has two `- conda:` lines
      (`…/noarch/ca-certificates-2025.8.3-hbd8a1cb_0.conda`,
      `…/noarch/certifi-2025.8.3-pyhd8ed1ab_0.conda`) and one `- pypi:` line
      (`…/certifi-2026.10.19-py3-none-any.whl`). `uv.lock` has `[[package]]`
      `name = "certifi"`, `version = "2025.8.3"`. `poetry.lock` has the same
      shape. `requirements.txt` has `certifi==2025.8.3 \` with a
      `--hash=sha256:…` continuation line, `pip>=20` (unpinned, ignored) and a
      comment. `bad_uv.lock` is invalid TOML.
- [ ] **Step 2: Failing tests:**
  - `test_pixi_lock`: pins
    `{("ca-certificates","2025.8.3"),("certifi","2025.8.3"),("certifi","2026.10.19")}`.
  - `test_uv_lock`, `test_poetry_lock`: `[("certifi","2025.8.3")]`.
  - `test_requirements_only_exact_pins`: only `certifi==2025.8.3` is reported.
  - `test_malformed_uv_lock_is_unknown`: one `LockPin` with `error` set, and no
    exception.
  - `test_scan_recurses_and_skips_envs`: `sub/uv.lock` is found, and
    `.pixi/envs/x/requirements.txt` isn't.
- [ ] **Step 3:** Run, expect FAIL.
- [ ] **Step 4: Implement.**
  - `pixi.lock`: no YAML parser. Use a line regex on `- (conda|pypi): <url>`.
    For conda, take the filename and match
    `^(?P<name>.+)-(?P<ver>[^-]+)-[^-]+\.(conda|tar\.bz2)$`. For pypi wheels and
    sdists, match `^(?P<name>[^-]+)-(?P<ver>[^-]+)(-.*\.whl|\.tar\.gz|\.zip)$`.
    Normalize the names.
  - `uv.lock` / `poetry.lock`: `tomllib`, using `[[package]]` `name`/`version`.
  - `requirements*.txt`: `^\s*([A-Za-z0-9_.-]+)\s*===?\s*([^\s;#\\]+)`.
  - Any exception while reading or parsing gives one error pin.
- [ ] **Step 5:** Run, expect PASS.
- [ ] **Step 6: Commit:**
      `feat(tools): scan lockfiles for pinned certifi/pip/ca-certificates`

---

### Task 6: Evaluation and fix commands

**Files:** Create `src/ssec_cli/tools/evaluate.py`. Test:
`tests/tools/test_evaluate.py`.

**Interfaces:**

- Consumes: everything from Tasks 1–5.
- Produces:

  - `class Status(str, Enum)`: `OK`, `OUTDATED`, `NOT_INSTALLED`, `UNKNOWN`,
    `SKIPPED`
  - `@dataclass Finding`: `category: Literal["tool","environment","lockfile"]`,
    `item: str` (the package or tool name), `location: Path | None`,
    `current: str | None`, `minimum: str | None`, `status: Status`,
    `advisory_id: str | None`, `fix: str | None` (a shell command, or `None`
    when there's nothing to do), `note: str | None` (a skip reason or other
    detail), `env_kind: EnvKind | None`, `install_method: InstallMethod | None`
  - `@dataclass ScanResult`: `findings: list[Finding]`,
    `advisories: list[Advisory]`, `used_rg: bool`
  - `evaluate_tool(t: ToolInfo, mins: dict[str, PackageMinimum]) -> Finding`
  - `evaluate_env(e: PythonEnv, mins) -> list[Finding]` (one per watched
    package: `pip`, `certifi`, and `ca-certificates` for conda/pixi envs)
  - `evaluate_lockpin(p: LockPin, mins) -> Finding`
  - `scan(home: Path, project: Path, *, full: bool = True) -> ScanResult`. When
    `full`, it covers all environments under home plus the PATH tools and the
    lockfiles under `project`, recursively. When `not full` (used by
    diagnostics), it covers the PATH tools, envs under `project` only
    (`extra_roots` only, with no home search and no PATH interpreters), and the
    top-level lockfiles in `project`.

- [ ] **Step 1: Failing tests.** One test per row of the status/fix table below,
      plus `test_broken_venv_is_unknown` (`packages=None` gives UNKNOWN for pip
      and certifi, never OK or NOT_INSTALLED) and
      `test_no_advisory_tool_has_no_status` (git: `status=OK`, `minimum=None`,
      `fix=None`, and the note `no advisory`).
- [ ] **Step 2:** Run, expect FAIL.
- [ ] **Step 3: Implement** using this table. The `fix` strings are exact copy,
      with `{py}` = `python_executable(env)` quoted and `{pip_url}` / `{sha}`
      taken from `mins["pip"]`:

| Case                                                                | Status        | `fix`                                                                                                                                                | `note`                                                     |
| ------------------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| package absent from a readable env                                  | NOT_INSTALLED | `None`                                                                                                                                               | –                                                          |
| env unreadable / version unparsable                                 | UNKNOWN       | `None`                                                                                                                                               | `could not read package metadata`                          |
| at or above the minimum                                             | OK            | `None`                                                                                                                                               | –                                                          |
| PLAIN_VENV / FRAMEWORK / PYENV / UV_PYTHON, pip outdated, py ≥ 3.10 | OUTDATED      | `{py} -m pip install "pip @ {pip_url}#sha256={sha}"`                                                                                                 | –                                                          |
| same kinds, certifi outdated, pip present                           | OUTDATED      | `{py} -m pip install --upgrade "certifi>={min}"`                                                                                                     | upgrade pip first                                          |
| same kinds, certifi outdated, no pip                                | OUTDATED      | `uv pip install --python {py} "certifi>={min}"`                                                                                                      | –                                                          |
| same kinds, py < 3.10                                               | OUTDATED      | `None`                                                                                                                                               | `pip 26.2.2 needs Python 3.10+; recreate this environment` |
| UV_PROJECT                                                          | OUTDATED      | `cd {project} && uv lock --upgrade-package certifi && uv sync`                                                                                       | `managed by uv; pip changes would be undone by uv sync`    |
| UV_TOOL / PIPX                                                      | OUTDATED      | `uv tool upgrade {tool}` / `pipx upgrade {tool}`                                                                                                     | –                                                          |
| PIXI_PROJECT                                                        | OUTDATED      | `cd {project} && pixi update certifi ca-certificates pip`                                                                                            | `managed by pixi`                                          |
| PIXI_GLOBAL                                                         | OUTDATED      | `pixi global update {tool}`                                                                                                                          | –                                                          |
| CONDA, conda-installed package                                      | OUTDATED      | `conda update -n {name or -p path} {pkg}`                                                                                                            | –                                                          |
| CONDA, pip-installed package                                        | OUTDATED      | pip command as for PLAIN_VENV                                                                                                                        | `env mixes pip and conda packages`                         |
| SYSTEM                                                              | SKIPPED       | `None`                                                                                                                                               | `system Python; leave to the OS package manager`           |
| HOMEBREW                                                            | SKIPPED       | `brew upgrade python@{X.Y}`                                                                                                                          | `managed by Homebrew`                                      |
| tool STANDALONE pixi / uv                                           | OUTDATED      | `pixi self-update` / `UV_SYSTEM_CERTS=true uv self update`                                                                                           | –                                                          |
| tool HOMEBREW                                                       | OUTDATED      | `brew upgrade {formula}`                                                                                                                             | –                                                          |
| tool PIXI_GLOBAL / UV_TOOL / PIPX                                   | OUTDATED      | `pixi global update {name}` / `uv tool upgrade {name}` / `pipx upgrade {name}`                                                                       | –                                                          |
| tool `conda` (method CONDA)                                         | OUTDATED      | `conda update -n base conda`                                                                                                                         | –                                                          |
| tool `pip` with method VENV / CONDA                                 | OUTDATED      | `None`                                                                                                                                               | `see Python environments`                                  |
| tool UNKNOWN / SYSTEM                                               | OUTDATED      | `None`                                                                                                                                               | `update {name} with the tool that installed it`            |
| tool on PATH, version unreadable                                    | UNKNOWN       | `None`                                                                                                                                               | `could not read version`                                   |
| lockfile pin below the minimum                                      | OUTDATED      | `pixi update certifi ca-certificates` / `uv lock --upgrade-package {pkg}` / `poetry update {pkg}` / `None` with note `edit the pin` for requirements | –                                                          |
| lockfile parse error                                                | UNKNOWN       | `None`                                                                                                                                               | the error message                                          |

- [ ] **Step 4:** Run, expect PASS.
- [ ] **Step 5: Commit:**
      `feat(tools): evaluate scan results against advisories`

---

### Task 7: Report rendering and `ssec tools check`

**Files:** Create `src/ssec_cli/tools/report.py` and
`src/ssec_cli/tools/cli.py`. Modify `src/ssec_cli/main.py` (add
`app.add_typer(tools_app, name="tools")`) and `README.md` (a "Checking tool
versions" section). Test: `tests/tools/test_cli.py`.

**Interfaces:**

- Consumes: `evaluate.scan`, `ScanResult`, `Finding`, `Status`.
- Produces:

  - `report.render(result: ScanResult, console: Console, home: Path) -> None`
  - `report.to_json(result: ScanResult, home: Path) -> str`: an object with
    `advisories` (`id`, `title`, `date`, `urls`), `findings` (every `Finding`
    field, with paths as `~/…` strings and enums as values) and `used_rg`
  - `report.display_path(p: Path | None, home: Path) -> str`
  - `cli.tools_app: typer.Typer`. Command `check` takes options `--path PATH`
    (default: cwd), `--json`, `--fail-on-outdated`. It is the function
    `check(path: Path, json_: bool, fail_on_outdated: bool) -> None`.

- [ ] **Step 1: Failing tests** with `typer.testing.CliRunner` and `scan`
      monkeypatched to return a fixed `ScanResult` containing one of each
      status:
  - `test_check_renders_three_sections`: the output contains `Tools on PATH`,
    `Python environments`, `Lockfiles`, the advisory title and its first URL.
  - `test_check_json_is_valid`: `json.loads(output)`, which has 1 advisory and
    the same number of findings; no path starts with the real home path.
  - `test_fail_on_outdated_exit_code`: exit 1 with the flag and an OUTDATED
    finding, exit 0 without the flag, exit 0 with the flag when there are only
    OK / NOT_INSTALLED findings.
  - `test_unknown_never_green`: in the rendered text, UNKNOWN rows say
    `UNKNOWN`, and the summary line counts them separately from OK.
- [ ] **Step 2:** Run, expect FAIL.
- [ ] **Step 3: Implement.**
  - **Tables:** one rich table per category, with columns
    `Item | Location | Current | Minimum | Status | Fix / note`. The tools table
    adds an `Installed via` column after `Location` (from `install_method`, plus
    the formula for Homebrew), and the environments table adds a `Kind` column
    (from `env_kind`). The spec wants users to see how each item was installed,
    because that decides the fix.
  - **Status styles:** OK green, OUTDATED bold red, UNKNOWN yellow, SKIPPED dim,
    NOT_INSTALLED dim, shown as `not installed`.
  - **Row order:** OUTDATED first. Collapse NOT_INSTALLED rows into a count per
    table (`+ 14 environments without pip/certifi`) so the table stays readable.
  - **Footer:** a summary line (`3 outdated · 2 unknown · 40 ok · 5 skipped`),
    then each advisory's title, date and URLs, then the rg note if `rg` wasn't
    used.
  - **Reminders:** always print the two reminders verbatim:
    `Containers: rebuild images with the layer cache disabled (e.g. docker build --no-cache).`
    and
    `New virtual environments: run "python -m pip install --upgrade pip" right after creating one, until CPython ships a fixed ensurepip.`
  - **Progress:** show a rich `console.status("Scanning…")` spinner during
    `scan` (it's skipped in `--json` mode).
- [ ] **Step 4:** Run, expect PASS. Then run it for real:
      `pixi run ssec tools check`. Expected: three tables; this repo's
      `pixi.lock` shows `ca-certificates 2025.8.3` as OUTDATED or not, depending
      on the lock at the time.
      `pixi run ssec tools check --json | python -m json.tool` should be valid.
- [ ] **Step 5: Commit:** `feat(tools): add ssec tools check command`

---

### Task 8: Diagnostics summary

**Files:** Modify `src/ssec_cli/main.py` (`diagnostics()` and `check_tools()`).
Test: `tests/tools/test_diagnostics_summary.py`.

**Interfaces:**

- Consumes: `evaluate.scan(home, project, full=False)`, `report.display_path`.
- Produces:
  `main.print_tool_versions_summary(home: Path, project: Path) -> None`.

- [ ] **Step 1: Failing tests** (monkeypatch `scan`):
  - `test_summary_lists_only_outdated`: with one OUTDATED and one OK finding,
    the output has a `## Tool versions` header, the OUTDATED item and its
    `~/`-relative location, and not the OK item.
  - `test_summary_all_clear`: no OUTDATED or UNKNOWN gives
    `No outdated tools found in PATH or this project.`
  - Both end with `Run \`ssec tools check\` for the full report across all
    environments.`
- [ ] **Step 2:** Run, expect FAIL.
- [ ] **Step 3: Implement**, called last in `diagnostics()`, using the same
      `## ` markdown-style headers as the existing sections. Add `"rg"` to
      `check_tools()`'s list.
- [ ] **Step 4:** Run the whole suite with `pixi run -e dev pytest -q`, expect
      all PASS. Then run `pixi run ssec diagnostics` and confirm it finishes in
      under ~5 s.
- [ ] **Step 5:** Run `pixi exec pre-commit run --all-files` and
      `pixi run -e dev ruff check src/ssec_cli/tools tests`. Fix new findings in
      the new code only.
- [ ] **Step 6: Commit:** `feat(diagnostics): add tool versions summary`

---

## Out of scope (release 2)

`ssec tools update`: the plan / confirm / execute flow and `--dry-run` /
`--yes`. It will consume `scan()` and turn each `Finding.fix` (plus `env_kind` /
`install_method`) into actions, as described in the spec's update table.
