# Design: `ssec tools check` / `ssec tools update`

> [!NOTE] > **AI assistance disclosure:** Claude Code
> (`claude-code:claude-opus-5-5`) drafted this document from issue #14 and a
> design conversation with the maintainer. The maintainer reviews it before it
> is used.

Issue: [#14](https://github.com/uw-ssec/ssec-cli/issues/14). Related:
[#13](https://github.com/uw-ssec/ssec-cli/issues/13) (security audit).

## Intent

On 2026-10-20 an advisory was posted that eMudhra / emSign intermediate CA
private keys were compromised. The emSign root was removed from CA bundles such
as `certifi`. Any tool that still trusts it can be man-in-the-middled, including
traffic to pypi.org. Fixing this by hand means checking pixi, uv, pip in every
environment, conda, and lockfiles, and nobody can easily answer "am I affected,
and where?".

`ssec tools check` answers that question. `ssec tools update` fixes what it
safely can.

**Who runs it, in order:**

1. The maintainer, on their own machine, right away.
2. SSEC members, once each, after the maintainer posts an announcement with a
   new `ssec-cli` release. Most won't know which of their tools or environments
   are affected.

**What success looks like:** a colleague who has never thought about CA bundles
runs `ssec tools check`, sees what is affected, why (with a link to the
advisory) and what to do about it, then runs `ssec tools update` and ends up
fixed, or with exact commands for whatever couldn't be fixed automatically.

## Goals

- Report the versions of security-relevant tools and packages, compared with the
  minimum safe versions from bundled advisories.
- Cover tools on `PATH`, every Python environment on the machine, and lockfiles
  in a project.
- `update` fixes everything it can safely reach, across every Python environment
  on the machine by default.
- Ship quickly enough to help during this incident.

## Phases (decided by the maintainer)

1. **Release 1: `ssec tools check`**, plus the `diagnostics` summary, the
   bundled advisory data and the packaging fixes below. This is the release the
   announcement goes out with. It answers "am I affected, and where?" and prints
   the fix command for each affected item, but changes nothing.
2. **Release 2: `ssec tools update`.** Builds on release 1's scan. It can take
   longer and get deeper review, because it changes people's machines.

The `update` section below is the design for release 2. Build release 1 so that
release 2 can reuse its scan and environment classification unchanged.

## Non-goals

- Fetching advisories over the network. The minimum versions ship only in the
  package, and a new incident means a new `ssec-cli` release. (The maintainer
  considered fetching a signed list and decided against it.)
- Scanning Docker images present locally. The final summary reminds users to
  rebuild containers instead.
- A `ssec security` command group. Use `ssec tools`, and revisit when #13 is
  built.
- CI use (`--fail-on-outdated`) is in scope, but it is not what this rollout
  needs, so it shouldn't drive the design.

## Anti-goals: a failure even if it technically works

- `update` breaks a colleague's machine. Concretely, it modifies a system
  Python, an "externally managed" Python, or a conda or pixi environment with
  pip in a way that corrupts the environment's own package records.
- `update` changes a lockfile.
- `update` changes anything before the user has seen the plan and confirmed it.
- `update` installs pip through a channel an attacker could tamper with. This
  incident is about MITM, so pip is installed only from a hash-pinned URL.
- The output says "fine" when something is affected. A false "OK" is worse than
  an "unknown".

## Constraints

- Existing code: a typer app in `src/ssec_cli/main.py`, using `rich.print` and
  plain `subprocess.run` calls with timeouts. `main.py` already has
  `is_tool_installed` / `get_tool_version` and a `diagnostics` command with a
  hard-coded tool list. New code goes in its own module(s), and the `tools`
  group is added to `app` as a typer sub-app.
- The package says `requires-python = ">=3.8"`, but `update_models.py` already
  uses `dict | None`, so the real floor is 3.10. New code may assume 3.10+.
- Platforms in `pixi.toml`: osx-arm64, osx-64, linux-64, win-64. macOS and Linux
  must work. Windows must not crash: unsupported checks report "unsupported on
  Windows".
- Finding files uses ripgrep (`rg --files --hidden --no-ignore --glob ...`) when
  it's on `PATH`, as #13 also proposes, and add `ripgrep` to `[dependencies]` in
  `pixi.toml`. When `rg` is missing, fall back to a built-in `os.walk` search
  with the same excludes, and print a one-line note that installing `rg` makes
  it faster. The command must never refuse to run because `rg` is missing.
  (Decided by the maintainer.)
- It isn't known yet how members will install the release: from a git clone with
  `pixi run install`, or with pip, pipx or uv tool. So release 1 must work from
  a plain `pip install` of the wheel: `advisories.toml` is included in the
  wheel, `rich` is declared in `pyproject.toml` `dependencies`, and
  `requires-python` is raised to `>=3.10` to match the code. _(My call: the
  maintainer didn't say how it will be installed.)_
- The scan reports ssec's own environment like any other environment. _(My
  call.)_
- No new runtime Python dependencies beyond the standard library, typer and
  rich. Parse TOML with `tomllib` (Python 3.11+), falling back to a simple
  reader, or add `tomli` for 3.10. Builder's call.
- Follow the repo's AI policy for commits and the PR: an
  `Assisted-by: claude-code:<model>` trailer, the `ai-assisted` label and a
  disclosure section.

## Decided behavior

### Advisory data

- A bundled data file, `src/ssec_cli/advisories.toml`, shipped in the wheel.
  Each advisory has an id, a title, a date, source URL(s) and a list of
  `{package, min_version}` entries. The report links each flagged item to its
  advisory.
- The first entry is the eMudhra / emSign incident:

  | Package         | Minimum                                                                                              |
  | --------------- | ---------------------------------------------------------------------------------------------------- |
  | certifi         | 2026.10.19 (advisory says .18; .19 recommended)                                                      |
  | ca-certificates | builder to confirm the first conda-forge version without emSign (latest on 2026-10-23 is 2026.10.23) |
  | pip             | 26.2.2                                                                                               |
  | uv              | 0.13.4                                                                                               |
  | sigstore        | 4.5.1                                                                                                |
  | conda           | 26.9.4                                                                                               |
  | pixi            | 0.82.1                                                                                               |

  Source:
  https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576

- The pip fix's direct URL and `sha256` live in the data file next to the
  minimum. The builder must take them from PyPI's JSON API
  (`https://pypi.org/pypi/pip/26.2.2/json`) and check them in the PR. Never type
  or guess a hash.
- Checked on 2026-10-23: pip 26.2.2 (wheel `pip-26.2.2-py3-none-any.whl`,
  `requires_python >=3.10`), certifi 2026.10.19, uv 0.13.4 and sigstore 4.5.1
  are on PyPI; pixi v0.82.1 is a GitHub release; conda 26.9.4 is on conda-forge.

### `ssec tools check`

Read-only. Three sections, each a rich table with the item, its location, the
current version, the minimum version and a status (OK, OUTDATED, UNKNOWN or
SKIPPED):

1. **Tools on `PATH`:** `pixi`, `uv`, `pip`, `conda`, `sigstore`, plus the tools
   `diagnostics` already lists. For each, show the path, version and how it was
   installed (standalone installer, Homebrew, pixi global, pip/pipx, conda,
   system), because that decides how `update` fixes it. Tools with no advisory
   entry are listed without a status.
2. **Python environments**, with the `pip` and `certifi` versions in each.
   Discovery is **marker-based**: search the home directory for environment
   markers rather than relying only on a list of known places, because anything
   the scan misses is effectively a false "fine". _(My call.)_ Markers and extra
   places:

   - `pyvenv.cfg`: a venv. Sub-classify it:
     - **uv project venv**: `pyvenv.cfg` has a `uv = ` line and the parent
       directory has a `uv.lock`
     - **uv tool / pipx env**: under `~/.local/share/uv/tools/` or
       `~/.local/pipx/venvs/` (and the platform equivalents)
     - **plain venv**: anything else
   - `.pixi/envs/*`: a pixi project environment
   - `conda-meta/`: a conda, mamba or micromamba environment, whether or not
     `conda` is on `PATH`. Also merge in `conda env list` when it's available,
     to catch envs outside home.
   - known interpreter installs outside home or not marked: python.org
     frameworks on macOS (`/Library/Frameworks/Python.framework/Versions/*`),
     Homebrew Pythons, pyenv (`~/.pyenv/versions/*`) and uv-managed Pythons
     (`~/.local/share/uv/python/*`)
   - system Pythons (macOS `/usr/bin/python3`, distro Python on Linux, anything
     with an `EXTERNALLY-MANAGED` marker): reported, never fixed

   Statuses: OK, OUTDATED, NOT INSTALLED (the package isn't in that env, so
   there's nothing to fix; counts as fine), UNKNOWN (the version couldn't be
   read; never shown as fine) and SKIPPED. _(My call.)_

3. **Lockfiles** under `--path` (default: current directory), recursing into
   subdirectories with the same excludes as the env search: `pixi.lock`,
   `uv.lock`, `requirements*.txt` and `poetry.lock`. Flag pinned `certifi`,
   `pip` and `ca-certificates` versions below the minimum. _(My call: recursive,
   to cover monorepos.)_

Each OUTDATED row in `check` includes the command that would fix it (the same
text as the `MANUAL` column in the `update` table below), so release 1 is useful
on its own.

Options: `--path PATH` sets the project/lockfile root (default: current
directory), `--json` prints machine-readable output, and `--fail-on-outdated`
exits non-zero when anything is OUTDATED.

Read package versions from the environment's `site-packages` `*.dist-info`
metadata (or conda-meta JSON) rather than running each environment's Python, so
that scanning stays fast and doesn't execute code from every venv on the
machine.

### `ssec tools update`

1. Run the same scan as `check`.
2. Print **the plan**: one row per affected item, with its action, which is
   either the exact command that will run, `SKIP: <reason>` or
   `MANUAL: <command for you to run>`.
3. Ask once for confirmation. `--dry-run` stops after the plan, and `--yes`
   skips the prompt.
4. Run the actions one at a time, streaming the output. A failure doesn't stop
   the rest.
5. Print a summary of what was fixed, skipped, failed and left as manual, plus
   these reminders: rebuild containers with the layer cache disabled, and
   upgrade pip right after creating new venvs until CPython ships a fixed
   `ensurepip`.

Scope: every Python environment found on the machine, by default.

Actions by kind:

| Item                               | Action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| plain venv (Python ≥ 3.10)         | if pip is present and outdated: `<env>/bin/python -m pip install "pip @ <url>#sha256=<hash>"`. Then, if certifi is present and outdated: `<env>/bin/python -m pip install --upgrade "certifi>=<min>"`. Never install pip or certifi into an env that doesn't have them. If certifi is outdated and the env has no pip: MANUAL `uv pip install --python <env> "certifi>=<min>"`                                                                                                                                                                      |
| plain venv (Python < 3.10)         | SKIP: pip 26.2.2 needs Python 3.10+                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| uv project venv                    | (revised in release 1 review) only an env named `.venv` next to a `uv.lock` (uv sync manages only `.venv`; any other uv-created venv is a plain venv). SKIP + MANUAL: `cd <project> && uv lock --upgrade-package <pkg> && uv sync` (pip changes would be undone by the next `uv sync`). Same reasoning as pixi                                                                                                                                                                                                                                      |
| uv tool / pipx env                 | (revised in release 1 review) uv tool: `uv tool upgrade <tool>`. pipx: `pipx runpip <tool> install --upgrade "certifi>=<min>"` for certifi and `pipx runpip <tool> install "pip @ <url>#sha256=<hash>"` for pip, because `pipx upgrade <tool>` keeps already-satisfied deps such as certifi; with no pinned pip URL, no fix (note: advisory has no pinned pip URL)                                                                                                                                                                                  |
| python.org macOS framework         | same as plain venv; SKIP if it needs elevated permissions, and print the `sudo` command as MANUAL                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| conda env                          | (revised in release 1 review) `<conda> update -p <env path> <pkg>` for each outdated package installed as a conda package; always target by path, since `-n` resolves against whichever conda is on PATH. `<conda>` is the owning install's `condabin/conda`, else `bin/conda` (Windows `Scripts/conda.exe`), looked up in the env itself or, for `<root>/envs/<name>`, in `<root>`; otherwise plain `conda`. Never pip. Pip-installed certifi/pip inside a conda env: MANUAL with the pip command, plus a warning that the env mixes pip and conda |
| pixi project env                   | (revised in release 1 review) SKIP + MANUAL: `cd <project> && pixi update <pkg>`, one command per outdated package, because pixi rejects the whole command if any named package is not in the lock (pip changes would be undone by the next `pixi install`)                                                                                                                                                                                                                                                                                         |
| system / externally managed Python | SKIP: system Python, leave to the OS / package manager. (revised in release 1 review) Any Python whose stdlib carries a PEP 668 `EXTERNALLY-MANAGED` marker (e.g. uv-managed Pythons) gets no pip fix: pip would refuse it; update environments created from it instead                                                                                                                                                                                                                                                                             |
| pixi (standalone)                  | `pixi self-update`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| uv (standalone)                    | `UV_SYSTEM_CERTS=true uv self update`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Homebrew-installed tool            | `brew upgrade <formula>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| conda (base)                       | (revised in release 1 review) `<root conda> update -p <root> conda`, targeting the install that owns the `conda` on PATH by path                                                                                                                                                                                                                                                                                                                                                                                                                    |
| tool installed another way         | MANUAL: the matching command (`pixi global update <x>`, `pipx upgrade <x>`, …)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| lockfile                           | (revised in release 1 review) never changed; MANUAL: `cd <dir> && pixi update <pkg>` (one package per command) / `uv lock --upgrade-package <pkg>` / `poetry update <pkg>` / edit the pin in `requirements*.txt`                                                                                                                                                                                                                                                                                                                                    |

Release 1 review notes: UV_PROJECT applies only to a `.venv`, and externally
managed Pythons get no pip fix, so release 2 must not run the older commands
above.

### `ssec diagnostics`

Add a short "Tool versions" section listing only OUTDATED items, with a pointer
to `ssec tools check`. It reuses the same scan, limited to tools on `PATH` and
the current project so that `diagnostics` stays fast. That limit is the
builder's call, flagged as a decision in the PR.

## Left to the builder

- Module layout, data structures and the exact `advisories.toml` schema.
- How to detect the install method (path heuristics are fine, for example
  `~/.pixi/bin`, `/opt/homebrew`, `~/.local/bin`, `~/.cargo/bin`).
- Version comparison. Use `packaging.version` if it's already available
  transitively, or a small comparator. Calendar versions like `2026.10.19` must
  compare correctly.
- The exact `rg` globs and excludes for the home-directory venv search. Exclude
  `.Trash`, `Library/Caches`, `node_modules` and the like, and keep it fast.
- Tests: the repo has none today. Add pytest tests for advisory parsing, version
  comparison, lockfile parsing, environment classification and plan building,
  using fixture directories. Don't run real updates in tests.
- The rich layout details.
