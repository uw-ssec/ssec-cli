# SSEC CLI

A CLI tool built with typer and managed with pixi.

## Installation

### Using pixi (recommended)

```bash
# Install pixi if you haven't already
curl -fsSL https://pixi.sh/install.sh | bash

# Install the CLI in development mode
pixi run install

# Or install with development dependencies
pixi run dev-install
```

### Using pip

```bash
pip install -e .
```

## Usage

```bash
ssec --help
```

### Archiving agent sessions

`ssec archive-sessions` finds the session transcripts that AI coding agents
(Claude Code, Codex, Copilot CLI, Cursor, Gemini CLI, and 13 others) keep on
your machine and writes them to a single zip file, with one directory per agent
and a `manifest.json` describing what's inside.

```bash
# See what would be archived
ssec archive-sessions --dry-run

# Archive sessions from this month
ssec archive-sessions --since 2026-10-01

# Only Codex transcripts, written to a chosen file
ssec archive-sessions --agents codex --jsonl-only --output codex.zip
```

Each agent's session directory can be overridden with an environment variable,
such as `CLAUDE_PROJECTS_DIR` or `CODEX_SESSIONS_DIR`. Known credential files
(for example `auth.json` and `oauth_creds.json`) are always left out, but
transcripts themselves can still contain secrets, tokens, and personal
information. Review an archive before you share it.

## Development

This project uses pixi for dependency management:

```bash
# Install in development mode
pixi run dev-install

# Run tests
pixi run test

# Lint code
pixi run lint

# Format code
pixi run format
```
