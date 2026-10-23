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

### Checking tool versions

```bash
ssec tools check                      # scan PATH tools, Python environments and lockfiles
ssec tools check --path ~/my-project  # also scan lockfiles in another project
ssec tools check --json               # machine-readable output
ssec tools check --fail-on-outdated   # exit 1 if anything is OUTDATED
```

It is read-only. Each affected item links to its advisory and shows the exact
command to fix it. UNKNOWN means the version could not be determined; treat it
as not verified, not as fine.

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
