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
