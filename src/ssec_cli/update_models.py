#!/usr/bin/env python3
"""
Fetch available models from LiteLLM and update VS Code's OAI Copilot extension settings.

Requires the LITELLM_API_KEY and LITELLM_BASE_URL environment variables to be set.

Usage:
    python update_models.py         # Update settings.json in place
    python update_models.py --dry-run # Preview changes without writing
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import platform
import urllib.error


def _default_settings_path() -> str:
    """Return the default VS Code settings.json path for the current OS."""
    system = platform.system()
    if system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Code/User/settings.json")
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        return os.path.join(appdata, "Code", "User", "settings.json")
    else:  # Linux and other Unix-like systems
        return os.path.expanduser("~/.config/Code/User/settings.json")


SETTINGS_PATH = _default_settings_path()
SETTINGS_KEY = "oaicopilot.models"
OWNER = "uw-ssec"
SUFFIX = f"(UW SSEC)"
DEFAULT_ANTHROPIC_MAX_TOKENS = 64000


def fetch_models(base_url: str, api_key: str) -> list[dict]:
    """Fetch models from the LiteLLM /model/info endpoint.

    Falls back to /v1/models when the key lacks access to /model/info. That
    route lists ids without token limits, so both token values come back
    ``None`` and the caller applies defaults.

    Returns a list of dicts with the model ``name``, its ``max_tokens`` (output
    budget) and its ``max_input_tokens`` (context window). Either token value is
    ``None`` when the endpoint does not report one. Sorted by name.
    """

    def get(url: str) -> tuple[dict | None, int]:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return (json.loads(resp.read().decode()), resp.status)
        except urllib.error.HTTPError as exc:
            print(f"Error: HTTP {exc.code} from {url}", file=sys.stderr)
            return (None, exc.code)
        except urllib.error.URLError as exc:
            print(f"Error: Could not reach {url}: {exc.reason}", file=sys.stderr)
            sys.exit(1)

    data, status = get(f"{base_url}/model/info")
    if data is None and status in (401, 403):
        print(
            "Falling back to default token limits. Ask an admin to add '/model/info' permissions to your LiteLLM key to allow fetching model specific values",
            file=sys.stderr,
        )
        data, _ = get(f"{base_url}/v1/models")
    if data is None:
        sys.exit(1)

    models: dict[str, dict] = {}
    for entry in data.get("data", []):
        name = entry.get("model_name") or entry.get("id")
        if not name or name in models:
            continue
        model_info = entry.get("model_info") or {}
        max_tokens = model_info.get("max_tokens") or model_info.get("max_output_tokens")
        models[name] = {
            "name": name,
            "max_tokens": max_tokens,
            "max_input_tokens": model_info.get("max_input_tokens"),
        }
    return [models[name] for name in sorted(models)]


def make_display_name(model_id: str) -> str:
    """
    Transform a model id into a human-readable display name.

    Rules:
      - Replace hyphens with spaces and title-case each word.
      - Convert bare version numbers like "4-6" → "4.6"
        (sequences of digit-digit at the end of the name or before another word).
      - Append the UW SSEC suffix.
      - Preserve date-like sequences (e.g. 2024-05-13) as-is.

    Examples:
        claude-sonnet-4-6   → Claude Sonnet 4.6 (UW SSEC)
        claude-haiku-4-5    → Claude Haiku 4.5 (UW SSEC)
        devstral-small      → Devstral Small (UW SSEC)
        gpt-4o-2024-05-13   → GPT 4o 2024-05-13 (UW SSEC)  (date-like kept)
    """
    # Split on hyphens
    parts = model_id.split("-")

    # First pass: group consecutive long-numeric parts as dates (e.g. 2024-05-13)
    # and merge short version-number pairs (e.g. 4-6 → 4.6).
    merged: list[str] = []
    i = 0
    while i < len(parts):
        # Detect date-like runs: 3+ consecutive numeric parts where the first has 4 digits
        if (
            i + 2 < len(parts)
            and re.fullmatch(r"\d{4}", parts[i])
            and re.fullmatch(r"\d{1,2}", parts[i + 1])
            and re.fullmatch(r"\d{1,2}", parts[i + 2])
        ):
            # Consume the entire date-like run
            date_parts = [parts[i], parts[i + 1], parts[i + 2]]
            i += 3
            while i < len(parts) and re.fullmatch(r"\d+", parts[i]):
                date_parts.append(parts[i])
                i += 1
            merged.append("-".join(date_parts))
        # Merge short version pairs: "4", "6" → "4.6"
        elif (
            i + 1 < len(parts)
            and re.fullmatch(r"\d{1,2}", parts[i])
            and re.fullmatch(r"\d{1,2}", parts[i + 1])
            # Don't merge if followed by another 1-2 digit number (mid-date like 2024-05-13)
            and not (i + 2 < len(parts) and re.fullmatch(r"\d{1,2}", parts[i + 2]))
            # Don't merge if previous part was already numeric (mid-date)
            and not (merged and re.fullmatch(r"[\d.]+", merged[-1]))
        ):
            merged.append(f"{parts[i]}.{parts[i + 1]}")
            i += 2
        else:
            merged.append(parts[i])
            i += 1

    # Map of words that should use a specific casing
    SPECIAL_CASE = {
        "ssec": "SSEC",
        "gpt": "GPT",
    }

    def format_word(w: str) -> str:
        lower = w.lower()
        if lower in SPECIAL_CASE:
            return SPECIAL_CASE[lower]
        return w.capitalize() if w.isalpha() else w

    display = " ".join(format_word(word) for word in merged)
    return f"{display} {SUFFIX}"


def build_model_entry(
    model_id: str,
    max_tokens: int | None = None,
    max_input_tokens: int | None = None,
) -> dict:
    entry = {
        "id": model_id,
        "displayName": make_display_name(model_id),
        "owned_by": OWNER,
        "isUserSelectable": True,
    }
    if "claude" in model_id.lower():
        entry["apiMode"] = "anthropic"
        if max_tokens is None:
            print(
                f"Warning: no max_tokens reported for {model_id}; "
                f"falling back to {DEFAULT_ANTHROPIC_MAX_TOKENS}.",
                file=sys.stderr,
            )
        max_tokens = max_tokens or DEFAULT_ANTHROPIC_MAX_TOKENS
        entry["max_tokens"] = max_tokens
    else:
        entry["apiMode"] = "openai-responses"
        if max_tokens is not None:
            entry["max_tokens"] = max_tokens

    if max_input_tokens is not None:
        # The extension derives its input budget as context_length - max_tokens,
        # so context_length must cover the output budget on top of the context
        # window LiteLLM reports. Without this the two values can cancel out and
        # leave the model advertising a single usable input token.
        entry["context_length"] = max_input_tokens + (max_tokens or 0)
    return entry


def _strip_jsonc(text: str) -> str:
    """Remove single-line comments and trailing commas from JSONC text.

    Properly skips // inside quoted strings (e.g. URLs like https://...).
    """
    result: list[str] = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < len(text):
                # Skip escaped character
                i += 1
                result.append(text[i])
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            result.append(ch)
        elif ch == "/" and i + 1 < len(text) and text[i + 1] == "/":
            # Single-line comment — skip to end of line
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        else:
            result.append(ch)
        i += 1

    stripped = "".join(result)
    # Strip trailing commas before } or ], preserving any whitespace (including
    # newlines) so that line numbers in the stripped text still line up with
    # the original file for error reporting purposes.
    stripped = re.sub(r",(\s*)([}\]])", r"\1\2", stripped)
    return stripped


class SettingsError(Exception):
    """Raised when settings.json cannot be read or parsed."""


def read_settings(path: str) -> dict:
    """Read VS Code settings.json, tolerating trailing commas and comments.

    Raises:
        SettingsError: If the file cannot be read, or contains invalid JSON.
            The error message points to the offending line/column when possible.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as exc:
        raise SettingsError(f"Could not read settings file at {path}: {exc}") from exc

    # Normalise Windows-style \r\n line endings to \n
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    stripped = _strip_jsonc(raw)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        lines = stripped.split("\n")
        line_no = exc.lineno
        col_no = exc.colno
        offending_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        pointer = " " * max(col_no - 1, 0) + "^"
        raise SettingsError(
            f"Failed to parse {path} as JSON at line {line_no}, column {col_no}: {exc.msg}\n"
            f"    {offending_line}\n"
            f"    {pointer}\n"
            "Please check the file for issues near this location (e.g. a missing "
            "comma, an unmatched bracket, or a stray character) and try again."
        ) from exc


def write_settings(path: str, settings: dict) -> None:
    """Write settings back as nicely-formatted JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)
        f.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update VS Code OAI Copilot model list from LiteLLM."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the new model list without modifying settings.json.",
    )
    parser.add_argument(
        "--settings",
        default=SETTINGS_PATH,
        help=f"Path to VS Code settings.json (default: {SETTINGS_PATH})",
    )
    args = parser.parse_args()

    api_key = os.environ.get("LITELLM_API_KEY")
    if not api_key:
        api_key = input("LITELLM_API_KEY not set. Enter your API key: ").strip()
        if not api_key:
            print("Error: API key is required.", file=sys.stderr)
            sys.exit(1)

    base_url = os.environ.get("LITELLM_BASE_URL")
    if not base_url:
        base_url = input("LITELLM_BASE_URL not set. Enter the base URL: ").strip()
        if not base_url:
            print("Error: Base URL is required.", file=sys.stderr)
            sys.exit(1)

    print("Fetching models from LiteLLM…")
    fetched_models = fetch_models(base_url, api_key)
    if not fetched_models:
        print("Warning: No models returned from the API.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(fetched_models)} model(s):")
    models = []
    for fetched in fetched_models:
        entry = build_model_entry(
            fetched["name"], fetched["max_tokens"], fetched["max_input_tokens"]
        )
        models.append(entry)
        print(
            f"  {entry['id']:30s} → {entry['displayName']} [{entry['apiMode']}] "
            f"out={entry.get('max_tokens', '—')} ctx={entry.get('context_length', '—')}"
        )

    if args.dry_run:
        print("\n--dry-run: No changes written.")
        print(json.dumps(models, indent=4))
        return

    settings_path = args.settings
    if not os.path.exists(settings_path):
        print(f"Error: Settings file not found at {settings_path}", file=sys.stderr)
        sys.exit(1)

    try:
        settings = read_settings(settings_path)
    except SettingsError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    settings[SETTINGS_KEY] = models
    write_settings(settings_path, settings)
    print(f"\n✅ Updated {SETTINGS_KEY} in {settings_path}")


if __name__ == "__main__":
    main()
