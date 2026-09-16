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


def fetch_model_names(base_url: str, api_key: str) -> list[str]:
    """Fetch model names from the LiteLLM /model/info endpoint."""
    url = f"{base_url}/model/info"
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
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"Error: HTTP {exc.code} from {url}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Error: Could not reach {url}: {exc.reason}", file=sys.stderr)
        sys.exit(1)

    names: list[str] = []
    for entry in data.get("data", []):
        name = entry.get("model_name")
        if name and name not in names:
            names.append(name)
    return sorted(names)


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


def build_model_entry(model_id: str) -> dict:
    return {
        "id": model_id,
        "displayName": make_display_name(model_id),
        "owned_by": OWNER,
        "isUserSelectable": True,
    }


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
    # Strip trailing commas before } or ]
    stripped = re.sub(r",\s*([}\]])", r"\1", stripped)
    return stripped


def read_settings(path: str) -> dict:
    """Read VS Code settings.json, tolerating trailing commas and comments."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    # Normalise Windows-style \r\n line endings to \n
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    return json.loads(_strip_jsonc(raw))


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
    model_names = fetch_model_names(base_url, api_key)
    if not model_names:
        print("Warning: No models returned from the API.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(model_names)} model(s):")
    models = []
    for name in model_names:
        entry = build_model_entry(name)
        models.append(entry)
        print(f"  {entry['id']:30s} → {entry['displayName']}")

    if args.dry_run:
        print("\n--dry-run: No changes written.")
        print(json.dumps(models, indent=4))
        return

    settings_path = args.settings
    if not os.path.exists(settings_path):
        print(f"Error: Settings file not found at {settings_path}", file=sys.stderr)
        sys.exit(1)

    settings = read_settings(settings_path)
    settings[SETTINGS_KEY] = models
    write_settings(settings_path, settings)
    print(f"\n✅ Updated {SETTINGS_KEY} in {settings_path}")


if __name__ == "__main__":
    main()
