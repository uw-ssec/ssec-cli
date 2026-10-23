"""Minimal version parsing and comparison (no `packaging` dependency)."""

import re

_LEADING = re.compile(r"^\s*v?(\d+(?:\.\d+)*)(.*)$", re.DOTALL)
_PRERELEASE = re.compile(r"^[.\-_]?(a|b|c|rc|alpha|beta|pre|preview|dev)(?![a-z])", re.IGNORECASE)
_TOKEN = re.compile(r"\d+(\.\d+)+[0-9A-Za-z.+-]*")


def parse_version(text: str) -> tuple[tuple[int, ...], bool] | None:
    """Return (release numbers, is_prerelease), or None if no leading number."""
    m = _LEADING.match(text)
    if not m:
        return None
    release = tuple(int(p) for p in m.group(1).split("."))
    return release, bool(_PRERELEASE.match(m.group(2)))


def is_below(current: str, minimum: str) -> bool | None:
    """True if `current` < `minimum`; None if either can't be parsed.

    post-release and +local suffixes are ignored.
    """
    cur = parse_version(current)
    mini = parse_version(minimum)
    if cur is None or mini is None:
        return None
    (c_rel, c_pre), (m_rel, m_pre) = cur, mini
    width = max(len(c_rel), len(m_rel))
    c_rel += (0,) * (width - len(c_rel))
    m_rel += (0,) * (width - len(m_rel))
    if c_rel != m_rel:
        return c_rel < m_rel
    return c_pre and not m_pre


def extract_version(text: str) -> str | None:
    """Return the first dotted version token in `text`, if any."""
    m = _TOKEN.search(text)
    return m.group(0) if m else None
