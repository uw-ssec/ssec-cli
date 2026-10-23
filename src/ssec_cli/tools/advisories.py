"""Load the bundled security-advisory minimum versions."""

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

from ssec_cli.tools.versions import is_below


@dataclass(frozen=True)
class PackageMinimum:
    package: str
    min_version: str
    advisory_id: str
    fix_url: str | None = None
    fix_sha256: str | None = None


@dataclass
class Advisory:
    id: str
    title: str
    date: str
    urls: list[str]
    minimums: list[PackageMinimum]


def normalize_name(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def load_advisories(path: Path | None = None) -> list[Advisory]:
    if path is None:
        data = (resources.files("ssec_cli") / "advisories.toml").read_bytes()
    else:
        data = Path(path).read_bytes()
    raw = tomllib.loads(data.decode("utf-8"))
    advisories = []
    for entry in raw.get("advisory", []):
        minimums = [
            PackageMinimum(
                package=m["package"],
                min_version=m["min_version"],
                advisory_id=entry["id"],
                fix_url=m.get("fix_url"),
                fix_sha256=m.get("fix_sha256"),
            )
            for m in entry.get("minimum", [])
        ]
        advisories.append(
            Advisory(
                id=entry["id"],
                title=entry["title"],
                date=entry["date"],
                urls=list(entry.get("urls", [])),
                minimums=minimums,
            )
        )
    return advisories


def minimums_by_package(advs: list[Advisory]) -> dict[str, PackageMinimum]:
    """Highest minimum per normalized package name."""
    result: dict[str, PackageMinimum] = {}
    for adv in advs:
        for m in adv.minimums:
            key = normalize_name(m.package)
            existing = result.get(key)
            if existing is None or is_below(existing.min_version, m.min_version):
                result[key] = m
    return result
