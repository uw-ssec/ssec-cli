"""Find which agents have session data on this machine.

Ported from agenthoist (https://github.com/uw-ssec/agenthoist).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from ssec_cli.sessions.agents import ALL_AGENTS, AgentConfig


@dataclass(frozen=True)
class DiscoveredAgent:
    """An agent whose session directory exists and is not empty."""

    agent: AgentConfig
    path: Path


def discover_agents(
    agents: list[AgentConfig] | None = None,
) -> tuple[list[DiscoveredAgent], list[str]]:
    """Discover which agents have session data on this machine.

    For each agent, the resolution order is:
    1. Environment variable override (``agent.env_override``)
    2. Platform-specific default path (``agent.default_path()``)

    Parameters
    ----------
    agents:
        Subset of agents to check. Defaults to ``ALL_AGENTS`` when ``None``.

    Returns
    -------
    tuple[list[DiscoveredAgent], list[str]]
        Agents that have a non-empty session directory, and a notice for each
        agent that was skipped.
    """
    candidates = agents if agents is not None else ALL_AGENTS
    discovered: list[DiscoveredAgent] = []
    skipped: list[str] = []

    for agent in candidates:
        path = resolve_path(agent)

        if path is None:
            skipped.append(
                f"Skipping {agent.display_name}: no default path for platform '{sys.platform}'"
            )
            continue

        if not path.is_dir():
            skipped.append(
                f"Skipping {agent.display_name}: directory not found ({path})"
            )
            continue

        try:
            empty = not any(path.iterdir())
        except OSError as error:
            skipped.append(
                f"Skipping {agent.display_name}: cannot read directory ({path}): "
                f"{error.strerror or error}"
            )
            continue
        if empty:
            skipped.append(
                f"Skipping {agent.display_name}: directory is empty ({path})"
            )
            continue

        discovered.append(DiscoveredAgent(agent, path))

    return discovered, skipped


def resolve_path(agent: AgentConfig) -> Path | None:
    """Return the resolved local path for an agent, or None if unavailable."""
    env_val = os.environ.get(agent.env_override)
    if env_val:
        return Path(env_val).expanduser()

    default = agent.default_path()
    if default is None:
        return None
    return default.expanduser()
