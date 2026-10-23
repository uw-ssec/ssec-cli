"""Session storage locations for the AI coding agents ssec-cli can archive.

Ported from agenthoist (https://github.com/uw-ssec/agenthoist).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    """Configuration for a single AI agent's session storage."""

    name: str
    """Identifier and archive subdirectory (e.g., 'claude-code')."""

    display_name: str
    """Human-readable name (e.g., 'Claude Code')."""

    default_paths: dict[str, Path]
    """Platform-specific session directory paths, keyed by sys.platform values:
    'darwin', 'linux', 'win32'. Use Path with ~ for home-relative paths."""

    env_override: str
    """Environment variable that overrides the default path."""

    def default_path(self) -> Path | None:
        """Return the default path for the current platform, or None if unsupported."""
        return self.default_paths.get(sys.platform)


def _home_path(*parts: str) -> Path:
    """Return a Path relative to home for all platforms (darwin/linux/win32)."""
    return Path("~").joinpath(*parts)


def _platform_paths(
    darwin: str,
    linux: str,
    win32: str,
) -> dict[str, Path]:
    return {
        "darwin": Path("~") / darwin,
        "linux": Path("~") / linux,
        "win32": Path("~") / win32,
    }


def _universal_path(rel: str) -> dict[str, Path]:
    """Return the same relative path for all three platforms."""
    p = _home_path(rel)
    return {"darwin": p, "linux": p, "win32": p}


ALL_AGENTS: list[AgentConfig] = [
    AgentConfig(
        name="claude-code",
        display_name="Claude Code",
        default_paths=_universal_path(".claude/projects"),
        env_override="CLAUDE_PROJECTS_DIR",
    ),
    AgentConfig(
        name="codex",
        display_name="Codex",
        default_paths=_universal_path(".codex/sessions"),
        env_override="CODEX_SESSIONS_DIR",
    ),
    AgentConfig(
        name="copilot-cli",
        display_name="Copilot CLI",
        default_paths=_universal_path(".copilot/session-state"),
        env_override="COPILOT_DIR",
    ),
    AgentConfig(
        name="cursor",
        display_name="Cursor",
        default_paths=_universal_path(".cursor/projects"),
        env_override="CURSOR_PROJECTS_DIR",
    ),
    AgentConfig(
        name="gemini-cli",
        display_name="Gemini CLI",
        default_paths=_universal_path(".gemini"),
        env_override="GEMINI_DIR",
    ),
    AgentConfig(
        name="opencode",
        display_name="OpenCode",
        default_paths=_universal_path(".local/share/opencode"),
        env_override="OPENCODE_DIR",
    ),
    AgentConfig(
        name="amp",
        display_name="Amp",
        default_paths=_universal_path(".local/share/amp/threads"),
        env_override="AMP_DIR",
    ),
    AgentConfig(
        name="vscode-copilot",
        display_name="VS Code Copilot",
        default_paths=_platform_paths(
            darwin=(
                "Library/Application Support/Code/User"
                "/globalStorage/github.copilot-chat"
            ),
            linux=".config/Code/User/globalStorage/github.copilot-chat",
            win32="AppData/Roaming/Code/User/globalStorage/github.copilot-chat",
        ),
        env_override="VSCODE_COPILOT_DIR",
    ),
    AgentConfig(
        name="openclaw",
        display_name="OpenClaw",
        default_paths=_universal_path(".openclaw/agents"),
        env_override="OPENCLAW_DIR",
    ),
    AgentConfig(
        name="pi",
        display_name="Pi",
        default_paths=_universal_path(".pi/agent/sessions"),
        env_override="PI_DIR",
    ),
    AgentConfig(
        name="iflow",
        display_name="iFlow",
        default_paths=_universal_path(".iflow/projects"),
        env_override="IFLOW_DIR",
    ),
    AgentConfig(
        name="zencoder",
        display_name="Zencoder",
        default_paths=_universal_path(".zencoder/sessions"),
        env_override="ZENCODER_DIR",
    ),
    AgentConfig(
        name="kimi",
        display_name="Kimi",
        default_paths=_universal_path(".kimi/sessions"),
        env_override="KIMI_DIR",
    ),
    AgentConfig(
        name="warp",
        display_name="Warp",
        default_paths=_platform_paths(
            darwin=(
                "Library/Group Containers/2BBY89MBSN.dev.warp"
                "/Library/Application Support/dev.warp.Warp-Stable"
            ),
            linux=".local/state/warp-terminal",
            win32="AppData/Local/warp/Warp/data",
        ),
        env_override="WARP_DIR",
    ),
    AgentConfig(
        name="hermes-agent",
        display_name="Hermes Agent",
        default_paths=_universal_path(".hermes/sessions"),
        env_override="HERMES_SESSIONS_DIR",
    ),
    AgentConfig(
        name="cortex-code",
        display_name="Cortex Code",
        default_paths=_universal_path(".snowflake/cortex/conversations"),
        env_override="CORTEX_DIR",
    ),
    AgentConfig(
        name="kiro-cli",
        display_name="Kiro CLI",
        default_paths=_universal_path(".kiro/sessions/cli"),
        env_override="KIRO_SESSIONS_DIR",
    ),
    AgentConfig(
        name="kiro-ide",
        display_name="Kiro IDE",
        default_paths=_platform_paths(
            darwin="Library/Application Support/Kiro/User/globalStorage/kiro.kiroagent",
            linux=".config/Kiro/User/globalStorage/kiro.kiroagent",
            win32="AppData/Roaming/Kiro/User/globalStorage/kiro.kiroagent",
        ),
        env_override="KIRO_IDE_DIR",
    ),
]
