"""Hook configuration integrity self-check (CVE-2025-59536 defense, D-13).

Verifies that the Claude Code hook configuration in settings.json points to
CloneGuard. Detects tampering, missing hooks, and configuration corruption.

Per Pitfall 5: checks command PATTERN (substring match), not absolute binary
path. Users may install CloneGuard via uv, pipx, or development venv --
different paths are legitimate as long as the command structure is correct.

Threat mitigations:
    T-03-01: Check command pattern, not path. Warn but do not block.
    T-03-05: Verify each expected event has a CloneGuard hook entry.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_EXPECTED_COMMAND_PREFIX = "cloneguard hook-check --event"
_EXPECTED_EVENTS = {"InstructionsLoaded", "PreToolUse", "PostToolUse"}


def check_hook_integrity(settings_path: Path | None = None) -> list[str]:
    """Verify hook configuration points to CloneGuard.

    Args:
        settings_path: Path to settings.json. Defaults to ~/.claude/settings.json.

    Returns:
        List of warning messages. Empty list = configuration intact.
    """
    warnings: list[str] = []

    if settings_path is None:
        settings_path = Path.home() / ".claude" / "settings.json"

    if not settings_path.exists():
        warnings.append(f"Hook config not found: {settings_path}")
        return warnings

    try:
        config = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        warnings.append(f"Cannot read hook config: {e}")
        return warnings

    hooks = config.get("hooks", {})
    found_events: set[str] = set()

    for event_name, matchers in hooks.items():
        if event_name not in _EXPECTED_EVENTS:
            continue
        if not isinstance(matchers, list):
            continue
        for matcher_block in matchers:
            if not isinstance(matcher_block, dict):
                continue
            for hook in matcher_block.get("hooks", []):
                if not isinstance(hook, dict):
                    continue
                command = hook.get("command", "")
                if _EXPECTED_COMMAND_PREFIX in command:
                    found_events.add(event_name)
                elif command:
                    warnings.append(
                        f"Hook {event_name} points to unexpected command: {command!r}"
                    )

    missing = _EXPECTED_EVENTS - found_events
    if missing:
        warnings.append(f"Missing CloneGuard hooks for events: {', '.join(sorted(missing))}")

    return warnings
