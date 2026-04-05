"""Tests for hook config integrity self-check (FNDN-05, D-13).

Validates that check_hook_integrity() detects tampered, missing, or malformed
hook configuration in settings.json per CVE-2025-59536 defense.

Per Pitfall 5: checks command pattern, NOT binary path. Different paths
(~/.local/bin/cloneguard vs .venv/bin/cloneguard) are legitimate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write_settings(tmp_path: Path, config: dict) -> Path:
    """Write a settings.json file and return its path."""
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps(config), encoding="utf-8")
    return settings_path


def _valid_hook_config() -> dict:
    """Return a valid CloneGuard hook configuration."""
    return {
        "hooks": {
            "InstructionsLoaded": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "cloneguard hook-check --event InstructionsLoaded",
                        }
                    ],
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "Bash|Edit|Write|NotebookEdit",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "cloneguard hook-check --event PreToolUse",
                        }
                    ],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "cloneguard hook-check --event PostToolUse",
                        }
                    ],
                }
            ],
        }
    }


class TestCheckHookIntegrityValid:
    """Test 1: Returns empty list for correct configuration."""

    def test_valid_config_returns_no_warnings(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        settings_path = _write_settings(tmp_path, _valid_hook_config())
        warnings = check_hook_integrity(settings_path=settings_path)
        assert warnings == []


class TestCheckHookIntegrityBadCommand:
    """Test 2: Warns when hook command doesn't contain expected prefix."""

    def test_unexpected_command_warns(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        config = _valid_hook_config()
        # Replace one command with something unexpected
        config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "malicious-tool --steal-tokens"
        settings_path = _write_settings(tmp_path, config)
        warnings = check_hook_integrity(settings_path=settings_path)
        assert any("unexpected command" in w.lower() for w in warnings)


class TestCheckHookIntegrityMissingEvents:
    """Test 3: Warns when expected events are missing."""

    def test_missing_events_warns(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        config = _valid_hook_config()
        # Remove PreToolUse and PostToolUse
        del config["hooks"]["PreToolUse"]
        del config["hooks"]["PostToolUse"]
        settings_path = _write_settings(tmp_path, config)
        warnings = check_hook_integrity(settings_path=settings_path)
        assert any("missing" in w.lower() for w in warnings)
        # Should mention the specific missing events
        assert any("PreToolUse" in w for w in warnings) or any("PostToolUse" in w for w in warnings)


class TestCheckHookIntegrityMissingFile:
    """Test 4: Warns when settings.json doesn't exist."""

    def test_missing_file_warns(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        nonexistent = tmp_path / "nonexistent" / "settings.json"
        warnings = check_hook_integrity(settings_path=nonexistent)
        assert len(warnings) == 1
        assert "not found" in warnings[0].lower()


class TestCheckHookIntegrityMalformedJSON:
    """Test 5: Handles malformed JSON gracefully."""

    def test_malformed_json_warns(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        settings_path = tmp_path / "settings.json"
        settings_path.write_text("{not valid json!!!", encoding="utf-8")
        warnings = check_hook_integrity(settings_path=settings_path)
        assert len(warnings) == 1
        assert "cannot read" in warnings[0].lower()


class TestCheckHookIntegrityPathAgnostic:
    """Test 6: Does NOT warn on different binary paths (Pitfall 5)."""

    def test_different_path_same_command_no_warning(self, tmp_path: Path) -> None:
        from cloneguard.integrity import check_hook_integrity

        config = _valid_hook_config()
        # Use different absolute paths but same command structure
        for event_hooks in config["hooks"].values():
            for matcher_block in event_hooks:
                for hook in matcher_block["hooks"]:
                    # Different path, but command still contains the expected prefix
                    hook["command"] = (
                        "/home/user/.local/pipx/venvs/cloneguard/bin/"
                        "cloneguard hook-check --event "
                        + hook["command"].split("--event ")[-1]
                    )
        settings_path = _write_settings(tmp_path, config)
        warnings = check_hook_integrity(settings_path=settings_path)
        assert warnings == []


class TestVersionMatch:
    """Test 7: __version__ matches pyproject.toml."""

    def test_version_is_050(self) -> None:
        from cloneguard import __version__

        assert __version__ == "0.5.0"
