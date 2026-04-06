"""Tests for InputAdapter Protocol, adapter registry, and platform adapters.

Validates that each platform's hook JSON format normalizes correctly into
ToolCallEvent, that the adapter registry auto-detects agent types from JSON
structure, and that all adapters satisfy the InputAdapter Protocol (PEP 544).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cloneguard.adapters import (
    InputAdapter,
    detect_agent_type,
    get_adapter,
)
from cloneguard.adapters.claude_code import ClaudeCodeAdapter
from cloneguard.adapters.cursor import CursorAdapter
from cloneguard.adapters.gemini_cli import GeminiCLIAdapter
from cloneguard.adapters.generic import GenericAdapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent


# ---------------------------------------------------------------------------
# Protocol conformance tests
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    """All adapter classes satisfy isinstance(adapter, InputAdapter)."""

    def test_claude_code_is_input_adapter(self) -> None:
        adapter = ClaudeCodeAdapter()
        assert isinstance(adapter, InputAdapter)

    def test_gemini_cli_is_input_adapter(self) -> None:
        adapter = GeminiCLIAdapter()
        assert isinstance(adapter, InputAdapter)

    def test_cursor_is_input_adapter(self) -> None:
        adapter = CursorAdapter()
        assert isinstance(adapter, InputAdapter)

    def test_generic_is_input_adapter(self) -> None:
        adapter = GenericAdapter()
        assert isinstance(adapter, InputAdapter)


# ---------------------------------------------------------------------------
# ClaudeCodeAdapter tests
# ---------------------------------------------------------------------------


class TestClaudeCodeAdapter:
    """Claude Code hook JSON normalization."""

    def test_agent_type(self) -> None:
        adapter = ClaudeCodeAdapter()
        assert adapter.agent_type == "claude-code"

    def test_normalize_pre_tool_use(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "session_id": "s1",
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert isinstance(event, ToolCallEvent)
        assert event.event_type == "PreToolUse"
        assert event.tool_name == "Bash"
        assert event.tool_input == {"command": "ls -la"}
        assert event.content == "ls -la"
        assert event.session_id == "s1"

    def test_normalize_instructions_loaded(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "InstructionsLoaded",
            "instructions": [{"content": "# Rules"}],
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "InstructionsLoaded"
        assert event.content == "# Rules"

    def test_normalize_instructions_loaded_multiple(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "InstructionsLoaded",
            "instructions": [
                {"content": "# Rules"},
                {"content": "# More rules"},
            ],
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert event.content == "# Rules\n# More rules"

    def test_normalize_post_tool_use(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "PostToolUse",
            "tool_name": "Read",
            "tool_output": {"content": "file data"},
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "PostToolUse"
        assert event.content == "file data"

    def test_normalize_pre_tool_use_write_content(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.py", "content": "malicious code"},
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert event.content == "malicious code"
        assert event.source_path == "/tmp/test.py"

    def test_format_response_allow(self) -> None:
        result = DetectionResult(verdict="clean", confidence=1.0, exit_code=0, message="")
        adapter = ClaudeCodeAdapter()
        response = adapter.format_response(result, {})
        assert response == {"exit_code": 0, "message": ""}

    def test_format_response_block(self) -> None:
        result = DetectionResult(
            verdict="detected", confidence=0.95, exit_code=2, message="blocked"
        )
        adapter = ClaudeCodeAdapter()
        response = adapter.format_response(result, {})
        assert response == {"exit_code": 2, "message": "blocked"}

    def test_raw_data_preserved(self) -> None:
        raw: dict[str, Any] = {
            "hook_type": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "s1",
        }
        adapter = ClaudeCodeAdapter()
        event = adapter.normalize(raw)
        assert event.raw_data == raw


# ---------------------------------------------------------------------------
# GeminiCLIAdapter tests
# ---------------------------------------------------------------------------


class TestGeminiCLIAdapter:
    """Gemini CLI hook JSON normalization."""

    def test_agent_type(self) -> None:
        adapter = GeminiCLIAdapter()
        assert adapter.agent_type == "gemini-cli"

    def test_normalize_before_tool(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "BeforeTool",
            "tool_name": "shell",
            "tool_input": {"cmd": "x"},
            "session_id": "g1",
        }
        adapter = GeminiCLIAdapter()
        event = adapter.normalize(raw)
        assert isinstance(event, ToolCallEvent)
        assert event.event_type == "PreToolUse"
        assert event.tool_name == "shell"
        assert event.content == "x"

    def test_normalize_after_tool(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "AfterTool",
            "tool_name": "shell",
            "tool_input": {},
            "session_id": "g1",
        }
        adapter = GeminiCLIAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "PostToolUse"

    def test_format_response_allow(self) -> None:
        result = DetectionResult(verdict="clean", confidence=1.0, exit_code=0, message="")
        adapter = GeminiCLIAdapter()
        response = adapter.format_response(result, {})
        assert response["decision"] == "allow"
        assert response["continue"] is True

    def test_format_response_block(self) -> None:
        result = DetectionResult(
            verdict="detected", confidence=0.95, exit_code=2, message="injection detected"
        )
        adapter = GeminiCLIAdapter()
        response = adapter.format_response(result, {})
        assert response["decision"] == "block"
        assert response["reason"] == "injection detected"
        assert response["continue"] is False

    def test_normalize_session_start(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "SessionStart",
            "session_id": "g2",
        }
        adapter = GeminiCLIAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "InstructionsLoaded"
        assert event.session_id == "g2"


# ---------------------------------------------------------------------------
# CursorAdapter tests
# ---------------------------------------------------------------------------


class TestCursorAdapter:
    """Cursor hook JSON normalization."""

    def test_agent_type(self) -> None:
        adapter = CursorAdapter()
        assert adapter.agent_type == "cursor"

    def test_normalize_before_shell_execution(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "beforeShellExecution",
            "command": "rm -rf /",
            "workspace_roots": ["/repo"],
            "conversation_id": "c1",
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        assert isinstance(event, ToolCallEvent)
        assert event.event_type == "PreToolUse"
        assert event.tool_name == "shell"
        assert event.content == "rm -rf /"
        assert event.session_id == "c1"

    def test_normalize_before_mcp_execution(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "read",
            "tool_input": json.dumps({"path": "/etc/passwd"}),
            "workspace_roots": ["/repo"],
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        assert event.tool_input == {"path": "/etc/passwd"}

    def test_normalize_before_mcp_invalid_json_fallback(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "beforeMCPExecution",
            "tool_input": "not-json",
            "workspace_roots": ["/repo"],
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        # Should not crash; falls back to scanning raw string as content
        assert "not-json" in event.content

    def test_normalize_after_file_edit(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "afterFileEdit",
            "workspace_roots": ["/repo"],
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "PostToolUse"

    def test_normalize_before_submit_prompt(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "beforeSubmitPrompt",
            "workspace_roots": ["/repo"],
            "conversation_id": "c2",
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        assert event.event_type == "InstructionsLoaded"

    def test_format_response_allow(self) -> None:
        result = DetectionResult(verdict="clean", confidence=1.0, exit_code=0, message="")
        adapter = CursorAdapter()
        response = adapter.format_response(result, {})
        assert response["continue"] is True
        assert response["permission"] == "allow"

    def test_format_response_block(self) -> None:
        result = DetectionResult(
            verdict="detected", confidence=0.95, exit_code=2, message="blocked"
        )
        adapter = CursorAdapter()
        response = adapter.format_response(result, {})
        assert response["continue"] is False
        assert response["permission"] == "deny"
        assert response["userMessage"] == "blocked"

    def test_session_id_from_generation_id(self) -> None:
        raw: dict[str, Any] = {
            "hook_event_name": "beforeShellExecution",
            "command": "ls",
            "workspace_roots": ["/repo"],
            "generation_id": "gen-123",
        }
        adapter = CursorAdapter()
        event = adapter.normalize(raw)
        assert event.session_id == "gen-123"


# ---------------------------------------------------------------------------
# GenericAdapter tests
# ---------------------------------------------------------------------------


class TestGenericAdapter:
    """Generic fallback adapter for unknown agents."""

    def test_agent_type(self) -> None:
        adapter = GenericAdapter()
        assert adapter.agent_type == "generic"

    def test_normalize_with_content_field(self) -> None:
        raw: dict[str, Any] = {"unknown": "format", "content": "some text"}
        adapter = GenericAdapter()
        event = adapter.normalize(raw)
        assert isinstance(event, ToolCallEvent)
        assert event.content == "some text"

    def test_normalize_empty_dict(self) -> None:
        adapter = GenericAdapter()
        event = adapter.normalize({})
        # Should not crash; returns ToolCallEvent with empty strings
        assert isinstance(event, ToolCallEvent)
        assert event.event_type == ""

    def test_normalize_fallback_to_json_dump(self) -> None:
        raw: dict[str, Any] = {"random_key": "random_value"}
        adapter = GenericAdapter()
        event = adapter.normalize(raw)
        # Content should contain some representation when no known field found
        assert event.content  # Non-empty content from JSON dump fallback

    def test_format_response(self) -> None:
        result = DetectionResult(
            verdict="detected", confidence=0.9, exit_code=2, message="threat"
        )
        adapter = GenericAdapter()
        response = adapter.format_response(result, {})
        assert response == {"exit_code": 2, "message": "threat"}


# ---------------------------------------------------------------------------
# detect_agent_type() tests
# ---------------------------------------------------------------------------


class TestDetectAgentType:
    """Agent type auto-detection from JSON structure."""

    def test_claude_code_detection(self) -> None:
        assert detect_agent_type({"hook_type": "PreToolUse"}) == "claude-code"

    def test_gemini_cli_detection(self) -> None:
        assert detect_agent_type({"hook_event_name": "BeforeTool", "session_id": "x"}) == (
            "gemini-cli"
        )

    def test_cursor_detection(self) -> None:
        assert (
            detect_agent_type(
                {"hook_event_name": "beforeShellExecution", "workspace_roots": []}
            )
            == "cursor"
        )

    def test_generic_fallback(self) -> None:
        assert detect_agent_type({"random": "data"}) == "generic"

    def test_cursor_with_workspace_roots_takes_priority(self) -> None:
        # Both hook_event_name and workspace_roots present -> cursor
        raw: dict[str, Any] = {
            "hook_event_name": "BeforeTool",
            "workspace_roots": ["/repo"],
        }
        assert detect_agent_type(raw) == "cursor"


# ---------------------------------------------------------------------------
# get_adapter() tests
# ---------------------------------------------------------------------------


class TestGetAdapter:
    """Adapter registry lookup and auto-detection."""

    def test_get_claude_code_adapter(self) -> None:
        adapter = get_adapter("claude-code")
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_get_gemini_cli_adapter(self) -> None:
        adapter = get_adapter("gemini-cli")
        assert isinstance(adapter, GeminiCLIAdapter)

    def test_get_cursor_adapter(self) -> None:
        adapter = get_adapter("cursor")
        assert isinstance(adapter, CursorAdapter)

    def test_get_generic_adapter(self) -> None:
        adapter = get_adapter("generic")
        assert isinstance(adapter, GenericAdapter)

    def test_auto_detect_claude_code(self) -> None:
        adapter = get_adapter("auto", raw_event={"hook_type": "PreToolUse"})
        assert isinstance(adapter, ClaudeCodeAdapter)

    def test_auto_detect_gemini_cli(self) -> None:
        adapter = get_adapter(
            "auto", raw_event={"hook_event_name": "BeforeTool", "session_id": "x"}
        )
        assert isinstance(adapter, GeminiCLIAdapter)

    def test_auto_detect_cursor(self) -> None:
        adapter = get_adapter(
            "auto",
            raw_event={"hook_event_name": "beforeShellExecution", "workspace_roots": []},
        )
        assert isinstance(adapter, CursorAdapter)

    def test_unknown_agent_returns_generic(self) -> None:
        adapter = get_adapter("unknown-agent")
        assert isinstance(adapter, GenericAdapter)

    def test_auto_without_raw_event_returns_generic(self) -> None:
        adapter = get_adapter("auto")
        assert isinstance(adapter, GenericAdapter)
