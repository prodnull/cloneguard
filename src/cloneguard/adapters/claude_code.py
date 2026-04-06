"""Claude Code hook JSON adapter.

Normalizes Claude Code's hook protocol JSON (stdin) into ToolCallEvent.
Extracted from hooks.py inline JSON parsing logic per D-04.

Claude Code hook protocol:
  Input: {"hook_type": "PreToolUse|PostToolUse|InstructionsLoaded", "tool_name": str, ...}
  Response: exit code 0 (allow) or 2 (block), optional stdout message

Content extraction logic (TOCTOU-safe -- all from stdin JSON, never disk):
  InstructionsLoaded: join instructions[*].content with newlines
  PreToolUse: tool_input.get("content") or tool_input.get("command")
  PostToolUse: tool_output.get("content") or tool_output.get("stdout")
"""

from __future__ import annotations

from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent


@register_adapter("claude-code")
class ClaudeCodeAdapter:
    """Adapter for Claude Code hook protocol JSON."""

    @property
    def agent_type(self) -> str:
        return "claude-code"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Normalize Claude Code hook JSON into ToolCallEvent."""
        hook_type = raw_event.get("hook_type", "")
        tool_name = raw_event.get("tool_name", hook_type)
        tool_input = raw_event.get("tool_input", {})
        session_id = raw_event.get("session_id", "")

        # Content extraction depends on event type
        content = ""
        source_path = ""

        if hook_type == "InstructionsLoaded":
            instructions = raw_event.get("instructions", [])
            content = "\n".join(
                inst.get("content", "") for inst in instructions if isinstance(inst, dict)
            )
        elif hook_type == "PreToolUse":
            # Write/Edit: content field; Bash: command field
            content = tool_input.get("content", "") or tool_input.get("command", "")
            source_path = tool_input.get("file_path", "")
        elif hook_type == "PostToolUse":
            tool_output = raw_event.get("tool_output", {})
            if isinstance(tool_output, dict):
                content = tool_output.get("content", "") or tool_output.get("stdout", "")
            elif isinstance(tool_output, str):
                content = tool_output

        return ToolCallEvent(
            event_type=hook_type,
            tool_name=tool_name,
            tool_input=tool_input,
            content=content,
            source_path=source_path,
            session_id=session_id,
            raw_data=raw_event,
        )

    def format_response(self, result: DetectionResult, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Format response for Claude Code: exit_code + message (T-03-04).

        Claude Code uses exit codes (0=allow, 2=block) not JSON response body.
        Only exit_code and message are exposed -- no internal signals or confidence.
        """
        return {
            "exit_code": result.exit_code,
            "message": result.message,
        }
