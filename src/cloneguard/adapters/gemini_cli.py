"""Gemini CLI hook JSON adapter.

Normalizes Gemini CLI's hook protocol JSON into ToolCallEvent.

Gemini CLI hook protocol (v0.30.1+):
  Input: {"session_id": str, "hook_event_name": "BeforeTool|AfterTool|SessionStart",
          "tool_name": str, "tool_input": {}, "cwd": str, "mcp_context": {}}
  Response: {"decision": "allow|deny|block", "reason": str, "continue": true,
             "hookSpecificOutput": {}}

Event name mapping:
  BeforeTool -> PreToolUse
  AfterTool -> PostToolUse
  SessionStart -> InstructionsLoaded (best-effort)
"""

from __future__ import annotations

from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent

# Gemini CLI event name -> CloneGuard event type
_EVENT_MAP: dict[str, str] = {
    "BeforeTool": "PreToolUse",
    "AfterTool": "PostToolUse",
    "SessionStart": "InstructionsLoaded",
}


@register_adapter("gemini-cli")
class GeminiCLIAdapter:
    """Adapter for Gemini CLI hook protocol JSON."""

    @property
    def agent_type(self) -> str:
        return "gemini-cli"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Normalize Gemini CLI hook JSON into ToolCallEvent."""
        hook_event_name = raw_event.get("hook_event_name", "")
        event_type = _EVENT_MAP.get(hook_event_name, hook_event_name)

        tool_name = raw_event.get("tool_name", "") or raw_event.get("original_request_name", "")
        tool_input = raw_event.get("tool_input", {})
        session_id = raw_event.get("session_id", "")

        # Content extraction: join string values from tool_input
        content = ""
        if isinstance(tool_input, dict):
            string_values = [str(v) for v in tool_input.values() if v]
            content = " ".join(string_values)

        # For AfterTool, also check output fields
        if hook_event_name == "AfterTool":
            output = raw_event.get("output", "")
            if output:
                content = str(output)

        return ToolCallEvent(
            event_type=event_type,
            tool_name=tool_name,
            tool_input=tool_input if isinstance(tool_input, dict) else {},
            content=content,
            session_id=session_id,
            raw_data=raw_event,
        )

    def format_response(self, result: DetectionResult, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Format response for Gemini CLI: decision/reason/continue (T-03-04).

        Only decision, reason, and continue are exposed -- no internal signals.
        """
        if result.exit_code == 0:
            return {
                "decision": "allow",
                "reason": result.message,
                "continue": True,
                "hookSpecificOutput": {},
            }
        return {
            "decision": "block",
            "reason": result.message,
            "continue": False,
            "hookSpecificOutput": {},
        }
