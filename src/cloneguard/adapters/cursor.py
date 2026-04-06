"""Cursor hook JSON adapter.

Normalizes Cursor's hook protocol JSON into ToolCallEvent.

Cursor hook protocol (v2.6.13+):
  Shell input: {"conversation_id": str, "command": str,
                "hook_event_name": "beforeShellExecution",
                "workspace_roots": [str], "cwd": str}
  MCP input:   {"conversation_id": str, "server": str, "tool_name": str,
                "tool_input": "escaped JSON string",
                "hook_event_name": "beforeMCPExecution",
                "workspace_roots": [str]}
  Response: {"continue": true, "permission": "allow|deny|ask",
             "userMessage": str, "agentMessage": str}

Note: Cursor's tool_input for MCP events is a JSON-encoded string, not a dict.
The adapter parses it with json.loads() and falls back to scanning the raw string
as content if parsing fails (T-03-03).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent

logger = logging.getLogger(__name__)

# Cursor event name -> CloneGuard event type
_EVENT_MAP: dict[str, str] = {
    "beforeShellExecution": "PreToolUse",
    "beforeMCPExecution": "PreToolUse",
    "afterFileEdit": "PostToolUse",
    "beforeSubmitPrompt": "InstructionsLoaded",
}


@register_adapter("cursor")
class CursorAdapter:
    """Adapter for Cursor hook protocol JSON."""

    @property
    def agent_type(self) -> str:
        return "cursor"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Normalize Cursor hook JSON into ToolCallEvent."""
        hook_event_name = raw_event.get("hook_event_name", "")
        event_type = _EVENT_MAP.get(hook_event_name, hook_event_name)

        # Session ID: conversation_id or generation_id
        session_id = raw_event.get("conversation_id", "") or raw_event.get(
            "generation_id", ""
        )

        content = ""
        tool_name = ""
        tool_input: dict[str, Any] = {}

        if hook_event_name == "beforeShellExecution":
            tool_name = "shell"
            content = raw_event.get("command", "")
            tool_input = {"command": content}
        elif hook_event_name == "beforeMCPExecution":
            tool_name = raw_event.get("tool_name", "")
            raw_input = raw_event.get("tool_input", "")
            # Cursor sends tool_input as a JSON-encoded string
            if isinstance(raw_input, str) and raw_input:
                try:
                    tool_input = json.loads(raw_input)
                    # Content: join string values from parsed input
                    string_values = [str(v) for v in tool_input.values() if v]
                    content = " ".join(string_values) if string_values else raw_input
                except json.JSONDecodeError:
                    # Fallback: scan raw string as content (T-03-03)
                    logger.debug("Cursor MCP tool_input not valid JSON: %s", raw_input[:100])
                    content = raw_input
                    tool_input = {"raw": raw_input}
            elif isinstance(raw_input, dict):
                tool_input = raw_input
                string_values = [str(v) for v in tool_input.values() if v]
                content = " ".join(string_values)
        else:
            # Other events: best-effort content extraction
            tool_name = raw_event.get("tool_name", "")
            content = raw_event.get("content", "") or raw_event.get("command", "")

        return ToolCallEvent(
            event_type=event_type,
            tool_name=tool_name,
            tool_input=tool_input,
            content=content,
            session_id=session_id,
            raw_data=raw_event,
        )

    def format_response(
        self, result: DetectionResult, raw_event: dict[str, Any]
    ) -> dict[str, Any]:
        """Format response for Cursor: continue/permission/userMessage (T-03-04).

        Only permission and userMessage are exposed -- no internal signals.
        """
        if result.exit_code == 0:
            return {
                "continue": True,
                "permission": "allow",
            }
        return {
            "continue": False,
            "permission": "deny",
            "userMessage": result.message,
            "agentMessage": "",
        }
