"""Generic fallback adapter for unknown agent platforms.

Best-effort normalization of unknown hook JSON into ToolCallEvent. Extracts
content from all JSON values and scans it -- unknown agents get FULL scanning,
never bypass (T-03-05).

Used when:
- Agent type is not recognized by detect_agent_type()
- Explicit agent_type="generic" is passed to get_adapter()
- No raw_event is available for auto-detection
"""

from __future__ import annotations

import json
from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent


@register_adapter("generic")
class GenericAdapter:
    """Fallback adapter for unknown agent platforms.

    Extracts content from all known fields, falling back to a JSON dump
    of the entire event. Ensures unknown agents get full scanning coverage.
    """

    @property
    def agent_type(self) -> str:
        return "generic"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Best-effort normalization of unknown hook JSON."""
        # Try common event type field names
        event_type = (
            raw_event.get("event_type", "")
            or raw_event.get("hook_type", "")
            or raw_event.get("hook_event_name", "")
        )

        tool_name = raw_event.get("tool_name", "")
        session_id = raw_event.get("session_id", "")

        # Content extraction: try known field names, then JSON dump fallback
        content = raw_event.get("content", "") or raw_event.get("command", "")
        if not content:
            # Fallback: dump entire event as content for scanning (T-03-05)
            content = json.dumps(raw_event, default=str)

        return ToolCallEvent(
            event_type=event_type,
            tool_name=tool_name,
            tool_input=raw_event,
            content=content,
            session_id=session_id,
            raw_data=raw_event,
        )

    def format_response(self, result: DetectionResult, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Generic response format: exit_code + message."""
        return {
            "exit_code": result.exit_code,
            "message": result.message,
        }
