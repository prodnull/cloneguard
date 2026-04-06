"""MCP protocol middleware adapter for CloneGuard (D-09, D-10, D-11).

Refactored from mcp_plugin.py into the adapter framework. Normalizes MCP
CallToolRequest JSON into ToolCallEvent via the InputAdapter Protocol.
Scans both tool request content (before execution) and tool response content
(after execution) via scan_response().

Threat model:
    T-03-08: scan_response() passes ALL text content through DetectionEngine.
             Non-text items skipped (no text to scan).
    T-03-09: normalize() extracts tool description field alongside arguments
             to detect RADE (tool description poisoning) attacks.
    T-03-10: mcp_plugin.py backward compat shim only re-imports (accepted risk).
"""

from __future__ import annotations

import logging
from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.engine import get_detection_engine
from cloneguard.detection.types import DetectionResult, ToolCallEvent

logger = logging.getLogger(__name__)

# Import guard: mcp SDK is optional
try:
    from mcp import types as mcp_types  # noqa: F401

    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False


def _extract_text_from_arguments(arguments: dict[str, Any]) -> str:
    """Extract all string values from MCP tool arguments for scanning."""
    parts: list[str] = []
    for value in arguments.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            nested = _extract_text_from_arguments(value)
            if nested:
                parts.append(nested)
    return " ".join(parts)


@register_adapter("mcp")
class MCPAdapter:
    """MCP protocol adapter conforming to InputAdapter Protocol.

    Normalizes MCP CallToolRequest JSON into ToolCallEvent and provides
    scan_response() for post-execution content scanning (D-10).
    """

    @property
    def agent_type(self) -> str:
        return "mcp"

    @property
    def available(self) -> bool:
        """Whether the MCP SDK is installed."""
        return _MCP_AVAILABLE

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Normalize MCP CallToolRequest JSON into ToolCallEvent.

        Extracts tool name, arguments, and description (D-11 RADE surface)
        from the MCP request format.
        """
        params = raw_event.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        description = params.get("description", "")

        # Build content: arguments text + description (D-11: RADE detection)
        content_parts: list[str] = []
        arg_text = _extract_text_from_arguments(arguments)
        if arg_text:
            content_parts.append(arg_text)
        if description:
            content_parts.append(description)
        content = " ".join(content_parts)

        # Session ID from MCP request id or session_id
        session_id = str(raw_event.get("id", "")) or raw_event.get("session_id", "")

        return ToolCallEvent(
            event_type="PreToolUse",
            tool_name=tool_name,
            tool_input=arguments,
            content=content,
            session_id=session_id,
            raw_data=raw_event,
        )

    def format_response(
        self, result: DetectionResult, raw_event: dict[str, Any]
    ) -> dict[str, Any]:
        """Format DetectionResult into MCP-compatible response.

        exit_code == 0 -> not blocked
        exit_code == 2 -> blocked with reason
        """
        if result.exit_code == 2:
            return {
                "blocked": True,
                "reason": result.message,
            }
        return {"blocked": False}

    def scan_response(self, response: dict[str, Any]) -> DetectionResult:
        """Scan MCP tool response content through DetectionEngine (D-10).

        Extracts text from MCP response content items. Non-text items
        (image, resource) are skipped. Empty content returns clean result.

        T-03-08: ALL text content items are concatenated and scanned.
        """
        content_items = response.get("content", [])

        # Extract text from text-type content items only
        text_parts: list[str] = []
        for item in content_items:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text", "")
                if text:
                    text_parts.append(text)

        if not text_parts:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        combined_text = "\n".join(text_parts)

        event = ToolCallEvent(
            event_type="PostToolUse",
            tool_name="mcp_response",
            tool_input={},
            content=combined_text,
            raw_data=response,
        )

        return get_detection_engine().scan(event)


class CloneGuardMCPPlugin:
    """Backward-compatible MCP Gateway plugin wrapping MCPAdapter.

    Provides process_request() and process_response() methods matching
    the old mcp-gateway GuardrailPlugin interface. Uses MCPAdapter
    internally for normalization and scanning.
    """

    def __init__(self) -> None:
        self._adapter = MCPAdapter()

    def process_request(
        self,
        server_name: str = "",
        capability_name: str = "",
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Scan tool input arguments for prompt injection.

        Returns the original arguments if clean, or None to block.
        Preserves existing mcp_plugin.py severity mapping:
        CRITICAL/HIGH -> block (None), MEDIUM -> warn, LOW -> pass.
        """
        if arguments is None:
            return arguments

        raw_event = {
            "method": "tools/call",
            "params": {
                "name": capability_name,
                "arguments": arguments,
            },
        }

        event = self._adapter.normalize(raw_event)
        result = get_detection_engine().scan(event)

        if result.exit_code == 2:
            logger.warning(
                "CloneGuard MCP: BLOCKED request %s/%s — %s",
                server_name,
                capability_name,
                result.message,
            )
            return None

        if result.verdict == "suspicious":
            logger.warning(
                "CloneGuard MCP: SUSPICIOUS request %s/%s (allowed) — %s",
                server_name,
                capability_name,
                result.message,
            )

        return arguments

    def process_response(
        self,
        content: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Scan tool response text for injection patterns.

        Returns scan result dict. Does not modify the response (mirrors
        original mcp_plugin.py behavior of logging but not blocking responses).
        """
        response = {"content": content or []}
        result = self._adapter.scan_response(response)

        if result.verdict != "clean":
            logger.warning(
                "CloneGuard MCP: response flagged — verdict=%s, %s",
                result.verdict,
                result.message,
            )

        return {
            "verdict": result.verdict,
            "blocked": result.exit_code == 2,
            "message": result.message,
        }
