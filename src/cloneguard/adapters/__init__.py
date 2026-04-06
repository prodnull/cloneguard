"""InputAdapter Protocol and adapter registry for multi-platform agent support.

Defines the InputAdapter Protocol (PEP 544 structural subtyping) that decouples
CloneGuard's detection engine from any specific agent platform's hook protocol.
Each agent platform (Claude Code, Gemini CLI, Cursor) gets its own adapter module
that translates platform-specific hook JSON into the existing ToolCallEvent dataclass.

Auto-detection probes JSON structure to select the correct adapter. Unknown agent
types fall back to GenericAdapter which scans all content -- never silently passes
(T-03-05).

Registry pattern: register_adapter() decorator adds classes to _ADAPTERS dict.
get_adapter() returns an instantiated adapter by agent type string or auto-detection.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from cloneguard.detection.types import DetectionResult, ToolCallEvent

# Adapter registry: agent_type string -> adapter class
_ADAPTERS: dict[str, type[InputAdapter]] = {}


@runtime_checkable
class InputAdapter(Protocol):
    """Protocol for normalizing agent-specific hook JSON into ToolCallEvent.

    Structural subtyping (PEP 544): any class implementing these three members
    satisfies the protocol without explicit inheritance. Follows the same pattern
    as SandboxAdapter in enforcement/adapter.py.
    """

    @property
    def agent_type(self) -> str:
        """Agent platform identifier (e.g., 'claude-code', 'gemini-cli')."""
        ...

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Translate platform-specific hook JSON into a normalized ToolCallEvent.

        Must be TOCTOU-safe: all content extracted from raw_event dict,
        never re-read from disk. Returns frozen ToolCallEvent (T-03-02).
        """
        ...

    def format_response(
        self, result: DetectionResult, raw_event: dict[str, Any]
    ) -> dict[str, Any]:
        """Format a DetectionResult into the platform-specific response format.

        Must not leak internal state -- only exit_code/message, decision/reason,
        or permission/userMessage depending on platform (T-03-04).
        """
        ...


def register_adapter(agent_type: str) -> Any:
    """Decorator that registers an adapter class in the _ADAPTERS registry."""

    def decorator(cls: type[InputAdapter]) -> type[InputAdapter]:
        _ADAPTERS[agent_type] = cls
        return cls

    return decorator


def detect_agent_type(raw_event: dict[str, Any]) -> str:
    """Auto-detect agent type from hook JSON structure (T-03-01).

    Uses definitive keys to distinguish platforms:
    - hook_type -> claude-code (Claude Code uses hook_type field)
    - hook_event_name + workspace_roots -> cursor (Cursor always includes workspace_roots)
    - hook_event_name (without workspace_roots) -> gemini-cli
    - Anything else -> generic (gets full scanning, never bypass)
    """
    if "hook_type" in raw_event:
        return "claude-code"
    if "hook_event_name" in raw_event and "workspace_roots" in raw_event:
        return "cursor"
    if "hook_event_name" in raw_event:
        return "gemini-cli"
    return "generic"


def get_adapter(
    agent_type: str = "auto", raw_event: dict[str, Any] | None = None
) -> InputAdapter:
    """Return an instantiated adapter for the given agent type.

    If agent_type is "auto" and raw_event is provided, auto-detects the agent
    type from JSON structure. Unknown agent types fall back to GenericAdapter
    (T-03-05: unknown agents get full scanning, not bypass).
    """
    if agent_type == "auto":
        if raw_event is not None:
            agent_type = detect_agent_type(raw_event)
        else:
            agent_type = "generic"

    adapter_cls = _ADAPTERS.get(agent_type)
    if adapter_cls is None:
        # Fallback to GenericAdapter for unknown agent types
        adapter_cls = _ADAPTERS.get("generic")
        if adapter_cls is None:
            # Import GenericAdapter directly if registry not yet populated
            from cloneguard.adapters.generic import GenericAdapter

            return GenericAdapter()
    return adapter_cls()


# Import adapter modules to trigger registration via @register_adapter decorators.
# These imports must come after the registry and Protocol definitions above.
import cloneguard.adapters.cicd as _ci  # noqa: E402, F401
import cloneguard.adapters.claude_code as _cc  # noqa: E402, F401
import cloneguard.adapters.cursor as _cu  # noqa: E402, F401
import cloneguard.adapters.gemini_cli as _gc  # noqa: E402, F401
import cloneguard.adapters.generic as _ge  # noqa: E402, F401
