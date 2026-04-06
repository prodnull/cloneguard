"""OTel span emitter for CloneGuard audit events (D-18).

Emits OpenTelemetry spans conforming to GenAI semantic conventions (experimental).
When opentelemetry-api is not installed, all methods are no-ops -- zero import
overhead. When installed without an SDK, spans are NonRecordingSpan (zero export
overhead). Export is configured via standard OTEL_EXPORTER_* environment variables
(D-19) -- CloneGuard does not manage the collector.

Threat model:
    T-03-12: Never include raw tool_input or gen_ai.tool.call.arguments in spans.
             Only hashes, verdicts, and metadata. Span attributes are selected
             explicitly from AuditEvent fields.
    T-03-14: Never call force_flush(). Span creation is synchronous (<1ms) but
             export is async via SDK BatchSpanProcessor.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)

_tracer: Any = None
_OTEL_AVAILABLE: bool = False

try:
    from opentelemetry import trace

    _tracer = trace.get_tracer(
        "cloneguard",
        schema_url="https://opentelemetry.io/schemas/1.29.0",
    )
    _OTEL_AVAILABLE = True
except ImportError:
    _tracer = None
    _OTEL_AVAILABLE = False


class OTelEmitter:
    """Emit OpenTelemetry spans for CloneGuard audit events.

    Zero-cost when opentelemetry-api is not installed: emit() returns
    immediately without any side effects. When the API is available but
    no SDK is configured, spans are NonRecordingSpan (zero export overhead).
    """

    @property
    def available(self) -> bool:
        """Whether the opentelemetry-api is available."""
        return _OTEL_AVAILABLE

    def emit(self, event: AuditEvent) -> None:
        """Create an OTel span from an AuditEvent.

        Attributes conform to GenAI semantic conventions (experimental)
        plus CloneGuard-specific namespace. Never includes raw tool_input
        content (T-03-12). Never calls force_flush (T-03-14).
        """
        if not _OTEL_AVAILABLE or _tracer is None:
            return

        try:
            with _tracer.start_as_current_span(
                name=f"cloneguard.scan {event.tool_name}",
                attributes={
                    "gen_ai.system": event.agent_type,
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": event.tool_name,
                    "cloneguard.verdict": event.verdict,
                    "cloneguard.confidence": event.confidence,
                    "cloneguard.enforcement_action": event.enforcement_action,
                    "cloneguard.sandbox_adapter": event.sandbox_adapter,
                    "cloneguard.source_path": event.source_path,
                    "cloneguard.schema_version": event.schema_version,
                },
            ):
                pass  # Span auto-ends when context manager exits
        except Exception:
            # OTel failures must never break hook responses
            logger.debug("OTel span emission failed", exc_info=True)
