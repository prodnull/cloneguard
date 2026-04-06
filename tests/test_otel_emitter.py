"""Tests for OTel span emitter.

Validates OTelEmitter zero-cost no-op when opentelemetry-api is absent,
correct span attributes when available, T-03-12 info disclosure prevention,
and resilience to tracer exceptions.
"""

from __future__ import annotations

import datetime
from typing import Any
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Import guard tests (no-op when opentelemetry-api absent)
# ---------------------------------------------------------------------------


def test_import_succeeds_without_otel() -> None:
    """Module imports even when opentelemetry-api is not installed."""
    # The module should always be importable -- it guards the import internally
    from cloneguard.audit.otel import OTelEmitter

    assert OTelEmitter is not None


def test_constructor_does_not_raise_when_otel_unavailable() -> None:
    """OTelEmitter() succeeds even when _OTEL_AVAILABLE is False."""
    from cloneguard.audit import otel as otel_mod

    original = otel_mod._OTEL_AVAILABLE
    try:
        otel_mod._OTEL_AVAILABLE = False
        otel_mod._tracer = None
        emitter = otel_mod.OTelEmitter()
        assert emitter is not None
    finally:
        otel_mod._OTEL_AVAILABLE = original


def test_available_returns_false_when_otel_absent() -> None:
    """OTelEmitter.available returns False when _OTEL_AVAILABLE is False."""
    from cloneguard.audit import otel as otel_mod

    original = otel_mod._OTEL_AVAILABLE
    try:
        otel_mod._OTEL_AVAILABLE = False
        emitter = otel_mod.OTelEmitter()
        assert emitter.available is False
    finally:
        otel_mod._OTEL_AVAILABLE = original


def test_emit_noop_when_otel_unavailable() -> None:
    """emit() is a no-op (no error) when _OTEL_AVAILABLE is False."""
    from cloneguard.audit import otel as otel_mod
    from cloneguard.audit.types import AuditEvent, EventType

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = False
        otel_mod._tracer = None
        emitter = otel_mod.OTelEmitter()
        event = AuditEvent(
            session_id="test-session",
            event_type=EventType.SCAN_COMPLETE,
            tool_name="test-tool",
            tool_input_hash="abc123",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        # Should not raise
        emitter.emit(event)
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


# ---------------------------------------------------------------------------
# Span attribute tests (with mocked tracer)
# ---------------------------------------------------------------------------


def _make_audit_event() -> Any:
    """Create a test AuditEvent with all required fields."""
    from cloneguard.audit.types import AuditEvent, EventType

    return AuditEvent(
        session_id="sess-42",
        agent_type="claude-code",
        event_type=EventType.RISK_IDENTIFIED,
        tool_name="Bash",
        tool_input_hash="deadbeef",
        verdict="detected",
        confidence=0.95,
        enforcement_action="BLOCK",
        sandbox_adapter="landlock",
        source_path="src/main.py",
        schema_version="cloneguard/event/v1",
        cloneguard_version="0.5.0",
    )


def test_emit_creates_span_with_correct_name() -> None:
    """emit() creates a span named 'cloneguard.scan {tool_name}'."""
    from cloneguard.audit import otel as otel_mod

    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__ = lambda s: mock_span
    mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()
        event = _make_audit_event()
        emitter.emit(event)

        mock_tracer.start_as_current_span.assert_called_once()
        call_kwargs = mock_tracer.start_as_current_span.call_args
        assert call_kwargs[1]["name"] == "cloneguard.scan Bash"
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


def test_emit_span_has_genai_attributes() -> None:
    """Span attributes include gen_ai.system, gen_ai.operation.name, gen_ai.tool.name."""
    from cloneguard.audit import otel as otel_mod

    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__ = lambda s: mock_span
    mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()
        emitter.emit(_make_audit_event())

        attrs = mock_tracer.start_as_current_span.call_args[1]["attributes"]
        assert attrs["gen_ai.system"] == "claude-code"
        assert attrs["gen_ai.operation.name"] == "execute_tool"
        assert attrs["gen_ai.tool.name"] == "Bash"
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


def test_emit_span_has_cloneguard_attributes() -> None:
    """Span has cloneguard.verdict, confidence, enforcement_action, etc."""
    from cloneguard.audit import otel as otel_mod

    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__ = lambda s: mock_span
    mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()
        emitter.emit(_make_audit_event())

        attrs = mock_tracer.start_as_current_span.call_args[1]["attributes"]
        assert attrs["cloneguard.verdict"] == "detected"
        assert attrs["cloneguard.confidence"] == 0.95
        assert attrs["cloneguard.enforcement_action"] == "BLOCK"
        assert attrs["cloneguard.sandbox_adapter"] == "landlock"
        assert attrs["cloneguard.source_path"] == "src/main.py"
        assert attrs["cloneguard.schema_version"] == "cloneguard/event/v1"
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


# ---------------------------------------------------------------------------
# T-03-12: No raw content in span attributes
# ---------------------------------------------------------------------------


def test_span_does_not_include_tool_call_arguments() -> None:
    """Span attributes do NOT include gen_ai.tool.call.arguments (T-03-12)."""
    from cloneguard.audit import otel as otel_mod

    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__ = lambda s: mock_span
    mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()
        emitter.emit(_make_audit_event())

        attrs = mock_tracer.start_as_current_span.call_args[1]["attributes"]
        assert "gen_ai.tool.call.arguments" not in attrs
        assert "tool_input" not in attrs
        assert "tool_input_hash" not in attrs
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


# ---------------------------------------------------------------------------
# Pitfall 3: No force_flush
# ---------------------------------------------------------------------------


def test_emit_does_not_call_force_flush() -> None:
    """emit() never calls force_flush() on tracer provider (Pitfall 3)."""
    import ast
    import inspect
    import textwrap

    from cloneguard.audit.otel import OTelEmitter

    source = inspect.getsource(OTelEmitter)
    tree = ast.parse(textwrap.dedent(source))
    # Walk AST for any function call to force_flush
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            assert name != "force_flush", "force_flush() must not be called"


# ---------------------------------------------------------------------------
# Exception resilience
# ---------------------------------------------------------------------------


def test_emit_does_not_crash_on_tracer_exception() -> None:
    """emit() catches exceptions from tracer (never breaks hook responses)."""
    from cloneguard.audit import otel as otel_mod

    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.side_effect = RuntimeError("tracer exploded")

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()
        # Should not raise
        emitter.emit(_make_audit_event())
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer


# ---------------------------------------------------------------------------
# Pipeline consistency
# ---------------------------------------------------------------------------


def test_otel_emitter_has_emit_method_compatible_with_ndjson() -> None:
    """OTelEmitter follows same emit(event) signature as NDJSONEmitter."""
    import inspect

    from cloneguard.audit.ndjson import NDJSONEmitter
    from cloneguard.audit.otel import OTelEmitter

    ndjson_sig = inspect.signature(NDJSONEmitter.emit)
    otel_sig = inspect.signature(OTelEmitter.emit)

    # Both should accept (self, event) -- same positional parameter count
    ndjson_params = [p for p in ndjson_sig.parameters if p != "self"]
    otel_params = [p for p in otel_sig.parameters if p != "self"]
    assert len(ndjson_params) == len(otel_params)
    assert ndjson_params[0] == "event"
    assert otel_params[0] == "event"


def test_emit_with_real_audit_event() -> None:
    """emit() works with a fully constructed AuditEvent object."""
    from cloneguard.audit import otel as otel_mod
    from cloneguard.audit.types import AuditEvent, EventType, SignalDetails

    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__ = lambda s: mock_span
    mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

    original_avail = otel_mod._OTEL_AVAILABLE
    original_tracer = otel_mod._tracer
    try:
        otel_mod._OTEL_AVAILABLE = True
        otel_mod._tracer = mock_tracer
        emitter = otel_mod.OTelEmitter()

        event = AuditEvent(
            timestamp=datetime.datetime.now(datetime.UTC),
            session_id="real-session",
            agent_type="gemini-cli",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Write",
            tool_input_hash="sha256hex",
            verdict="suspicious",
            confidence=0.72,
            signals=SignalDetails(pattern_severity="medium", summary="test signal"),
            enforcement_action="CONSTRAIN",
            sandbox_adapter="seatbelt",
            source_path="/tmp/test.py",
            cloneguard_version="0.5.0",
        )
        emitter.emit(event)

        mock_tracer.start_as_current_span.assert_called_once()
        attrs = mock_tracer.start_as_current_span.call_args[1]["attributes"]
        assert attrs["gen_ai.system"] == "gemini-cli"
        assert attrs["cloneguard.verdict"] == "suspicious"
        assert attrs["cloneguard.confidence"] == 0.72
    finally:
        otel_mod._OTEL_AVAILABLE = original_avail
        otel_mod._tracer = original_tracer
