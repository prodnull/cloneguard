"""Tests for CloneGuard audit types and NDJSON emitter.

Tests cover:
- AuditEvent construction with all required fields (D-05)
- Immutability (frozen Pydantic model)
- NDJSON serialization with all required fields (D-06)
- Schema version default (D-07)
- Enforcement action default (Phase 1: ALLOW)
- NDJSONEmitter writes to configured stream, never stdout (T-02-01)
- NDJSONEmitter respects CLONEGUARD_NDJSON_OUTPUT env var
- SignalDetails nested sub-object serialization
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from pathlib import Path

import pytest

from cloneguard.audit import AuditEvent, EventType, NDJSONEmitter, SignalDetails

# ---------------------------------------------------------------------------
# Test 1: AuditEvent construction with all required fields
# ---------------------------------------------------------------------------


class TestAuditEventConstruction:
    def test_constructs_with_required_fields(self) -> None:
        """AuditEvent can be constructed with all required fields per D-05."""
        event = AuditEvent(
            session_id="test-session-1",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Bash",
            tool_input_hash="abc123def456",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        assert event.session_id == "test-session-1"
        assert event.event_type == EventType.HOOK_INVOKED
        assert event.tool_name == "Bash"
        assert event.tool_input_hash == "abc123def456"
        assert event.verdict == "clean"
        assert event.cloneguard_version == "0.5.0"

    # -----------------------------------------------------------------------
    # Test 2: Immutability
    # -----------------------------------------------------------------------

    def test_is_frozen_immutable(self) -> None:
        """AuditEvent is frozen (immutable) -- assigning to a field raises."""
        event = AuditEvent(
            session_id="test-frozen",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Bash",
            tool_input_hash="hash123",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        with pytest.raises(Exception):
            event.verdict = "detected"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 3 & 4: NDJSON serialization
# ---------------------------------------------------------------------------


class TestNDJSONSerialization:
    def test_to_ndjson_returns_single_line_json(self) -> None:
        """AuditEvent.to_ndjson() returns a valid single-line JSON string ending with newline."""
        event = AuditEvent(
            session_id="test-ndjson",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Read",
            tool_input_hash="deadbeef",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        ndjson = event.to_ndjson()
        assert ndjson.endswith("\n"), "NDJSON line must end with newline"
        assert "\n" not in ndjson.rstrip("\n"), "NDJSON must be single line"
        # Must be valid JSON
        parsed = json.loads(ndjson)
        assert isinstance(parsed, dict)

    def test_to_ndjson_contains_all_required_fields(self) -> None:
        """NDJSON output contains all required fields per D-05."""
        event = AuditEvent(
            session_id="test-fields",
            event_type=EventType.RISK_IDENTIFIED,
            tool_name="Write",
            tool_input_hash="cafebabe",
            verdict="detected",
            confidence=0.95,
            cloneguard_version="0.5.0",
        )
        parsed = json.loads(event.to_ndjson())
        required_keys = [
            "schema_version",
            "timestamp",
            "session_id",
            "verdict",
            "confidence",
            "signals",
            "enforcement_action",
        ]
        for key in required_keys:
            assert key in parsed, f"Required field {key!r} missing from NDJSON output"


# ---------------------------------------------------------------------------
# Test 5: Schema version default (D-07)
# ---------------------------------------------------------------------------


class TestSchemaVersion:
    def test_schema_version_defaults_to_v1(self) -> None:
        """Schema version defaults to 'cloneguard/event/v1' per D-07."""
        event = AuditEvent(
            session_id="test-schema",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Bash",
            tool_input_hash="abc",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        assert event.schema_version == "cloneguard/event/v1"


# ---------------------------------------------------------------------------
# Test 6: Enforcement action default (Phase 1)
# ---------------------------------------------------------------------------


class TestEnforcementDefault:
    def test_enforcement_action_defaults_to_allow(self) -> None:
        """Phase 1: enforcement_action defaults to 'ALLOW'."""
        event = AuditEvent(
            session_id="test-enforce",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Bash",
            tool_input_hash="abc",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        assert event.enforcement_action == "ALLOW"


# ---------------------------------------------------------------------------
# Test 7: NDJSONEmitter writes to configured stream (not stdout)
# ---------------------------------------------------------------------------


class TestNDJSONEmitter:
    def test_emitter_writes_to_configured_stream(self) -> None:
        """NDJSONEmitter.emit() writes to configured output stream (not stdout)."""
        buf = io.StringIO()
        emitter = NDJSONEmitter(output=buf)
        event = AuditEvent(
            session_id="test-emit",
            event_type=EventType.HOOK_INVOKED,
            tool_name="Bash",
            tool_input_hash="abc",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        emitter.emit(event)
        written = buf.getvalue()
        assert written.endswith("\n")
        parsed = json.loads(written)
        assert parsed["session_id"] == "test-emit"

    # -----------------------------------------------------------------------
    # Test 8: CLONEGUARD_NDJSON_OUTPUT env var
    # -----------------------------------------------------------------------

    def test_emitter_respects_env_var_for_file_output(self) -> None:
        """NDJSONEmitter respects CLONEGUARD_NDJSON_OUTPUT env var for file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            outfile = Path(tmpdir) / "audit.ndjson"
            os.environ["CLONEGUARD_NDJSON_OUTPUT"] = str(outfile)
            try:
                emitter = NDJSONEmitter.from_env()
                event = AuditEvent(
                    session_id="test-envvar",
                    event_type=EventType.SCAN_COMPLETE,
                    tool_name="Bash",
                    tool_input_hash="xyz",
                    verdict="clean",
                    cloneguard_version="0.5.0",
                )
                emitter.emit(event)
                emitter.flush()

                content = outfile.read_text()
                parsed = json.loads(content.strip())
                assert parsed["session_id"] == "test-envvar"
            finally:
                del os.environ["CLONEGUARD_NDJSON_OUTPUT"]
                emitter.close()


# ---------------------------------------------------------------------------
# Test 9: SignalDetails serialization
# ---------------------------------------------------------------------------


class TestSignalDetailsSerialization:
    def test_signal_details_serializes_nested_data(self) -> None:
        """SignalDetails sub-object serializes nested pattern/semantic/sequence data."""
        signals = SignalDetails(
            pattern_matches=[{"rule_id": "RH-001", "matched": "ignore previous"}],
            pattern_severity="critical",
            semantic_verdict="MALICIOUS",
            semantic_confidence=0.95,
            semantic_ood_distance=2.5,
            sequence_alerts=[{"rule_id": "SEQ-001", "type": "exfil"}],
            summary="Pattern + semantic detection",
            primary_rule_id="RH-001",
            line_number=42,
        )
        event = AuditEvent(
            session_id="test-signals",
            event_type=EventType.RISK_IDENTIFIED,
            tool_name="Write",
            tool_input_hash="abc",
            verdict="detected",
            confidence=0.95,
            signals=signals,
            cloneguard_version="0.5.0",
        )
        parsed = json.loads(event.to_ndjson())
        sig = parsed["signals"]
        assert sig["pattern_matches"] == [{"rule_id": "RH-001", "matched": "ignore previous"}]
        assert sig["semantic_confidence"] == 0.95
        assert sig["sequence_alerts"] == [{"rule_id": "SEQ-001", "type": "exfil"}]
        assert sig["primary_rule_id"] == "RH-001"
        assert sig["line_number"] == 42
