"""Structured audit event types for CloneGuard.

Pydantic v2 frozen models for the serialization/audit layer. These are NOT
used on the detection hot path -- detection uses lightweight frozen dataclasses
(see cloneguard.detection.types). Pydantic is lazy-imported only when audit
events are emitted, AFTER the detection decision and exit code are determined.

Schema: cloneguard/event/v1 (D-07)
Fields: per D-05 event schema design
Serialization: model_dump_json() for NDJSON (D-06)

Threat model:
    T-02-03: tool_input_hash is SHA-256, not raw tool_input content.
    T-02-04: Every event includes timestamp, session_id, cloneguard_version.
"""

from __future__ import annotations

import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    """Types of audit events emitted by CloneGuard."""

    RISK_IDENTIFIED = "RISK_IDENTIFIED"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    HOOK_INVOKED = "HOOK_INVOKED"


class SignalDetails(BaseModel):
    """Nested signal sub-object per D-05.

    Captures pattern, semantic, and sequence detection details in a single
    structured object for audit trail fidelity.
    """

    model_config = ConfigDict(frozen=True)

    pattern_matches: list[dict[str, str]] = Field(default_factory=list)
    pattern_severity: str = ""
    semantic_verdict: str = ""
    semantic_confidence: float = 0.0
    semantic_ood_distance: float = 0.0
    sequence_alerts: list[dict[str, str]] = Field(default_factory=list)
    summary: str = ""
    primary_rule_id: str = ""
    line_number: int = 0


class AuditEvent(BaseModel):
    """Structured audit event conforming to cloneguard/event/v1 schema (D-05).

    Frozen (immutable) Pydantic v2 model. Every detection event produces one
    AuditEvent capturing the full decision context for compliance and debugging.

    Threat mitigations:
        T-02-03: tool_input_hash stores SHA-256 digest, not raw content.
        T-02-04: timestamp + session_id + cloneguard_version for traceability.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    # Schema identification (D-07)
    schema_version: str = "cloneguard/event/v1"

    # Temporal and session context (T-02-04)
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    session_id: str

    # Agent and event context
    agent_type: str = "claude-code"
    event_type: EventType
    tool_name: str
    tool_input_hash: str  # SHA-256 digest (T-02-03: never raw content)

    # Detection outcome
    verdict: str  # "clean" | "suspicious" | "detected"
    confidence: float = 0.0
    signals: SignalDetails = Field(default_factory=SignalDetails)

    # Enforcement (Phase 1 default: ALLOW; Phase 2 adds CONSTRAIN/BLOCK)
    enforcement_action: str = "ALLOW"
    constraints_applied: dict[str, list[str]] = Field(default_factory=dict)

    # Runtime context
    sandbox_adapter: str = "noop"
    outcome: str = "completed"
    policy_version: str = ""
    cloneguard_version: str
    source_path: str = ""

    def to_ndjson(self) -> str:
        """Serialize to a single NDJSON line (D-06).

        Returns a valid JSON string terminated by a newline character.
        Uses Pydantic's Rust-backed serializer for performance.
        """
        return self.model_dump_json(exclude_none=True) + "\n"
