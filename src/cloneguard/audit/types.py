"""Audit event types for structured SIEM-compatible event emission.

AuditEvent is the canonical event format emitted by CloneGuard hooks.
It serializes to NDJSON for downstream consumption by SIEM connectors
(Splunk HEC, Microsoft Sentinel, Chronicle UDM).

Uses Pydantic for validation and serialization (not on the hot detection path).
"""

from __future__ import annotations

import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    """Hook event types that trigger audit emission."""

    INSTRUCTIONS_LOADED = "instructions_loaded"
    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    SCAN = "scan"


class SignalDetails(BaseModel):
    """Detection signal breakdown for audit trail."""

    model_config = ConfigDict(frozen=True)

    tier0_matches: int = 0
    tier15_verdict: str = ""
    tier15_confidence: float = 0.0
    tier2_verdict: str = ""
    tier2_confidence: float = 0.0
    sequence_rule: str = ""


class AuditEvent(BaseModel):
    """Canonical audit event emitted by CloneGuard hooks.

    Frozen for immutability after construction. Serializes to NDJSON
    via to_ndjson() for SIEM connector consumption.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_version: str = "cloneguard/event/v1"
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    session_id: str
    agent_type: str = "claude-code"
    agent_identity: str = ""
    event_type: EventType
    tool_name: str
    tool_input_hash: str
    verdict: str
    confidence: float = 0.0
    signals: SignalDetails = Field(default_factory=SignalDetails)
    enforcement_action: str = "ALLOW"
    constraints_applied: dict[str, list[str]] = Field(default_factory=dict)
    would_apply: dict[str, list[str]] = Field(default_factory=dict)
    sandbox_adapter: str = "noop"
    outcome: str = "completed"
    policy_version: str = ""
    cloneguard_version: str
    source_path: str = ""

    def to_ndjson(self) -> str:
        """Serialize to newline-delimited JSON (one line per event)."""
        return self.model_dump_json(exclude_none=True) + "\n"
