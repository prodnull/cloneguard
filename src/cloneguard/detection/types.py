"""Typed contracts for the CloneGuard detection engine.

Defines Protocol interfaces (PEP 544 structural subtyping) and frozen
dataclass data objects for the detection pipeline. All data objects on
the hot path use @dataclass(frozen=True) for immutability and hashability
(never Pydantic -- see research Pitfall 6).

Threat model T-01-01: frozen dataclasses prevent mutation after construction.
Threat model T-01-03: raw_data must never be logged verbatim -- only hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ToolCallEvent:
    """Normalized input to the detection engine.

    Encapsulates a single hook event with all context needed for detection.
    Frozen to prevent mutation after construction (T-01-01).
    """

    event_type: str  # "InstructionsLoaded" | "PreToolUse" | "PostToolUse"
    tool_name: str
    tool_input: dict[str, Any]
    content: str  # The text to scan
    source_path: str = ""
    scan_mode_hint: str = ""  # "strict" | "standard" | "lenient" or "" for auto-detect
    session_id: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)  # Original hook JSON for shim compat


@dataclass(frozen=True)
class SignalResult:
    """Individual signal output (pattern, semantic, or sequence).

    Each detection tier produces a SignalResult that feeds into the
    composite DetectionResult.
    """

    signal_type: str  # "pattern" | "semantic" | "sequence"
    verdict: str  # "clean" | "suspicious" | "detected"
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionResult:
    """Output from DetectionEngine.scan().

    Composite result aggregating signals from pattern, semantic, and
    sequence detection tiers. exit_code maps directly to hook protocol
    (0=allow, 2=block).
    """

    verdict: str  # "clean" | "suspicious" | "detected"
    confidence: float
    signals: list[SignalResult] = field(default_factory=list)
    exit_code: int = 0  # Hook exit code: 0 (allow) or 2 (block)
    message: str = ""  # Human-readable output for hook response
    severity: str = ""  # "critical" | "high" | "medium" | "low" | ""
    primary_rule_id: str = ""
    matched_text: str = ""
    source_path: str = ""
    line_number: int = 0


@runtime_checkable
class DetectionEngineProtocol(Protocol):
    """Protocol for detection engine -- structural subtyping per D-04.

    Any class implementing scan(ToolCallEvent) -> DetectionResult satisfies
    this protocol without explicit inheritance.
    """

    def scan(self, event: ToolCallEvent) -> DetectionResult: ...
