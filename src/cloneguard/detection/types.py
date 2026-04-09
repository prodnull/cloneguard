"""Shared types for the detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SignalResult:
    """Result from a single detection signal (pattern, semantic, behavioral, registry)."""

    signal_type: str
    verdict: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)
