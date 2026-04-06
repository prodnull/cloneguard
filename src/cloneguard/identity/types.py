"""Agent identity types for audit attribution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentIdentity:
    """SPIFFE-based agent identity for audit attribution (GOVN-06).

    When available=True, spiffe_id contains the SPIFFE URI
    (e.g., "spiffe://example.org/agent/claude-code-01").
    When available=False, spiffe_id="" and trust_domain="" --
    identity is unknown but never an error.
    """

    spiffe_id: str = ""
    trust_domain: str = ""
    available: bool = False
