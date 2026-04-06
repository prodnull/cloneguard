"""Typed contracts for the CloneGuard enforcement engine.

Defines frozen dataclass data objects for the enforcement pipeline.
All data objects use @dataclass(frozen=True) for immutability (hot path).

Pydantic is NOT used here -- these are hot-path objects that must stay
lightweight. Pydantic validation lives only in cold-path config loaders.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Constraints:
    """Sandbox constraint specification for a tool call.

    Paths in filesystem_writable/readable may contain variable references
    (e.g., ${PROJECT_DIR}) that are expanded at evaluation time.
    """

    filesystem_writable: tuple[str, ...] = ()
    filesystem_readable: tuple[str, ...] = ()
    network_allow: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    """Output from the policy engine for a single detection result.

    action: "allow" (no constraints), "constrain" (sandbox tightened), "block" (deny execution)
    dry_run: True means the decision is logged but not enforced (safe default).
    matched_rule: Human-readable description of which policy rule matched.
    """

    action: str = "allow"  # "allow" | "constrain" | "block"
    constraints: Constraints = field(default_factory=Constraints)
    dry_run: bool = True
    matched_rule: str = ""
