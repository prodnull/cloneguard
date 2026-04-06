"""Enforcement type contracts -- frozen dataclasses on the hot path.

PolicyDecision, Constraints, and EnforcementOutcome are the core data objects
flowing through the enforcement pipeline: DetectionResult -> PolicyEngine.evaluate()
-> PolicyDecision -> SandboxAdapter.apply() -> EnforcementOutcome -> AuditEvent.

All types frozen for immutability (T-01-01 pattern from detection types).
Never Pydantic on the hot path (Pitfall 6).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Constraints:
    """Filesystem and network restrictions for sandbox enforcement.

    Uses tuples (not lists) for immutable sequences in frozen dataclass.
    """

    filesystem_writable: tuple[str, ...] = ()
    filesystem_readable: tuple[str, ...] = ()
    network_allow: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    """Output from PolicyEngine.evaluate() -- maps verdict to enforcement action.

    action: "allow" | "constrain" | "block"
    constraints: filesystem/network restrictions (only meaningful when action="constrain")
    dry_run: if True, log constraints but don't enforce (D-13 default)
    matched_rule: which policy section triggered this decision
    """

    action: str = "allow"
    constraints: Constraints = field(default_factory=Constraints)
    dry_run: bool = True
    matched_rule: str = ""


@dataclass(frozen=True)
class EnforcementOutcome:
    """Result of applying enforcement via a sandbox adapter.

    Records what adapter was used, what action was taken, and what
    constraints were actually applied (may differ from PolicyDecision
    if adapter doesn't support all constraint types).
    """

    adapter_name: str = "noop"
    action_taken: str = "allow"
    constraints_applied: Constraints = field(default_factory=Constraints)
    dry_run: bool = True
