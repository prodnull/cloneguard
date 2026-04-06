"""CloneGuard enforcement layer -- adaptive constraint enforcement.

Maps detection verdicts to policy decisions and sandbox restrictions.
Phase 2: YAML policy engine + Landlock/Seatbelt/Noop adapters.
"""

from cloneguard.enforcement.types import (  # noqa: F401
    Constraints,
    EnforcementOutcome,
    PolicyDecision,
)

__all__ = [
    "Constraints",
    "EnforcementOutcome",
    "PolicyDecision",
]
