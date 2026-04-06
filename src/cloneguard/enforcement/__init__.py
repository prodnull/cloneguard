"""CloneGuard enforcement layer -- adaptive constraint enforcement.

Maps detection verdicts to policy decisions and sandbox restrictions.
Phase 2: YAML policy engine + Landlock/Seatbelt/Noop adapters.
"""

from cloneguard.enforcement.adapter import (  # noqa: F401
    NoopAdapter,
    SandboxAdapter,
    get_sandbox_adapter,
)
from cloneguard.enforcement.policy import (  # noqa: F401
    PolicyConfig,
    YAMLPolicyEngine,
    get_policy_engine,
)
from cloneguard.enforcement.types import (  # noqa: F401
    Constraints,
    EnforcementOutcome,
    PolicyDecision,
)

__all__ = [
    "Constraints",
    "EnforcementOutcome",
    "NoopAdapter",
    "PolicyConfig",
    "PolicyDecision",
    "SandboxAdapter",
    "YAMLPolicyEngine",
    "get_policy_engine",
    "get_sandbox_adapter",
]
