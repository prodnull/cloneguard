"""CloneGuard enforcement layer -- adaptive constraint enforcement.

Maps detection verdicts to policy decisions and sandbox restrictions.
Phase 2: YAML policy engine + Landlock/Seatbelt/Noop adapters.
Phase 5: PolicyBackend Protocol + OPA/Cedar/YAML backends.
"""

from cloneguard.enforcement.adapter import (  # noqa: F401
    NoopAdapter,
    SandboxAdapter,
    get_sandbox_adapter,
)
from cloneguard.enforcement.backends import (  # noqa: F401
    PolicyBackend,
    get_policy_backend,
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
    "PolicyBackend",
    "PolicyConfig",
    "PolicyDecision",
    "SandboxAdapter",
    "YAMLPolicyEngine",
    "get_policy_backend",
    "get_policy_engine",
    "get_sandbox_adapter",
]
