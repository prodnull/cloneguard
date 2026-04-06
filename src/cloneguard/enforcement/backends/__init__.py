"""Policy backend Protocol and factory for multi-language policy compilation.

Defines the PolicyBackend Protocol (PEP 544 structural subtyping) and a factory
function that returns the appropriate backend for a given policy language name.

All backends compile their native policy language into a PolicyConfig object --
the canonical intermediate representation. The YAMLPolicyEngine then evaluates
against this PolicyConfig at runtime. OPA/Cedar are DATA sources for configuration
values (cold path), not runtime evaluators (hot path). See D-01 and D-02.

Supported backends:
  - "yaml": Direct YAML -> PolicyConfig (thin wrapper around PolicyConfig.from_yaml)
  - "opa": Rego module -> PolicyConfig via regopy (optional: pip install cloneguard[opa])
  - "cedar": Cedar-wrapped YAML -> PolicyConfig via cedarpy
    (optional: pip install cloneguard[cedar])
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from cloneguard.enforcement.policy import PolicyConfig

logger = logging.getLogger(__name__)


@runtime_checkable
class PolicyBackend(Protocol):
    """Protocol for policy backends that compile to PolicyConfig IR.

    Each backend translates a policy language (YAML, Rego, Cedar) into
    a PolicyConfig Pydantic model. The YAMLPolicyEngine then evaluates
    against this PolicyConfig to produce PolicyDecision objects.
    """

    @property
    def name(self) -> str:
        """Backend name for logging and audit."""
        ...

    def compile(self, source: str) -> PolicyConfig:
        """Parse native policy language and compile to PolicyConfig.

        Raises ValueError on parse or validation failure.
        """
        ...

    def validate(self, source: str) -> list[str]:
        """Validate policy syntax without side effects.

        Returns list of error messages (empty list means valid).
        """
        ...


def get_policy_backend(name: str) -> PolicyBackend:
    """Return a PolicyBackend instance by name.

    Lazy-imports optional backends to avoid requiring regopy/cedarpy
    unless the operator explicitly selects that backend.

    Args:
        name: Backend name ("yaml", "opa", or "cedar").

    Returns:
        PolicyBackend implementation for the requested language.

    Raises:
        ValueError: If the backend name is unknown.
        ImportError: If the required optional dependency is not installed.
    """
    if name == "yaml":
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        return YAMLPolicyBackend()

    if name == "opa":
        try:
            from cloneguard.enforcement.backends.opa import OPAPolicyBackend
        except ImportError:
            msg = (
                "regopy not installed. Install with: pip install 'cloneguard[opa]' "
                "or pip install regopy"
            )
            raise ImportError(msg) from None
        return OPAPolicyBackend()

    if name == "cedar":
        try:
            from cloneguard.enforcement.backends.cedar import CedarPolicyBackend
        except ImportError:
            msg = (
                "cedarpy not installed. Install with: pip install 'cloneguard[cedar]' "
                "or pip install cedarpy"
            )
            raise ImportError(msg) from None
        return CedarPolicyBackend()

    msg = f"Unknown policy backend: {name}"
    raise ValueError(msg)


__all__ = ["PolicyBackend", "get_policy_backend"]
