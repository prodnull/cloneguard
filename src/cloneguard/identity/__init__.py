"""CloneGuard identity layer -- agent identity for zero-trust attribution (GOVN-06)."""

from cloneguard.identity.spiffe import get_agent_identity  # noqa: F401
from cloneguard.identity.types import AgentIdentity  # noqa: F401

__all__ = ["AgentIdentity", "get_agent_identity"]
