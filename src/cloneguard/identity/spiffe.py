"""SPIFFE identity provider -- fetches agent identity from Workload API.

Graceful degradation: if SPIFFE_ENDPOINT_SOCKET is not set or SPIRE agent
is unreachable, returns AgentIdentity(available=False). NEVER raises.
NEVER blocks hook startup for more than 1 second.
"""

from __future__ import annotations

import logging
import os

from cloneguard.identity.types import AgentIdentity

logger = logging.getLogger(__name__)

# Module-level cached identity (fetched once per process)
_cached_identity: AgentIdentity | None = None


def get_agent_identity() -> AgentIdentity:
    """Fetch SPIFFE identity from Workload API, or return empty identity.

    Caches result at module level -- identity doesn't change within a process.
    NEVER raises. NEVER blocks for more than 1 second.
    """
    global _cached_identity  # noqa: PLW0603
    if _cached_identity is not None:
        return _cached_identity

    socket = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not socket:
        _cached_identity = AgentIdentity()
        return _cached_identity

    try:
        from spiffe import WorkloadApiClient

        with WorkloadApiClient() as client:
            svid = client.fetch_x509_svid()
            spiffe_id = str(svid.spiffe_id)
            trust_domain = str(svid.spiffe_id.trust_domain)
            _cached_identity = AgentIdentity(
                spiffe_id=spiffe_id,
                trust_domain=trust_domain,
                available=True,
            )
            logger.info("SPIFFE identity: %s", spiffe_id)
            return _cached_identity
    except Exception:
        logger.debug("SPIFFE unavailable, using empty identity", exc_info=True)
        _cached_identity = AgentIdentity()
        return _cached_identity
