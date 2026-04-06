"""NDJSON emitter for audit events.

Writes AuditEvent instances as newline-delimited JSON to a file handle
(defaults to stderr). SIEM connectors consume this output asynchronously --
the emitter itself is synchronous but lightweight (<1ms per event).
"""

from __future__ import annotations

import logging
import os
import sys
from typing import TextIO

from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)


class NDJSONEmitter:
    """Emit AuditEvents as NDJSON to a file handle.

    Default output is stderr (captured by agent log infrastructure).
    Override via CLONEGUARD_AUDIT_LOG env var to write to a file path.
    """

    def __init__(self, output: TextIO | None = None) -> None:
        self._output = output or sys.stderr

    def emit(self, event: AuditEvent) -> None:
        """Write a single AuditEvent as one NDJSON line. Never raises."""
        try:
            self._output.write(event.to_ndjson())
            self._output.flush()
        except Exception:
            logger.debug("Failed to emit audit event", exc_info=True)

    @classmethod
    def from_env(cls) -> NDJSONEmitter:
        """Create emitter from CLONEGUARD_AUDIT_LOG env var, or default to stderr."""
        log_path = os.environ.get("CLONEGUARD_AUDIT_LOG")
        if log_path:
            try:
                fh = open(log_path, "a")  # noqa: SIM115
                return cls(output=fh)
            except OSError:
                logger.warning("Cannot open audit log %s, falling back to stderr", log_path)
        return cls()
