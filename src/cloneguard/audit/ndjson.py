"""NDJSON emitter for structured audit events.

Writes AuditEvent objects as newline-delimited JSON lines to a configurable
output stream. Default output is stderr -- NEVER stdout, which is the hook
communication channel (T-02-01).

Output destination priority:
    1. Explicit `output` parameter to constructor
    2. CLONEGUARD_NDJSON_OUTPUT env var (file path, append mode)
    3. sys.stderr (fallback)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TextIO

from cloneguard.audit.types import AuditEvent


class NDJSONEmitter:
    """Emit AuditEvent objects as NDJSON lines.

    Threat mitigations:
        T-02-01: Default output is stderr, never stdout.
        T-02-02: Emit failures are caught by the caller (hooks._emit_audit_event).
    """

    def __init__(self, output: TextIO | None = None) -> None:
        # Default: stderr (NEVER stdout -- stdout is hook communication channel)
        self._output: TextIO = output or sys.stderr
        self._owns_stream: bool = False

    def emit(self, event: AuditEvent) -> None:
        """Write a single NDJSON line to the output stream."""
        self._output.write(event.to_ndjson())

    def flush(self) -> None:
        """Flush the output stream."""
        self._output.flush()

    def close(self) -> None:
        """Close the output stream if we own it (opened from env var or file path)."""
        if self._owns_stream and self._output not in (sys.stdout, sys.stderr):
            self._output.close()

    @classmethod
    def from_env(cls) -> NDJSONEmitter:
        """Create emitter from CLONEGUARD_NDJSON_OUTPUT env var, or stderr.

        If the env var is set, opens the file in append mode. The emitter
        owns the file handle and caller should call close() when done.
        """
        env_path = os.environ.get("CLONEGUARD_NDJSON_OUTPUT")
        if env_path:
            path = Path(env_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = open(path, "a", encoding="utf-8")  # noqa: SIM115
            emitter = cls(output=handle)
            emitter._owns_stream = True
            return emitter
        return cls()  # Falls back to stderr

    @classmethod
    def to_file(cls, path: Path) -> NDJSONEmitter:
        """Create emitter writing to a specific file path (append mode)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(path, "a", encoding="utf-8")  # noqa: SIM115
        emitter = cls(output=handle)
        emitter._owns_stream = True
        return emitter
