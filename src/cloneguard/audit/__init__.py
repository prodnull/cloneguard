"""CloneGuard structured audit layer.

Provides Pydantic v2 frozen event models for structured audit logging (FNDN-02)
and NDJSON emission (D-06). This module is the serialization layer -- it is
lazy-imported AFTER detection decisions are made, never on the hot path
(see research Pitfall 6).

Public API:
    AuditEvent -- Structured audit event conforming to cloneguard/event/v1
    EventType -- Enum of event types
    SignalDetails -- Nested signal sub-object
    NDJSONEmitter -- NDJSON line emitter (file or stderr, never stdout)
    SARIFEmitter -- SARIF 2.1.0 output emitter (D-08, D-09, D-10)
    build_sarif -- Low-level SARIF document builder
"""

from cloneguard.audit.ndjson import NDJSONEmitter  # noqa: F401
from cloneguard.audit.otel import OTelEmitter  # noqa: F401
from cloneguard.audit.sarif import SARIFEmitter, build_sarif  # noqa: F401
from cloneguard.audit.types import AuditEvent, EventType, SignalDetails  # noqa: F401
