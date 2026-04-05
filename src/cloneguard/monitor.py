"""Backward-compatibility re-export. Actual implementation in detection/sequence.py."""

from cloneguard.detection.sequence import (  # noqa: F401
    _MAX_SESSIONS,
    EnforcementVerdict,
    MarkerEvent,
    SequenceAlert,
    SessionMarkers,
    ToolCallMonitor,
    ToolEvent,
    _extract_external_url,
    _is_build_command,
    _is_build_sensitive_target,
    _is_sensitive_file,
    _summarize_input,
    get_monitor,
)
