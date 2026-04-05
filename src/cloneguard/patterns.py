"""Backward-compatibility re-export. Actual implementation in detection/patterns.py."""

from cloneguard.detection.patterns import (  # noqa: F401
    _LENIENT_SEGMENTS,
    _STRICT_BASENAMES,
    _STRICT_PATH_PATTERNS,
    PatternEngine,
    PatternMatch,
    ScanMode,
    ScanResult,
    Severity,
    Verdict,
    _CompiledRule,
)
