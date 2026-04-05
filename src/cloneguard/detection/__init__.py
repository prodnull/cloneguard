"""CloneGuard detection engine -- extracted from hooks.py/patterns.py/monitor.py."""

from cloneguard.detection.engine import DetectionEngine, get_detection_engine  # noqa: F401
from cloneguard.detection.types import (  # noqa: F401
    DetectionEngineProtocol,
    DetectionResult,
    SignalResult,
    ToolCallEvent,
)
