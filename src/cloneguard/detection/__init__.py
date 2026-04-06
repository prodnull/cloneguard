"""CloneGuard detection engine -- extracted from hooks.py/patterns.py/monitor.py."""

from cloneguard.detection.engine import DetectionEngine, get_detection_engine  # noqa: F401
from cloneguard.detection.fusion import (  # noqa: F401
    FusionLayer,
    FusionResult,
    WeightProfile,
    load_weight_profile,
)
from cloneguard.detection.types import (  # noqa: F401
    DetectionEngineProtocol,
    DetectionResult,
    SignalResult,
    ToolCallEvent,
)
