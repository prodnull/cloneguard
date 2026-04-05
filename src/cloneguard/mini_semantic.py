"""Backward-compatibility re-export. Actual implementation in detection/semantic.py."""

from cloneguard.detection.semantic import (  # noqa: F401
    _DEFAULT_THRESHOLDS,
    _MAX_CHUNKS,
    _MIN_MAHALANOBIS_CHARS,
    _REVIEW_LOG_PATH,
    _REVIEW_THRESHOLD,
    _STRIDE,
    _WINDOW_SIZE,
    MiniClassification,
    MiniSemanticClassifier,
    _get_thresholds,
)
