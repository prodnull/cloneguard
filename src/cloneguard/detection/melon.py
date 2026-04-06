"""MELON selective re-execution for ambiguous confidence zone.

Adapted from the ICML 2025 paper (arXiv:2502.05174) for CloneGuard's hook
architecture. MELON fires post-fusion when confidence falls in the ambiguous
zone (default 0.4-0.6), masks content sections suspected of injection,
re-classifies through the semantic classifier, and compares CLS embeddings
to detect divergence indicating injected content.

Design rationale: ambiguous-confidence detections are where false positives
and false negatives cluster. MELON provides a second opinion by testing
whether removing suspected-injected sections changes the classification.
If it does, the removed section was driving the ambiguous signal and is
likely malicious.

Circuit breaker (D-12): disables MELON for the session when trigger rate
exceeds 15% in a sliding window of 20 calls. Once tripped, stays tripped
(irreversible within session). Prevents denial-of-service via trigger
flooding.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

try:
    import numpy as np

    _HAS_NUMPY = True
except ImportError:  # pragma: no cover
    _HAS_NUMPY = False

# Heuristic patterns for instruction-override masking.
# Conceptually derived from instruction_override.yaml patterns but
# implemented as simple regexes -- not imported from PatternEngine.
_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions?"),
    re.compile(r"(?i)you\s+are\s+now\b"),
    re.compile(r"(?i)^system\s*:", re.MULTILINE),
    re.compile(r"(?i)disregard\s+(?:all\s+)?(?:prior|above|previous)\b"),
    re.compile(r"(?i)override\s+(?:all\s+)?(?:rules?|instructions?|constraints?)\b"),
    re.compile(r"(?i)new\s+instructions?\s*:"),
    re.compile(r"(?i)forget\s+(?:all\s+)?(?:prior|previous|above)\b"),
    re.compile(r"(?i)^\[system\]", re.MULTILINE),
]


@dataclass(frozen=True)
class MELONResult:
    """Immutable result from MELONDetector.detect().

    Captures whether MELON fired, the embedding divergence score,
    whether the verdict was upgraded, and circuit breaker state.
    """

    triggered: bool
    divergence_score: float
    verdict_upgraded: bool
    original_verdict: str
    circuit_breaker_tripped: bool
    masked_sections: int


class CircuitBreaker:
    """Sliding-window circuit breaker for MELON trigger rate limiting.

    Trips when trigger rate exceeds max_rate (strict greater-than) in a
    sliding window. Once tripped, stays tripped for the session (irreversible).
    Uses collections.deque(maxlen=window_size) for sliding window.
    """

    def __init__(self, window_size: int = 20, max_rate: float = 0.15) -> None:
        self._window: deque[bool] = deque(maxlen=window_size)
        self._tripped: bool = False
        self._window_size = window_size
        self._max_rate = max_rate

    @property
    def is_tripped(self) -> bool:
        """Whether the circuit breaker has tripped (irreversible within session)."""
        return self._tripped

    def record(self, triggered: bool) -> None:
        """Record a trigger event in the sliding window.

        Checks rate only when window is full. Trips if rate > max_rate
        (strict greater-than, not >=).
        """
        self._window.append(triggered)
        if self._tripped:
            return
        if len(self._window) < self._window_size:
            return
        rate = sum(1 for t in self._window if t) / len(self._window)
        if rate > self._max_rate:
            self._tripped = True
            logger.warning(
                "MELON circuit breaker tripped: %.1f%% trigger rate exceeds %.1f%% threshold",
                rate * 100,
                self._max_rate * 100,
            )


def mask_content(
    content: str,
    suspicious_spans: list[tuple[int, int]] | None = None,
) -> str:
    """Mask content sections suspected of containing injected instructions.

    If suspicious_spans provided (from pattern match positions), masks those
    specific byte ranges. Otherwise, uses heuristic masking based on
    instruction-override patterns.

    Returns masked content with removed sections replaced by '[MASKED]'.
    """
    if suspicious_spans:
        # Mask specific byte ranges (process in reverse to preserve offsets)
        result = content
        for start, end in sorted(suspicious_spans, reverse=True):
            result = result[:start] + "[MASKED]" + result[end:]
        return result

    # Heuristic masking: remove lines matching instruction-override patterns
    lines = content.split("\n")
    masked_count = 0
    result_lines: list[str] = []
    for line in lines:
        masked = False
        for pattern in _INSTRUCTION_PATTERNS:
            if pattern.search(line):
                result_lines.append("[MASKED]")
                masked_count += 1
                masked = True
                break
        if not masked:
            result_lines.append(line)

    return "\n".join(result_lines)


def cosine_similarity(a: Any, b: Any) -> float:
    """Compute cosine similarity between two vectors.

    Returns 0.0 for zero-vector edge case (avoids division by zero / NaN).
    """
    if not _HAS_NUMPY:
        return 0.0

    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def extract_cls_embedding(classifier: Any, content: str) -> Any:
    """Extract CLS embedding via MiniSemanticClassifier's public API.

    Delegates to classifier.get_cls_embedding() when available,
    falling back to direct attribute access for backward compatibility.

    Returns 384-dim numpy array, or None if extraction fails.
    """
    if not _HAS_NUMPY or classifier is None:
        return None
    try:
        # Prefer public API (Phase 4 gap closure)
        if hasattr(classifier, "get_cls_embedding"):
            return classifier.get_cls_embedding(content)
        # Fallback: direct attribute access (pre-Phase-4 classifiers)
        inputs = classifier._tokenizer(
            content,
            return_tensors="np",
            truncation=True,
            max_length=256,
            padding="max_length",
        )
        outputs = classifier._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )
        if len(outputs) > 1:
            return outputs[1][0]
        return None
    except Exception:
        logger.debug("MELON: failed to extract CLS embedding", exc_info=True)
        return None


class MELONDetector:
    """Selective re-execution detector for ambiguous confidence zone.

    Fires post-fusion when confidence falls in [ambiguous_low, ambiguous_high].
    Masks content, extracts CLS embeddings for original and masked versions,
    compares via cosine similarity. High divergence indicates the masked
    section was driving the ambiguous signal -- likely malicious.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.8,
        ambiguous_low: float = 0.4,
        ambiguous_high: float = 0.6,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._similarity_threshold = similarity_threshold
        self._ambiguous_low = ambiguous_low
        self._ambiguous_high = ambiguous_high
        self._circuit_breaker = circuit_breaker or CircuitBreaker()

    def should_trigger(self, fusion_confidence: float) -> bool:
        """Check if MELON should fire for this confidence level.

        Returns True if confidence is in ambiguous zone AND circuit breaker
        not tripped. High-confidence verdicts skip MELON entirely with
        zero added latency.
        """
        if self._circuit_breaker.is_tripped:
            return False
        return self._ambiguous_low <= fusion_confidence <= self._ambiguous_high

    def detect(
        self,
        content: str,
        classifier: Any,
        suspicious_spans: list[tuple[int, int]] | None = None,
    ) -> MELONResult:
        """Run MELON selective re-execution.

        1. Mask content using mask_content()
        2. Extract CLS embeddings for original and masked content
        3. Compute cosine similarity -> divergence_score = 1.0 - similarity
        4. If divergence exceeds threshold -> upgrade verdict

        Returns MELONResult with divergence_score and upgrade decision.
        """
        masked = mask_content(content, suspicious_spans)
        masked_section_count = masked.count("[MASKED]")

        # Extract embeddings
        original_emb = extract_cls_embedding(classifier, content)
        masked_emb = extract_cls_embedding(classifier, masked)

        if original_emb is None or masked_emb is None:
            # Graceful degradation: no ONNX or extraction failed
            logger.debug("MELON: CLS embedding extraction failed, returning no-op result")
            self._circuit_breaker.record(True)
            return MELONResult(
                triggered=True,
                divergence_score=0.0,
                verdict_upgraded=False,
                original_verdict="",
                circuit_breaker_tripped=self._circuit_breaker.is_tripped,
                masked_sections=masked_section_count,
            )

        similarity = cosine_similarity(original_emb, masked_emb)
        divergence_score = 1.0 - similarity

        # Divergence exceeds threshold when score > (1.0 - similarity_threshold)
        verdict_upgraded = divergence_score > (1.0 - self._similarity_threshold)

        self._circuit_breaker.record(True)

        if verdict_upgraded:
            logger.info(
                "MELON: verdict upgraded (divergence=%.3f, threshold=%.3f)",
                divergence_score,
                1.0 - self._similarity_threshold,
            )

        return MELONResult(
            triggered=True,
            divergence_score=divergence_score,
            verdict_upgraded=verdict_upgraded,
            original_verdict="",
            circuit_breaker_tripped=self._circuit_breaker.is_tripped,
            masked_sections=masked_section_count,
        )
