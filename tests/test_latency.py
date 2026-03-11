"""Test stubs for HARD-05: latency gate verification.

Validates that Tier 1.5 + Mahalanobis inference latency stays under 25ms p95
on the local CPU. Uses MiniSemanticClassifier directly with perf_counter.

Also validates the v4 ONNX model output shapes.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

ONNX_MODEL = Path("src/cloneguard/model/mini_semantic.onnx")
MAHALANOBIS_PARAMS = Path("src/cloneguard/model/mahalanobis_params.npz")

# Warmup and measurement configuration.
_N_WARMUP = 5
_N_MEASURE = 50
# CI runners have unpredictable latency (shared vCPUs, cold caches).
# macOS CI runners are especially slow (~100ms+ vs ~16ms local M-series).
# This is a hardware performance gate — only meaningful on known hardware.
_P95_LIMIT_MS = 25.0
_SKIP_ON_CI = bool(os.environ.get("CI"))

_TEST_TEXT = (
    "This is a test prompt for latency measurement. "
    "It contains enough tokens to exercise the full tokenization and inference pipeline "
    "without triggering the sliding window path, which would inflate latency unfairly."
)


@pytest.fixture(scope="module")
def classifier():
    """Load MiniSemanticClassifier once for all latency tests."""
    if not ONNX_MODEL.exists():
        pytest.skip("ONNX model not found — run scripts/fetch_model.py first")
    from cloneguard.mini_semantic import MiniSemanticClassifier

    c = MiniSemanticClassifier()
    if not c.available:
        pytest.skip("MiniSemanticClassifier not available")
    return c


class TestTier15MahalanobisLatency:
    """HARD-05: end-to-end Tier 1.5 + Mahalanobis latency < 25ms p95."""

    def test_tier15_mahalanobis_latency(self, classifier) -> None:
        """Classify a 100+ char text and verify p95 latency < 25ms over 50 iterations."""
        if _SKIP_ON_CI:
            pytest.skip("Latency gate not meaningful on shared CI runners")
        import numpy as np

        assert len(_TEST_TEXT) >= 100, "Test text too short to trigger Mahalanobis"

        # Warmup (excluded from measurements).
        for _ in range(_N_WARMUP):
            classifier.classify(_TEST_TEXT)

        # Measure.
        durations_ms: list[float] = []
        for _ in range(_N_MEASURE):
            t0 = time.perf_counter()
            classifier.classify(_TEST_TEXT)
            t1 = time.perf_counter()
            durations_ms.append((t1 - t0) * 1000.0)

        p50 = float(np.percentile(durations_ms, 50))
        p95 = float(np.percentile(durations_ms, 95))

        print(f"\nLatency: p50={p50:.2f}ms, p95={p95:.2f}ms (limit {_P95_LIMIT_MS}ms)")

        assert p95 <= _P95_LIMIT_MS, (
            f"HARD-05 p95 latency {p95:.2f}ms exceeds {_P95_LIMIT_MS}ms limit. p50={p50:.2f}ms"
        )

    def test_mahalanobis_loaded_in_classifier(self, classifier) -> None:
        """If mahalanobis_params.npz exists, the detector should be loaded."""
        if not MAHALANOBIS_PARAMS.exists():
            pytest.skip("mahalanobis_params.npz not present")
        assert classifier._mahalanobis is not None, (
            "MahalanobisDetector not loaded despite params file existing"
        )
        assert classifier._mahalanobis.threshold > 0.0

    def test_anomaly_score_populated_on_long_text(self, classifier) -> None:
        """anomaly_score should be > 0 for text >= 100 chars when Mahalanobis is loaded."""
        if classifier._mahalanobis is None:
            pytest.skip("Mahalanobis not loaded")
        result = classifier.classify(_TEST_TEXT)
        # anomaly_score is populated for text >= _MIN_MAHALANOBIS_CHARS
        assert result.anomaly_score > 0.0, (
            "anomaly_score is 0 for long text — Mahalanobis scoring may not be applied"
        )


class TestDualOutputOnnxShape:
    """Validate v4 ONNX model dual-output structure."""

    def test_dual_output_onnx_shape(self) -> None:
        """ONNX model outputs should be ['logits', 'cls_embedding'] with correct shapes."""
        if not ONNX_MODEL.exists():
            pytest.skip("ONNX model not found")

        try:
            import numpy as np
            import onnxruntime as ort  # type: ignore[import-untyped]
        except ImportError:
            pytest.skip("onnxruntime not installed")

        session = ort.InferenceSession(str(ONNX_MODEL), providers=["CPUExecutionProvider"])
        output_names = [o.name for o in session.get_outputs()]

        assert "logits" in output_names, f"Expected 'logits' in outputs, got {output_names}"
        assert "cls_embedding" in output_names, (
            f"Expected 'cls_embedding' in outputs, got {output_names}"
        )

        # Verify shapes with a dummy forward pass.
        dummy_ids = np.ones((1, 256), dtype=np.int64)
        dummy_mask = np.ones((1, 256), dtype=np.int64)
        outputs = session.run(None, {"input_ids": dummy_ids, "attention_mask": dummy_mask})

        assert len(outputs) == 2, f"Expected 2 outputs, got {len(outputs)}"
        logits, cls_emb = outputs
        assert logits.shape == (1, 2), f"logits shape should be (1, 2), got {logits.shape}"
        assert cls_emb.shape[0] == 1, f"cls_embedding batch dim should be 1, got {cls_emb.shape}"
        assert cls_emb.shape[1] == 384, (
            f"cls_embedding dim should be 384 (MiniLM-L6-v2), got {cls_emb.shape[1]}"
        )
