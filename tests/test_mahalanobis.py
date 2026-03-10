"""Tests for MahalanobisDetector (HARD-03).

Unit tests using synthetic 384-dim embeddings — no ONNX model required.
All tests exercise the core API contract: fit, score, threshold calibration,
save/load round-trip, and singularity resistance via diagonal shrinkage.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_gaussian(n: int, mean: np.ndarray, std: float, rng: np.random.Generator) -> np.ndarray:
    """Generate n samples from a Gaussian centred at mean."""
    dim = len(mean)
    return (rng.standard_normal((n, dim)) * std + mean).astype(np.float32)


DIM = 384
rng = np.random.default_rng(42)

# Two well-separated Gaussian clusters for classes 0 and 1.
_CLASS0_MEAN = rng.standard_normal(DIM).astype(np.float32) * 0.5
_CLASS1_MEAN = _CLASS0_MEAN + rng.standard_normal(DIM).astype(np.float32) * 3.0  # far away
_OOD_MEAN = _CLASS0_MEAN + rng.standard_normal(DIM).astype(np.float32) * 20.0  # very far


# ---------------------------------------------------------------------------
# Test 1: fit() runs without error on synthetic embeddings
# ---------------------------------------------------------------------------


class TestMahalanobisFit:
    """MahalanobisDetector.fit() computes per-class means and inverse covariances."""

    def test_fit_smoke(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(100, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 100 + [1] * 100)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)

        # After fitting, class_means and class_inv_covs must be set.
        assert hasattr(detector, "class_means")
        assert hasattr(detector, "class_inv_covs")
        assert len(detector.class_means) == 2
        assert len(detector.class_inv_covs) == 2

    def test_fit_single_sample_per_class(self) -> None:
        """Singularity: covariance from 1 sample must not crash (shrinkage rescues it)."""
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _CLASS0_MEAN.reshape(1, -1)
        emb1 = _CLASS1_MEAN.reshape(1, -1)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0, 1])

        detector = MahalanobisDetector()
        # Should not raise
        detector.fit(embeddings, labels)
        # score() must also work after degenerate fit
        score = detector.score(emb0[0])
        assert np.isfinite(score)


# ---------------------------------------------------------------------------
# Test 2: score() OOD detection — in-distribution < out-of-distribution
# ---------------------------------------------------------------------------


class TestMahalanobisScore:
    """score() returns higher distance for out-of-distribution embeddings."""

    def test_ood_score_higher(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(200, _CLASS0_MEAN, 0.3, rng)
        emb1 = _make_gaussian(200, _CLASS1_MEAN, 0.3, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 200 + [1] * 200)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)

        in_dist_score = detector.score(emb0[0])
        ood_score = detector.score(_OOD_MEAN)

        assert ood_score > in_dist_score, (
            f"OOD score {ood_score:.4f} should exceed in-dist score {in_dist_score:.4f}"
        )

    def test_score_returns_float(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(50, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(50, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 50 + [1] * 50)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)

        score = detector.score(emb0[0])
        assert isinstance(score, float)
        assert np.isfinite(score)
        assert score >= 0.0

    def test_is_anomalous_returns_bool(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(50, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(50, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 50 + [1] * 50)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)
        # Calibrate threshold so is_anomalous() makes sense.
        benign_emb = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        detector.fit_threshold(benign_emb, target_fpr=0.1)

        result = detector.is_anomalous(emb0[0])
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Test 3: fit_threshold() at 5% FPR — <= 5% of benign embeddings flagged
# ---------------------------------------------------------------------------


class TestMahalanobisThreshold:
    """fit_threshold() at 5% FPR produces a threshold where <= 5% benign flagged."""

    def test_fpr_at_most_5pct(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(300, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(300, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 300 + [1] * 300)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)

        # Use a fresh benign set (different seed to avoid fitting on eval set).
        rng2 = np.random.default_rng(99)
        benign_eval = _make_gaussian(500, _CLASS0_MEAN, 0.5, rng2)
        threshold = detector.fit_threshold(benign_eval, target_fpr=0.05)

        assert isinstance(threshold, float)
        assert np.isfinite(threshold)

        # Measure actual FPR on the calibration set.
        actual_fpr = sum(1 for e in benign_eval if detector.score(e) > threshold) / len(benign_eval)
        # Allow small margin for numerical precision; target is <= 5%.
        assert actual_fpr <= 0.055, f"Actual FPR {actual_fpr:.3%} exceeds target 5% + margin"

    def test_threshold_is_positive(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(100, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 100 + [1] * 100)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)
        benign_eval = _make_gaussian(200, _CLASS0_MEAN, 0.5, rng)
        threshold = detector.fit_threshold(benign_eval, target_fpr=0.05)
        assert threshold > 0.0


# ---------------------------------------------------------------------------
# Test 4: save() / load() round-trip — identical scores
# ---------------------------------------------------------------------------


class TestMahalanobisSaveLoad:
    """save() and load() round-trip produces identical scores."""

    def test_roundtrip_identical_scores(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(100, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 100 + [1] * 100)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)
        benign_eval = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        detector.fit_threshold(benign_eval, target_fpr=0.05)

        # Save to a temp file, reload, compare scores.
        test_vec = _make_gaussian(5, _CLASS0_MEAN, 0.5, rng)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mahalanobis_params.npz"
            detector.save(path)

            loaded = MahalanobisDetector.load(path)

        original_scores = [detector.score(v) for v in test_vec]
        loaded_scores = [loaded.score(v) for v in test_vec]

        for orig, load in zip(original_scores, loaded_scores):
            assert abs(orig - load) < 1e-5, (
                f"Score mismatch after round-trip: {orig:.6f} vs {load:.6f}"
            )

    def test_roundtrip_threshold_preserved(self) -> None:
        from cloneguard.mahalanobis import MahalanobisDetector

        emb0 = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        emb1 = _make_gaussian(100, _CLASS1_MEAN, 0.5, rng)
        embeddings = np.concatenate([emb0, emb1])
        labels = np.array([0] * 100 + [1] * 100)

        detector = MahalanobisDetector()
        detector.fit(embeddings, labels)
        benign_eval = _make_gaussian(100, _CLASS0_MEAN, 0.5, rng)
        detector.fit_threshold(benign_eval, target_fpr=0.05)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "params.npz"
            detector.save(path)
            loaded = MahalanobisDetector.load(path)

        assert abs(detector.threshold - loaded.threshold) < 1e-6
