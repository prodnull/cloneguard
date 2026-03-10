"""Mahalanobis anomaly detector for Tier 1.5 CLS embeddings.

Detects out-of-distribution (OOD) samples by computing Mahalanobis distance
from each sample to the nearest class center. An embedding far from all known
class centers is anomalous -- it may represent an adversarial example that the
classifier labels SAFE but which lies outside the training distribution.

Defense-in-depth role:
    When the ONNX classifier returns SAFE but the CLS embedding is anomalous
    (score > threshold), the caller escalates the verdict to SUSPICIOUS.
    This raises attacker cost by requiring adversarial examples to fool both
    the logits head AND remain inside the training distribution.

Algorithm:
    - Fit per-class means and inverse covariances on training CLS embeddings.
    - Use LedoitWolf (scikit-learn) for covariance estimation.
    - score(x) = min over classes of sqrt((x-mu)^T Sigma^{-1} (x-mu)).
    - Threshold calibrated at (1 - target_fpr) quantile of benign eval scores.

References:
    Lee et al. (2018) "A Simple Unified Framework for Detecting Out-of-Distribution
    Samples and Adversarial Attacks." NeurIPS 2018. arXiv:1807.03888.
    Yoo and Qi (2021) "Towards Improving Adversarial Training of NLP Models."
    EMNLP Findings 2021. arXiv:2109.00544.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_SHRINKAGE = 1e-4
_STRONG_SHRINKAGE = 1e-3


class MahalanobisDetector:
    """Per-class Mahalanobis distance anomaly detector."""

    def __init__(self) -> None:
        self.class_labels: np.ndarray = np.array([])
        self.class_means: dict[int, np.ndarray] = {}
        self.class_inv_covs: dict[int, np.ndarray] = {}
        self.threshold: float = float("inf")

    def fit(self, embeddings: np.ndarray, labels: np.ndarray) -> None:
        """Fit per-class Gaussians from training CLS embeddings."""
        embeddings = np.asarray(embeddings, dtype=np.float64)
        labels = np.asarray(labels, dtype=np.int64)
        unique_labels = np.unique(labels)
        self.class_labels = unique_labels

        for label in unique_labels:
            class_emb = embeddings[labels == label]
            n, dim = class_emb.shape
            mean = class_emb.mean(axis=0)
            self.class_means[int(label)] = mean
            inv_cov = self._compute_inv_cov(class_emb, n, dim)
            self.class_inv_covs[int(label)] = inv_cov

    def _compute_inv_cov(self, class_emb: np.ndarray, n: int, dim: int) -> np.ndarray:
        if n < 2:
            shrinkage = _STRONG_SHRINKAGE
            return np.eye(dim, dtype=np.float64) / shrinkage

        near_singular = n < 2 * dim
        shrinkage = _STRONG_SHRINKAGE if near_singular else _DEFAULT_SHRINKAGE

        try:
            from sklearn.covariance import LedoitWolf

            lw = LedoitWolf(assume_centered=False)
            lw.fit(class_emb)
            cov = lw.covariance_
        except ImportError:
            cov = np.cov(class_emb, rowvar=False)
            if cov.ndim == 0:
                cov = np.array([[float(cov)]])
            cov = cov + np.eye(dim, dtype=np.float64) * shrinkage
        except Exception as exc:
            logger.debug("LedoitWolf failed (%s), using shrinkage covariance", exc)
            cov = np.cov(class_emb, rowvar=False)
            if cov.ndim == 0:
                cov = np.array([[float(cov)]])
            cov = cov + np.eye(dim, dtype=np.float64) * shrinkage

        cov = cov + np.eye(dim, dtype=np.float64) * shrinkage

        from scipy.linalg import pinv

        return pinv(cov)

    def score(self, embedding: np.ndarray) -> float:
        """Compute minimum Mahalanobis distance to any class center."""
        if not self.class_means:
            raise RuntimeError("MahalanobisDetector not fitted -- call fit() first.")

        x = np.asarray(embedding, dtype=np.float64).ravel()
        min_dist = float("inf")

        for label, mean in self.class_means.items():
            diff = x - mean
            inv_cov = self.class_inv_covs[label]
            dist_sq = float(diff @ inv_cov @ diff)
            dist = float(np.sqrt(max(dist_sq, 0.0)))
            if dist < min_dist:
                min_dist = dist

        return min_dist

    def is_anomalous(self, embedding: np.ndarray) -> bool:
        """Return True if score exceeds threshold."""
        return self.score(embedding) > self.threshold

    def fit_threshold(self, benign_embeddings: np.ndarray, target_fpr: float = 0.05) -> float:
        """Set threshold at (1 - target_fpr) quantile of benign scores."""
        benign_embeddings = np.asarray(benign_embeddings, dtype=np.float64)
        n = len(benign_embeddings)
        scores = np.array([self.score(e) for e in benign_embeddings])
        quantile = np.quantile(scores, 1.0 - target_fpr)
        self.threshold = float(quantile)

        n_flagged = int((scores > self.threshold).sum())
        actual_fpr = n_flagged / n if n > 0 else 0.0
        ci_lo, ci_hi = self._wilson_ci(n_flagged, n)

        logger.info(
            "Mahalanobis threshold calibrated: %.4f | target FPR=%.1f%% | "
            "actual FPR=%.1f%% (n=%d) | Wilson 95%% CI: [%.1f%%, %.1f%%]",
            self.threshold,
            target_fpr * 100,
            actual_fpr * 100,
            n,
            ci_lo * 100,
            ci_hi * 100,
        )
        return self.threshold

    @staticmethod
    def _wilson_ci(n_pos: int, n: int, z: float = 1.96) -> tuple[float, float]:
        """Wilson score interval for a proportion."""
        if n == 0:
            return 0.0, 1.0
        p = n_pos / n
        denom = 1 + z**2 / n
        centre = (p + z**2 / (2 * n)) / denom
        margin = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
        return max(0.0, centre - margin), min(1.0, centre + margin)

    def save(self, path: Path | str) -> None:
        """Serialize fitted parameters to a .npz file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        labels = self.class_labels
        k = len(labels)
        if k == 0:
            raise RuntimeError("Cannot save unfitted MahalanobisDetector.")

        dim = next(iter(self.class_means.values())).shape[0]
        means_arr = np.stack([self.class_means[int(lbl)] for lbl in labels])
        inv_covs_arr = np.stack([self.class_inv_covs[int(lbl)] for lbl in labels])

        np.savez(
            str(path),
            class_labels=labels,
            class_means=means_arr,
            class_inv_covs=inv_covs_arr,
            threshold=np.array([self.threshold]),
        )
        logger.info("MahalanobisDetector saved to %s (%d classes, dim=%d)", path, k, dim)

    @classmethod
    def load(cls, path: Path | str) -> MahalanobisDetector:
        """Load fitted parameters from a .npz file."""
        path = Path(path)
        data = np.load(str(path))

        detector = cls()
        labels = data["class_labels"]
        means = data["class_means"]
        inv_covs = data["class_inv_covs"]
        threshold = float(data["threshold"][0])

        detector.class_labels = labels
        detector.threshold = threshold

        for i, label in enumerate(labels):
            key = int(label)
            detector.class_means[key] = means[i]
            detector.class_inv_covs[key] = inv_covs[i]

        logger.debug("MahalanobisDetector loaded from %s (threshold=%.4f)", path, threshold)
        return detector
