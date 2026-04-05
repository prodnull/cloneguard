"""Tier 1.5: Bundled mini semantic classifier using ONNX Runtime.

Fine-tuned MiniLM-L6-v2 (~87MB ONNX) for prompt injection detection.
No external services required — runs entirely offline with onnxruntime.

Falls through to Tier 2 (Ollama) for:
- Multilingual attacks (non-English) — limited training data
- Novel attack patterns not in training set
- High-confidence SUSPICIOUS verdicts needing confirmation
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloneguard.semantic import SemanticResult

from cloneguard.detection.patterns import ScanMode

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent.parent / "model"
ONNX_MODEL = MODEL_DIR / "mini_semantic.onnx"
MAHALANOBIS_PARAMS = MODEL_DIR / "mahalanobis_params.npz"

_FENCED_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_MIN_LINE_LEN = 10  # Skip trivially short lines in code blocks

# Low-confidence classification log: captures SAFE verdicts below a confidence
# threshold for analyst review. Disabled by default.
# Enable via: CLONEGUARD_REVIEW_LOG=/path/to/review.jsonl
# Threshold via: CLONEGUARD_REVIEW_THRESHOLD=0.98 (default: 0.98)
_REVIEW_LOG_PATH = os.environ.get("CLONEGUARD_REVIEW_LOG", "")
_REVIEW_THRESHOLD = float(os.environ.get("CLONEGUARD_REVIEW_THRESHOLD", "0.98"))

_MAX_CHUNKS = 16  # Sliding window: max chunks to classify (~8K chars, ~256ms worst case)
_WINDOW_SIZE = 256  # Tokens per classification window
_STRIDE = 128  # Token stride (50% overlap) — prevents boundary-splitting evasion
# Minimum text length for Mahalanobis scoring: short inputs (<100 chars) produce
# systematically OOD embeddings due to padding artifacts, not adversarial content.
_MIN_MAHALANOBIS_CHARS = 100

# Per-ScanMode threshold table: (suspicious_threshold, malicious_threshold).
# STRICT is LOCKED — see Phase 5 CONTEXT.md. Do not modify STRICT values.
# STANDARD and LENIENT values derived from calibration sweep on
# data/benchmark/benign_eval_751.json (scripts/calibrate_thresholds.py, 2026-03-11).
_DEFAULT_THRESHOLDS: dict[ScanMode, tuple[float, float]] = {
    ScanMode.STRICT: (0.5, 0.8),  # LOCKED: Do not modify — per Phase 5 CONTEXT.md
    ScanMode.STANDARD: (0.65, 0.88),  # From calibration: balances FPR reduction and recall
    ScanMode.LENIENT: (0.75, 0.92),  # From calibration: test/fixture contexts, low attack surface
}


def _get_thresholds(mode: ScanMode) -> tuple[float, float]:
    """Return (suspicious_threshold, malicious_threshold) for the given ScanMode.

    Reads env var overrides at call time (not module load) to support test patching
    and runtime configuration without restart. Env var pattern:
      CLONEGUARD_THRESHOLD_{MODE}_SUSPICIOUS
      CLONEGUARD_THRESHOLD_{MODE}_MALICIOUS

    Where {MODE} is STRICT, STANDARD, or LENIENT.
    """
    defaults = _DEFAULT_THRESHOLDS[mode]
    mode_name = mode.value.upper()
    susp = float(os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_SUSPICIOUS", defaults[0]))
    mal = float(os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_MALICIOUS", defaults[1]))
    return susp, mal


@dataclass
class MiniClassification:
    verdict: str  # "SAFE", "SUSPICIOUS", "MALICIOUS"
    confidence: float
    reason: str
    anomaly_score: float = 0.0  # Mahalanobis distance (0.0 = normal, higher = anomalous)
    anomaly_flagged: bool = False  # True when score exceeds calibrated threshold


class MiniSemanticClassifier:
    """Lightweight ONNX-based prompt injection classifier (Tier 1.5)."""

    def __init__(self) -> None:
        self._session: Any = None
        self._tokenizer: Any = None
        self._available: bool | None = None
        self._mahalanobis: Any = None  # MahalanobisDetector | None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = self._try_load()
        return self._available

    def _try_load(self) -> bool:
        try:
            import onnxruntime as ort  # type: ignore[import-untyped]
            from transformers import AutoTokenizer

            if not ONNX_MODEL.exists():
                logger.debug("Mini model not found at %s", ONNX_MODEL)
                return False
            self._session = ort.InferenceSession(
                str(ONNX_MODEL),
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
            logger.debug("Mini semantic model loaded successfully")

            # Load Mahalanobis detector if parameters are available.
            # Graceful degradation: v3 ONNX models without .npz still work.
            if MAHALANOBIS_PARAMS.exists():
                try:
                    from cloneguard.mahalanobis import MahalanobisDetector

                    self._mahalanobis = MahalanobisDetector.load(MAHALANOBIS_PARAMS)
                    logger.debug(
                        "Mahalanobis detector loaded (threshold=%.4f)", self._mahalanobis.threshold
                    )
                except Exception as e:
                    logger.warning("Failed to load Mahalanobis detector: %s", e)
                    self._mahalanobis = None
            else:
                logger.debug(
                    "Mahalanobis params not found at %s — anomaly detection disabled",
                    MAHALANOBIS_PARAMS,
                )

            return True
        except ImportError:
            logger.debug("onnxruntime or transformers not installed")
            return False
        except Exception as e:
            logger.warning("Failed to load mini model: %s", e)
            return False

    def classify(
        self,
        text: str,
        *,
        mode: ScanMode = ScanMode.STANDARD,
        _apply_mahalanobis: bool = True,
    ) -> MiniClassification:
        """Classify a single text sample.

        Args:
            text: Input text to classify.
            mode: ScanMode controlling detection thresholds. STRICT uses the
                locked (0.5, 0.8) thresholds; STANDARD and LENIENT use higher
                thresholds to reduce FPR on benign content. Defaults to STANDARD
                for backward-compatibility with callers that don't pass mode.
            _apply_mahalanobis: Apply Mahalanobis scoring (default True). Set
                to False for short-fragment line scanning where OOD distances
                reflect fragment length, not adversarial content.
        """
        if not self.available:
            return MiniClassification(
                verdict="SAFE", confidence=0.0, reason="Mini model not available"
            )

        import numpy as np

        inputs = self._tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=256,
            padding="max_length",
        )
        outputs = self._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )
        logits = outputs[0][0]

        # Extract CLS embedding if available (v4 dual-output ONNX).
        cls_embedding = outputs[1][0] if len(outputs) > 1 else None

        probs = np.exp(logits) / np.exp(logits).sum()
        malicious_prob = float(probs[1])

        susp_thresh, mal_thresh = _get_thresholds(mode)
        if malicious_prob > mal_thresh:
            verdict = "MALICIOUS"
        elif malicious_prob > susp_thresh:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        confidence = malicious_prob if verdict != "SAFE" else 1.0 - malicious_prob
        result = MiniClassification(
            verdict=verdict,
            confidence=confidence,
            reason=f"Mini model: {malicious_prob:.1%} malicious probability",
        )

        # Mahalanobis anomaly scoring (defense-in-depth orthogonal signal).
        # Applied only on full-content text of sufficient length. Short inputs
        # produce systematically OOD embeddings regardless of content (fragment
        # length effect). _scan_lines also sets _apply_mahalanobis=False.
        # SAFE + anomalous -> SUSPICIOUS raises attacker cost: adversaries must
        # fool both the logits head AND remain inside the training distribution.
        if (
            _apply_mahalanobis
            and self._mahalanobis is not None
            and cls_embedding is not None
            and len(text) >= _MIN_MAHALANOBIS_CHARS
        ):
            anomaly_score = self._mahalanobis.score(cls_embedding)
            anomaly_flagged = self._mahalanobis.is_anomalous(cls_embedding)
            result.anomaly_score = anomaly_score
            result.anomaly_flagged = anomaly_flagged
            if result.verdict == "SAFE" and anomaly_flagged:
                result.verdict = "SUSPICIOUS"
                result.reason = f"{result.reason} [Mahalanobis anomaly: score={anomaly_score:.2f}]"

        # Log SAFE verdicts below the review threshold for analyst review.
        if _REVIEW_LOG_PATH and result.verdict == "SAFE" and result.confidence < _REVIEW_THRESHOLD:
            self._log_for_review(text, result)

        # Sliding window: if initial verdict is SAFE, check for truncation evasion.
        if result.verdict == "SAFE":
            sw_result = self._classify_sliding_window(text, mode=mode)
            if sw_result is not None:
                return sw_result

        return result

    def _classify_sliding_window(
        self, text: str, mode: ScanMode = ScanMode.STANDARD
    ) -> MiniClassification | None:
        """Classify long inputs via overlapping sliding window.

        If the input fits within _WINDOW_SIZE tokens, returns None (no action).
        Otherwise, classifies overlapping chunks and returns the worst verdict.
        This defeats truncation-based evasion where an attacker front-pads
        benign tokens to push malicious content past the 256-token window.

        Args:
            text: Input text to classify.
            mode: ScanMode controlling detection thresholds (threaded from classify()).
        """
        import numpy as np

        # Tokenize without truncation to measure true length.
        full_encoding = self._tokenizer(text, truncation=False, return_tensors="np")
        token_ids = full_encoding["input_ids"][0]

        if len(token_ids) <= _WINDOW_SIZE:
            return None

        logger.warning(
            "Input truncated: %d tokens (max %d). Applying sliding window.",
            len(token_ids),
            _WINDOW_SIZE,
        )

        worst_prob = 0.0
        num_chunks = 0

        for i in range(0, len(token_ids), _STRIDE):
            if num_chunks >= _MAX_CHUNKS:
                break

            chunk_ids = token_ids[i : i + _WINDOW_SIZE]
            chunk_len = len(chunk_ids)

            # Pad to _WINDOW_SIZE if the last chunk is shorter.
            if chunk_len < _WINDOW_SIZE:
                pad_len = _WINDOW_SIZE - chunk_len
                chunk_ids = np.concatenate([chunk_ids, np.zeros(pad_len, dtype=chunk_ids.dtype)])
                attention_mask = np.concatenate(
                    [np.ones(chunk_len, dtype=np.int64), np.zeros(pad_len, dtype=np.int64)]
                )
            else:
                attention_mask = np.ones(_WINDOW_SIZE, dtype=np.int64)

            # Reshape to (1, 256) for ONNX inference.
            input_ids_batch = chunk_ids.reshape(1, _WINDOW_SIZE)
            attention_mask_batch = attention_mask.reshape(1, _WINDOW_SIZE)

            chunk_outputs = self._session.run(
                None,
                {
                    "input_ids": input_ids_batch,
                    "attention_mask": attention_mask_batch,
                },
            )
            logits = chunk_outputs[0][0]

            # NOTE: Mahalanobis scoring is NOT applied per-chunk in the sliding
            # window. The threshold was calibrated on single-chunk (256-token)
            # embeddings. Scoring multiple chunks from the same document and
            # taking the worst would inflate false positive rates substantially
            # (one OOD chunk in a long benign document would flag the whole
            # document). Mahalanobis runs once at the classify() level on the
            # first 256 tokens, before the sliding window is invoked.

            probs = np.exp(logits) / np.exp(logits).sum()
            malicious_prob = float(probs[1])
            worst_prob = max(worst_prob, malicious_prob)
            num_chunks += 1

        susp_thresh, mal_thresh = _get_thresholds(mode)
        if worst_prob > mal_thresh:
            verdict = "MALICIOUS"
        elif worst_prob > susp_thresh:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        if verdict == "SAFE":
            return None

        confidence = worst_prob
        return MiniClassification(
            verdict=verdict,
            confidence=confidence,
            reason=(
                f"Sliding window ({num_chunks} chunks): {worst_prob:.1%} malicious probability"
            ),
            # anomaly_score and anomaly_flagged are not set here — see classify()
            # for the single-chunk Mahalanobis scoring applied before sliding window.
        )

    def _log_for_review(self, text: str, result: MiniClassification) -> None:
        """Append a low-confidence SAFE classification to the review log."""
        try:
            entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "verdict": result.verdict,
                "confidence": round(result.confidence, 4),
                "text_preview": text[:200],
                "text_length": len(text),
                "reason": result.reason,
            }
            with open(_REVIEW_LOG_PATH, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            logger.debug("Failed to write review log to %s", _REVIEW_LOG_PATH)

    def _scan_lines(
        self, content: str, mode: ScanMode = ScanMode.STANDARD
    ) -> MiniClassification | None:
        """Scan individual lines to counter dilution attacks.

        If the whole-file classification is SAFE, an attacker may have diluted
        a short malicious line among many benign lines. This scans all lines
        (not just fenced code blocks) that look like they could contain
        instructions or commands.
        Returns the worst finding, or None if all lines are safe.

        Args:
            content: Full file content to line-scan.
            mode: ScanMode controlling detection thresholds (threaded from classify_files()).
        """
        worst: MiniClassification | None = None

        for line in content.splitlines():
            line = line.strip()
            if len(line) < _MIN_LINE_LEN:
                continue
            # Classify lines that could be imperative instructions or commands.
            # Skip Mahalanobis on line fragments: short snippets produce OOD
            # distances by nature (fragment length, not adversarial content).
            result = self.classify(line, mode=mode, _apply_mahalanobis=False)
            if result.verdict != "SAFE":
                if worst is None or result.confidence > worst.confidence:
                    worst = MiniClassification(
                        verdict=result.verdict,
                        confidence=result.confidence,
                        reason=f"Line scan: {result.reason}",
                    )
        return worst

    def classify_files(
        self, files: list[tuple[str, str]], mode: ScanMode = ScanMode.STANDARD
    ) -> SemanticResult:
        """Classify files — conforms to SemanticClassifier interface.

        Args:
            files: List of (file_path, content) pairs to classify.
            mode: ScanMode controlling detection thresholds for all files in this
                batch. Callers (scanner.py, hooks.py) supply mode from path-based
                mode detection so per-file thresholds are applied correctly.
        """
        from cloneguard.semantic import SemanticFinding, SemanticResult, SemanticVerdict

        start = time.perf_counter()
        findings: list[SemanticFinding] = []

        for file_path, content in files:
            result = self.classify(content, mode=mode)
            if result.verdict == "SAFE":
                # Counter-dilution: scan all lines individually
                line_result = self._scan_lines(content, mode=mode)
                if line_result is not None:
                    result = line_result

            if result.verdict != "SAFE":
                findings.append(
                    SemanticFinding(
                        verdict=SemanticVerdict(result.verdict.lower()),
                        confidence=result.confidence,
                        reason=result.reason,
                        file_path=file_path,
                        anomaly_score=result.anomaly_score,
                        anomaly_flagged=result.anomaly_flagged,
                    )
                )

        elapsed = (time.perf_counter() - start) * 1000
        return SemanticResult(
            findings=findings,
            scan_time_ms=elapsed,
            model="mini-semantic-v1",
            available=True,
        )
