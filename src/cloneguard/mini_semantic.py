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

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / "model"
ONNX_MODEL = MODEL_DIR / "mini_semantic.onnx"

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


@dataclass
class MiniClassification:
    verdict: str  # "SAFE", "SUSPICIOUS", "MALICIOUS"
    confidence: float
    reason: str


class MiniSemanticClassifier:
    """Lightweight ONNX-based prompt injection classifier (Tier 1.5)."""

    def __init__(self) -> None:
        self._session: Any = None
        self._tokenizer: Any = None
        self._available: bool | None = None

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
            return True
        except ImportError:
            logger.debug("onnxruntime or transformers not installed")
            return False
        except Exception as e:
            logger.warning("Failed to load mini model: %s", e)
            return False

    def classify(self, text: str) -> MiniClassification:
        """Classify a single text sample."""
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
        logits = self._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )[0][0]

        probs = np.exp(logits) / np.exp(logits).sum()
        malicious_prob = float(probs[1])

        if malicious_prob > 0.8:
            verdict = "MALICIOUS"
        elif malicious_prob > 0.5:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        confidence = malicious_prob if verdict != "SAFE" else 1.0 - malicious_prob
        result = MiniClassification(
            verdict=verdict,
            confidence=confidence,
            reason=f"Mini model: {malicious_prob:.1%} malicious probability",
        )

        # Log SAFE verdicts below the review threshold for analyst review.
        if _REVIEW_LOG_PATH and verdict == "SAFE" and confidence < _REVIEW_THRESHOLD:
            self._log_for_review(text, result)

        # Sliding window: if initial verdict is SAFE, check for truncation evasion.
        if verdict == "SAFE":
            sw_result = self._classify_sliding_window(text)
            if sw_result is not None:
                return sw_result

        return result

    def _classify_sliding_window(self, text: str) -> MiniClassification | None:
        """Classify long inputs via overlapping sliding window.

        If the input fits within _WINDOW_SIZE tokens, returns None (no action).
        Otherwise, classifies overlapping chunks and returns the worst verdict.
        This defeats truncation-based evasion where an attacker front-pads
        benign tokens to push malicious content past the 256-token window.
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

            logits = self._session.run(
                None,
                {
                    "input_ids": input_ids_batch,
                    "attention_mask": attention_mask_batch,
                },
            )[0][0]

            probs = np.exp(logits) / np.exp(logits).sum()
            malicious_prob = float(probs[1])
            worst_prob = max(worst_prob, malicious_prob)
            num_chunks += 1

        if worst_prob > 0.8:
            verdict = "MALICIOUS"
        elif worst_prob > 0.5:
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

    def _scan_lines(self, content: str) -> MiniClassification | None:
        """Scan individual lines to counter dilution attacks.

        If the whole-file classification is SAFE, an attacker may have diluted
        a short malicious line among many benign lines. This scans all lines
        (not just fenced code blocks) that look like they could contain
        instructions or commands.
        Returns the worst finding, or None if all lines are safe.
        """
        worst: MiniClassification | None = None

        for line in content.splitlines():
            line = line.strip()
            if len(line) < _MIN_LINE_LEN:
                continue
            # Classify lines that could be imperative instructions or commands.
            # Skip lines that are clearly structural (pure markdown headers with
            # no instruction content, blank-ish lines, import statements).
            result = self.classify(line)
            if result.verdict != "SAFE":
                if worst is None or result.confidence > worst.confidence:
                    worst = MiniClassification(
                        verdict=result.verdict,
                        confidence=result.confidence,
                        reason=f"Line scan: {result.reason}",
                    )
        return worst

    def classify_files(self, files: list[tuple[str, str]]) -> SemanticResult:
        """Classify files — conforms to SemanticClassifier interface."""
        from cloneguard.semantic import SemanticFinding, SemanticResult, SemanticVerdict

        start = time.perf_counter()
        findings: list[SemanticFinding] = []

        for file_path, content in files:
            result = self.classify(content)
            if result.verdict == "SAFE":
                # Counter-dilution: scan all lines individually
                line_result = self._scan_lines(content)
                if line_result is not None:
                    result = line_result

            if result.verdict != "SAFE":
                findings.append(
                    SemanticFinding(
                        verdict=SemanticVerdict(result.verdict.lower()),
                        confidence=result.confidence,
                        reason=result.reason,
                        file_path=file_path,
                    )
                )

        elapsed = (time.perf_counter() - start) * 1000
        return SemanticResult(
            findings=findings,
            scan_time_ms=elapsed,
            model="mini-semantic-v1",
            available=True,
        )
