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

        return result

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

    def _scan_code_block_lines(self, content: str) -> MiniClassification | None:
        """Scan individual lines in fenced code blocks to counter dilution attacks.

        If the whole-file classification is SAFE, an attacker may have diluted
        a short malicious line among many benign lines. This method extracts
        lines from fenced code blocks and classifies each individually.
        Returns the worst finding, or None if all lines are safe.
        """
        blocks = _FENCED_BLOCK_RE.findall(content)
        if not blocks:
            return None

        worst: MiniClassification | None = None
        for block in blocks:
            for line in block.splitlines():
                line = line.strip()
                if len(line) < _MIN_LINE_LEN:
                    continue
                result = self.classify(line)
                if result.verdict != "SAFE":
                    if worst is None or result.confidence > worst.confidence:
                        worst = MiniClassification(
                            verdict=result.verdict,
                            confidence=result.confidence,
                            reason=f"Code block line: {result.reason}",
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
                # Counter-dilution: scan code block lines individually
                line_result = self._scan_code_block_lines(content)
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
