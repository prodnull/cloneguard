#!/usr/bin/env python3
# Run with: .venv-transfer/bin/python scripts/adaptive_pwws_benchmark.py
"""Adaptive PWWS benchmark against the final v4 hardened ONNX model.

This script measures the TRUE adaptive attack success rate (ASR) of PWWS
against the v4 hardened MiniLM ONNX model. This is a MEASUREMENT-ONLY script —
it does NOT write augmentation data and does NOT merge into any training dataset.

IMPORTANT: This adaptive ASR is distinct from the round-2 training-time ASR
(20.0%). The round-2 number was measured during PWWS-augmented training rounds
and is a generation rate, not an adaptive attack measurement. This script treats
PWWS as a test-time adversary with fresh attacks against the final v4 model.

Usage
-----
  .venv-transfer/bin/python scripts/adaptive_pwws_benchmark.py \\
      --output docs/results/adaptive-pwws-benchmark-2026-03-10.json \\
      --time-limit 90

References
----------
- Ren et al. (2019). Generating Natural Language Adversarial Examples through
  Probability Weighted Word Saliency. ACL 2019.
  https://aclanthology.org/P19-1103/
- Morris et al. (2020). TextAttack: A Framework for Adversarial Attacks, Data
  Augmentation, and Adversarial Training in NLP.
  https://arxiv.org/abs/2005.05909
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_PATH = str(_REPO_ROOT / "src" / "cloneguard" / "model" / "mini_semantic.onnx")
_DEFAULT_CORPUS = str(_REPO_ROOT / "data" / "benchmark" / "malicious_corpus.json")
_DEFAULT_OUTPUT = str(_REPO_ROOT / "docs" / "results" / "adaptive-pwws-benchmark-2026-03-10.json")

# Round-2 training-time numbers for comparison context (NOT an adaptive attack)
_ROUND2_BENCHMARK_ASR = 0.20  # fraction of 185-sample benchmark flipped after round-2
_ROUND2_GENERATION_ASR = 0.317  # PWWS generation success rate during round-2 augmentation


# ---------------------------------------------------------------------------
# MiniLMOnnxWrapper (copied from scripts/generate_pwws_augmentation.py)
# Copied intentionally — .venv-transfer and .venv have incompatible packages.
# Keep in sync manually if the ONNX interface changes.
# ---------------------------------------------------------------------------


class MiniLMOnnxWrapper:
    """TextAttack ModelWrapper wrapping the MiniLM ONNX classifier.

    Implements the __call__ interface expected by TextAttack attack recipes.
    Input: list[str]
    Output: np.ndarray of shape [batch, 2] — col 0 = P(benign), col 1 = P(malicious)

    References:
    - TextAttack ModelWrapper protocol: https://textattack.readthedocs.io/
    - Pattern copied from scripts/generate_pwws_augmentation.py (venv isolation)
    """

    def __init__(self, session: Any, tokenizer: Any) -> None:
        # TextAttack ModelWrapper protocol requires self.model attribute
        self.model = session
        self.tokenizer = tokenizer
        self._session = session

    def __call__(self, text_inputs: list[str]) -> np.ndarray:
        results = []
        for text in text_inputs:
            inputs = self.tokenizer(
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
            exp_logits = np.exp(logits - logits.max())  # numerically stable softmax
            probs = exp_logits / exp_logits.sum()
            results.append(probs)  # [p_benign, p_malicious]
        return np.array(results, dtype=np.float32)


# ---------------------------------------------------------------------------
# Raw scoring helper (bypasses classify() thresholds, mirrors generate_pwws)
# ---------------------------------------------------------------------------


def raw_score(session: Any, tokenizer: Any, text: str) -> float:
    """Score a text sample via raw ONNX logits, bypassing thresholds.

    Returns p(malicious) in [0, 1].
    """
    inputs = tokenizer(
        text,
        return_tensors="np",
        truncation=True,
        max_length=256,
        padding="max_length",
    )
    logits = session.run(
        None,
        {
            "input_ids": inputs["input_ids"],
            "attention_mask": inputs["attention_mask"],
        },
    )[0][0]
    exp_l = np.exp(logits - logits.max())
    probs = exp_l / exp_l.sum()
    return float(probs[1])


# ---------------------------------------------------------------------------
# Wilson confidence interval
# ---------------------------------------------------------------------------


def wilson_ci(successes: int, total: int, alpha: float = 0.05) -> tuple[float, float]:
    """Compute Wilson score confidence interval for a proportion.

    More accurate than normal approximation for small samples.

    Reference: Wilson (1927). Probable inference, the law of succession,
    and statistical inference. JASA 22(158):209-212.
    Implemented via scipy.stats.proportion_confint (method='wilson').

    Args:
        successes: Number of successful events.
        total: Total number of trials.
        alpha: Significance level (default 0.05 → 95% CI).

    Returns:
        (ci_low, ci_high) tuple.
    """
    from scipy.stats import proportion_confint  # type: ignore[import-untyped]

    if total == 0:
        return 0.0, 0.0
    ci_low, ci_high = proportion_confint(successes, total, alpha=alpha, method="wilson")
    return float(ci_low), float(ci_high)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the adaptive PWWS benchmark script.

    Args:
        argv: Argument list (defaults to sys.argv[1:] if None).

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Adaptive PWWS benchmark against v4 hardened ONNX. "
            "Measurement only — does NOT write training data."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--output",
        type=str,
        default=_DEFAULT_OUTPUT,
        metavar="PATH",
        help=f"Output JSON path (default: {_DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=_DEFAULT_MODEL_PATH,
        metavar="PATH",
        help=f"Path to MiniLM ONNX model (default: {_DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=_DEFAULT_CORPUS,
        metavar="PATH",
        help=f"Path to malicious corpus JSON (default: {_DEFAULT_CORPUS})",
    )
    parser.add_argument(
        "--time-limit",
        type=int,
        default=90,
        metavar="MINUTES",
        help="Maximum wall-clock time for attack generation (default: 90 minutes)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Process only first N corpus samples (for testing/debugging)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Main — requires TextAttack and onnxruntime (.venv-transfer)
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    try:
        import onnxruntime as ort
        from textattack import AttackArgs, Attacker
        from textattack.attack_recipes import PWWSRen2019
        from textattack.attack_results import SkippedAttackResult, SuccessfulAttackResult
        from textattack.datasets import Dataset as TADataset
        from transformers import AutoTokenizer
    except ImportError as exc:
        print(
            f"ERROR: Required package not found: {exc}\n"
            "This script must run in .venv-transfer (TextAttack environment).\n"
            "Run: .venv-transfer/bin/python scripts/adaptive_pwws_benchmark.py",
            file=sys.stderr,
        )
        sys.exit(1)

    model_path = Path(args.model_path)
    corpus_path = Path(args.corpus)
    output_path = Path(args.output)
    time_limit_seconds = args.time_limit * 60

    print("=" * 60, file=sys.stderr)
    print("CloneGuard Adaptive PWWS Benchmark — v4 ONNX", file=sys.stderr)
    print("MEASUREMENT ONLY — not writing training data", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Model:       {model_path}", file=sys.stderr)
    print(f"  Corpus:      {corpus_path}", file=sys.stderr)
    print(f"  Output:      {output_path}", file=sys.stderr)
    print(f"  Time limit:  {args.time_limit} minutes", file=sys.stderr)
    print(f"  Limit:       {args.limit if args.limit else 'all'}", file=sys.stderr)
    print(file=sys.stderr)

    # Guard: model and corpus must exist
    if not model_path.exists():
        print(f"ERROR: ONNX model not found: {model_path}", file=sys.stderr)
        sys.exit(1)
    if not corpus_path.exists():
        print(f"ERROR: Corpus not found: {corpus_path}", file=sys.stderr)
        sys.exit(1)

    # Load model + tokenizer
    print("Loading MiniLM ONNX model...", file=sys.stderr)
    session = ort.InferenceSession(str(model_path))
    tokenizer = AutoTokenizer.from_pretrained(
        str(model_path.parent),
        local_files_only=True,
    )
    print("  Loaded.", file=sys.stderr)

    model_wrapper = MiniLMOnnxWrapper(session, tokenizer)

    # Load corpus
    with open(corpus_path) as f:
        corpus: list[dict[str, Any]] = json.load(f)

    if args.limit is not None:
        corpus = corpus[: args.limit]

    corpus_size = len(corpus)

    # Pre-filter: only attack samples the v4 model currently detects (score > 0.5)
    # Rationale: attacking already-missed samples gives inflated apparent ASR
    # (a "successful evasion" on a sample already evading is not informative)
    print(
        "Pre-filtering corpus (v4 raw score > 0.5 required)...",
        file=sys.stderr,
    )
    filtered_samples: list[tuple[str, int]] = []
    sample_ids: list[str] = []
    sample_categories: list[str] = []
    pre_misclassified_skipped = 0

    for sample in corpus:
        score = raw_score(session, tokenizer, sample["payload"])
        if score <= 0.5:
            pre_misclassified_skipped += 1
            print(
                f"  Skipping {sample['id']} ({sample.get('category', '?')}): "
                f"score={score:.3f} (already evading)",
                file=sys.stderr,
            )
            continue
        filtered_samples.append((sample["payload"], 1))
        sample_ids.append(sample["id"])
        sample_categories.append(sample.get("category", "unknown"))

    pre_filtered_count = len(filtered_samples)
    print(
        f"Pre-filter complete: {pre_filtered_count} to attack "
        f"({pre_misclassified_skipped} skipped — already evading v4)",
        file=sys.stderr,
    )

    if not filtered_samples:
        print("ERROR: No samples to attack after pre-filtering.", file=sys.stderr)
        sys.exit(1)

    # Initialize per-category tracking
    categories_seen = sorted(set(sample_categories))
    per_category: dict[str, dict[str, Any]] = {
        cat: {"total": 0, "evaded": 0, "asr": 0.0} for cat in categories_seen
    }
    for cat in sample_categories:
        per_category[cat]["total"] += 1

    # Build TextAttack dataset and PWWS attack
    ta_dataset = TADataset(filtered_samples)
    attack = PWWSRen2019.build(model_wrapper)
    attack_args = AttackArgs(
        num_examples=pre_filtered_count,
        disable_stdout=True,
        silent=True,
    )
    attacker = Attacker(attack, ta_dataset, attack_args)

    # Run adaptive attack
    attacks_successful = 0
    attacks_failed = 0
    attacks_skipped = 0

    t_start = time.time()
    print(f"\nRunning PWWS on {pre_filtered_count} samples...", file=sys.stderr)

    for idx, result in enumerate(attacker.attack_dataset()):
        elapsed = time.time() - t_start
        print(
            f"\r  {idx + 1}/{pre_filtered_count} | evaded={attacks_successful} | {elapsed:.0f}s",
            end="",
            file=sys.stderr,
        )

        if elapsed > time_limit_seconds:
            print(
                f"\n  Time limit ({args.time_limit} min) reached. Stopping early.",
                file=sys.stderr,
            )
            break

        sample_cat = sample_categories[idx] if idx < len(sample_categories) else "unknown"

        if isinstance(result, SuccessfulAttackResult):
            attacks_successful += 1
            per_category[sample_cat]["evaded"] += 1
        elif isinstance(result, SkippedAttackResult):
            attacks_skipped += 1
        else:
            attacks_failed += 1

    print(file=sys.stderr)

    # Compute overall adaptive ASR on attacked samples
    # Denominator = samples actually attacked (not pre-filtered + not skipped)
    samples_attempted = attacks_successful + attacks_failed
    if samples_attempted == 0:
        adaptive_asr = 0.0
    else:
        adaptive_asr = attacks_successful / samples_attempted

    # Wilson confidence interval on the adaptive ASR
    ci_low, ci_high = wilson_ci(attacks_successful, samples_attempted)

    # Compute per-category ASR
    for cat_data in per_category.values():
        cat_total = cat_data["total"]
        cat_evaded = cat_data["evaded"]
        cat_data["asr"] = round(cat_evaded / cat_total, 4) if cat_total > 0 else 0.0

    # Build output JSON
    output: dict[str, Any] = {
        "date": "2026-03-10",
        "model_version": "v4",
        "attack_method": "pwws",
        "corpus_size": corpus_size,
        "pre_filtered_count": pre_filtered_count,
        "pre_misclassified_skipped": pre_misclassified_skipped,
        "adaptive_asr": round(adaptive_asr, 4),
        "attacks_successful": attacks_successful,
        "attacks_failed": attacks_failed,
        "confidence_interval": {
            "ci_low": round(ci_low, 4),
            "ci_high": round(ci_high, 4),
            "method": "wilson",
            "alpha": 0.05,
        },
        "per_category": per_category,
        "comparison_to_training_rounds": {
            "round_2_benchmark_asr": _ROUND2_BENCHMARK_ASR,
            "round_2_generation_asr": _ROUND2_GENERATION_ASR,
            "note": (
                "Round-2 numbers measured during training; "
                "this adaptive ASR measured on final v4 model as test-time attack"
            ),
        },
        "metadata": {
            "model_version": "v4",
            "attack_method": "pwws",
            "model_path": str(model_path),
            "time_limit_minutes": args.time_limit,
            "distinguishing_note": (
                "Adaptive attack: fresh PWWS against final v4 model. "
                "NOT the round-2 training-time ASR (20.0%). "
                "Round-2 ASR was measured during augmented training, not as a test-time adversary."
            ),
        },
    }

    # Write output (never to training data directories)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Print summary
    elapsed_total = time.time() - t_start
    print(f"\n{'=' * 60}", file=sys.stderr)
    print("Adaptive PWWS Benchmark Summary", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)
    print(f"  Corpus size:           {corpus_size}", file=sys.stderr)
    print(f"  Pre-filtered (v4>0.5): {pre_filtered_count}", file=sys.stderr)
    print(f"  Pre-missed (skipped):  {pre_misclassified_skipped}", file=sys.stderr)
    print(f"  Attacks attempted:     {samples_attempted}", file=sys.stderr)
    print(f"  Successful evasions:   {attacks_successful}", file=sys.stderr)
    print(f"  Failed attacks:        {attacks_failed}", file=sys.stderr)
    ci_str = f"{ci_low:.1%}–{ci_high:.1%}"
    print(f"  Adaptive ASR:          {adaptive_asr:.1%} (95% CI: {ci_str})", file=sys.stderr)
    print(f"  Round-2 training ASR:  {_ROUND2_BENCHMARK_ASR:.1%} (NOT adaptive)", file=sys.stderr)
    print(f"  Elapsed:               {elapsed_total:.0f}s", file=sys.stderr)
    print(f"  Output:                {output_path}", file=sys.stderr)

    print(f"\nAdaptive ASR: {adaptive_asr:.1%}")


if __name__ == "__main__":
    main()
