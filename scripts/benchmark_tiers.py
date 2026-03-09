#!/usr/bin/env python3
"""Benchmark Tier 0 (regex), Tier 1.5 (ONNX mini model), and Tier 2 (Ollama) against the training dataset.

Reports accuracy, precision, recall, F1, and false positive rates for each tier.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

DATASET_PATH = Path("data/training/dataset.jsonl")


def load_dataset() -> list[dict]:
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}", file=sys.stderr)
        sys.exit(1)
    data = [json.loads(line) for line in DATASET_PATH.open()]
    print(f"Loaded {len(data)} samples ({sum(d['label'] for d in data)} malicious, "
          f"{sum(1 for d in data if d['label'] == 0)} benign)")
    return data


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    fpr = fp / max(fp + tn, 1)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def print_metrics(name: str, metrics: dict, elapsed: float) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")
    print(f"  Accuracy:           {metrics['accuracy']:.2%}")
    print(f"  Precision:          {metrics['precision']:.2%}")
    print(f"  Recall (detection): {metrics['recall']:.2%}")
    print(f"  F1 Score:           {metrics['f1']:.2%}")
    print(f"  False Positive Rate:{metrics['false_positive_rate']:.2%}")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  TN={metrics['tn']}  FN={metrics['fn']}")
    print(f"  Time: {elapsed:.1f}s ({elapsed * 1000 / max(metrics['tp'] + metrics['fp'] + metrics['tn'] + metrics['fn'], 1):.1f}ms/sample)")


def benchmark_tier0(data: list[dict]) -> None:
    """Benchmark Tier 0: regex PatternEngine."""
    from cloneguard.patterns import PatternEngine

    engine = PatternEngine()
    y_true = []
    y_pred = []

    start = time.perf_counter()
    for sample in data:
        result = engine.scan(sample["text"], source_path="test.md")
        predicted = 1 if result.matches else 0
        y_true.append(sample["label"])
        y_pred.append(predicted)
    elapsed = time.perf_counter() - start

    metrics = compute_metrics(y_true, y_pred)
    print_metrics("Tier 0: Regex PatternEngine", metrics, elapsed)

    # Show some false negatives (malicious missed by regex)
    fn_examples = [(d["text"][:80], d["label"]) for d, p in zip(data, y_pred)
                   if d["label"] == 1 and p == 0]
    if fn_examples:
        print(f"\n  Sample false negatives (malicious missed, showing 10/{len(fn_examples)}):")
        for text, _ in fn_examples[:10]:
            print(f"    - {text!r}")

    # Show some false positives (benign flagged by regex)
    fp_examples = [(d["text"][:80], d["label"]) for d, p in zip(data, y_pred)
                   if d["label"] == 0 and p == 1]
    if fp_examples:
        print(f"\n  Sample false positives (benign flagged, showing 10/{len(fp_examples)}):")
        for text, _ in fp_examples[:10]:
            print(f"    - {text!r}")


def benchmark_tier15(data: list[dict]) -> None:
    """Benchmark Tier 1.5: ONNX mini model."""
    from cloneguard.mini_semantic import MiniSemanticClassifier

    classifier = MiniSemanticClassifier()
    if not classifier.available:
        print("\nTier 1.5: ONNX mini model NOT AVAILABLE (skipping)")
        return

    y_true = []
    y_pred = []

    start = time.perf_counter()
    for sample in data:
        result = classifier.classify(sample["text"])
        predicted = 1 if result.verdict in ("MALICIOUS", "SUSPICIOUS") else 0
        y_true.append(sample["label"])
        y_pred.append(predicted)
    elapsed = time.perf_counter() - start

    metrics = compute_metrics(y_true, y_pred)
    print_metrics("Tier 1.5: ONNX Mini Model", metrics, elapsed)

    # False positives
    fp_examples = [(d["text"][:80], d["label"]) for d, p in zip(data, y_pred)
                   if d["label"] == 0 and p == 1]
    if fp_examples:
        print(f"\n  Sample false positives (benign flagged, showing 10/{len(fp_examples)}):")
        for text, _ in fp_examples[:10]:
            print(f"    - {text!r}")

    # False negatives
    fn_examples = [(d["text"][:80], d["label"]) for d, p in zip(data, y_pred)
                   if d["label"] == 1 and p == 0]
    if fn_examples:
        print(f"\n  Sample false negatives (malicious missed, showing 10/{len(fn_examples)}):")
        for text, _ in fn_examples[:10]:
            print(f"    - {text!r}")


def benchmark_tier2(data: list[dict], sample_size: int = 200) -> None:
    """Benchmark Tier 2: Ollama LLM (sampled, since it's slow)."""
    try:
        import ollama
        ollama.list()
    except Exception:
        print("\nTier 2: Ollama NOT AVAILABLE (skipping)")
        return

    from cloneguard.semantic import SemanticClassifier, SemanticVerdict

    classifier = SemanticClassifier()
    if not classifier.is_available():
        print("\nTier 2: Ollama model not available (skipping)")
        return

    # Sample evenly from malicious and benign
    import random
    rng = random.Random(42)
    malicious = [d for d in data if d["label"] == 1]
    benign = [d for d in data if d["label"] == 0]
    half = sample_size // 2
    sampled = rng.sample(malicious, min(half, len(malicious))) + rng.sample(benign, min(half, len(benign)))
    rng.shuffle(sampled)

    print(f"\nTier 2: Sampling {len(sampled)} of {len(data)} (Ollama is slow)")

    y_true = []
    y_pred = []

    start = time.perf_counter()
    for i, sample in enumerate(sampled):
        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{len(sampled)}", file=sys.stderr)
        finding = classifier.classify_content(sample["text"], "test.md")
        predicted = 1 if finding.verdict in (SemanticVerdict.MALICIOUS, SemanticVerdict.SUSPICIOUS) else 0
        y_true.append(sample["label"])
        y_pred.append(predicted)
    elapsed = time.perf_counter() - start

    metrics = compute_metrics(y_true, y_pred)
    print_metrics(f"Tier 2: Ollama (sampled {len(sampled)})", metrics, elapsed)


def main():
    data = load_dataset()

    tiers = sys.argv[1:] if len(sys.argv) > 1 else ["0", "1.5", "2"]

    if "0" in tiers:
        benchmark_tier0(data)
    if "1.5" in tiers:
        benchmark_tier15(data)
    if "2" in tiers:
        benchmark_tier2(data)

    print("\n" + "=" * 60)
    print("  BENCHMARK COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
