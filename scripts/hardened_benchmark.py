"""Hardened pipeline benchmark for CloneGuard v0.3.0 adversarial hardening.

Runs the full hardened pipeline (Tier 0 regex + hardened Tier 1.5 ONNX v4
+ Mahalanobis anomaly detector) on the adversarial and benign corpora.

Produces docs/results/hardened-benchmark-2026-03-10.json with:
  - recall: overall + per-category (malicious detected as MALICIOUS or SUSPICIOUS)
  - fpr: combined pipeline false positive rate on benign eval
  - mahalanobis: Mahalanobis-only detection rate and FPR
  - asr: attack success rate (adversarial examples that evade hardened pipeline)
  - latency: p50/p95 per-sample latency measurement (gate: p95 < 25ms)
  - delta_from_v3: before/after comparison against v3 baseline numbers

Framing: this benchmark measures how much the v4 hardened pipeline raises
attacker cost compared to v3. It does not measure absolute protection.

Usage:
    .venv/bin/python scripts/hardened_benchmark.py \
        --malicious data/benchmark/malicious_corpus.json \
        --benign data/benchmark/benign_eval_751.json \
        --output docs/results/hardened-benchmark-2026-03-10.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

# v3 baseline numbers from docs/results/multitier-benchmark-2026-03-10.json
# v3 baseline from docs/results/multitier-benchmark-2026-03-10.json (234-sample benign eval).
# Note: v4 benchmark uses 757-sample benign eval -- FPR comparison is approximate.
_V3_RECALL = 0.805  # union recall on 185 malicious samples
_V3_FPR = 0.038  # false_block_rate (BLOCKED verdicts only, 234-sample benign eval)
_V3_TIER15_FPR = 0.1538  # Tier 1.5 FPR v3 for direct Tier 1.5 comparison
_V3_ASR = 0.200  # benchmark ASR after 2 rounds PWWS (Plan 02 summary)

_P95_LATENCY_LIMIT_MS = 25.0


def _load_corpus(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def _load_benign(path: Path) -> list[dict]:
    """Load benign eval samples as dicts (preserves content_type for source_path inference)."""
    with open(path) as f:
        data = json.load(f)
    if not data:
        return []
    # Normalize to list of dicts with at least 'text' and 'content_type'.
    if isinstance(data[0], str):
        return [{"text": t, "content_type": "readme"} for t in data]
    return list(data)


# Map content_type to plausible source paths for Tier 0 mode detection.
# Mirrors the logic in multitier_benchmark.py.
_CONTENT_TYPE_PATHS: dict[str, str] = {
    "agent_instructions": "CLAUDE.md",
    "readme": "README.md",
    "config": "package.json",
    "workflow": ".github/workflows/ci.yml",
    "test_file": "tests/test_main.py",
    "env_config": ".env.example",
    "security_doc": "SECURITY.md",
    "build_script": "Makefile",
}


def _make_tier0_engine():
    """Create a PatternEngine instance (reuse across samples for speed)."""
    from cloneguard.patterns import PatternEngine

    return PatternEngine()


def _tier0_scan(engine, text: str, source_path: str = "CLAUDE.md") -> tuple[bool, str | None]:
    """Run Tier 0 (regex) detection. Returns (detected, severity)."""
    from cloneguard.patterns import Severity

    result = engine.scan(text, source_path=source_path)
    if not result.matches:
        return False, None
    severities = [m.severity for m in result.matches]
    if Severity.CRITICAL in severities:
        return True, "critical"
    if Severity.HIGH in severities:
        return True, "high"
    if Severity.MEDIUM in severities:
        return True, "medium"
    return True, "low"


def _tier15_classify(classifier, text: str) -> tuple[str, float, float, bool]:
    """Run Tier 1.5 classification.

    Returns (verdict, confidence, anomaly_score, anomaly_flagged).
    """
    result = classifier.classify(text)
    return result.verdict, result.confidence, result.anomaly_score, result.anomaly_flagged


def _combined_verdict(
    tier0_detected: bool,
    tier15_verdict: str,
    anomaly_flagged: bool,
) -> str:
    """Combined pipeline verdict. Returns 'FLAGGED' or 'CLEAN'."""
    if tier0_detected:
        return "FLAGGED"
    if tier15_verdict in ("MALICIOUS", "SUSPICIOUS"):
        return "FLAGGED"
    return "CLEAN"


def _run_latency_measurement(classifier, n_warmup: int = 5, n_measure: int = 50) -> dict:
    """Measure end-to-end Tier 1.5 + Mahalanobis latency."""
    test_text = (
        "This is a test prompt for latency measurement. "
        "It contains enough content to exercise the full tokenization and inference pipeline "
        "including Mahalanobis anomaly scoring on the CLS embedding."
    )

    # Warmup.
    for _ in range(n_warmup):
        classifier.classify(test_text)

    # Measure.
    durations_ms: list[float] = []
    for _ in range(n_measure):
        t0 = time.perf_counter()
        classifier.classify(test_text)
        t1 = time.perf_counter()
        durations_ms.append((t1 - t0) * 1000.0)

    p50 = float(np.percentile(durations_ms, 50))
    p95 = float(np.percentile(durations_ms, 95))
    gate_pass = p95 <= _P95_LATENCY_LIMIT_MS

    return {
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "gate_pass": gate_pass,
        "n_warmup": n_warmup,
        "n_measure": n_measure,
        "note": (
            f"PASS: p95={p95:.1f}ms < {_P95_LATENCY_LIMIT_MS}ms"
            if gate_pass
            else f"FAIL: p95={p95:.1f}ms exceeds {_P95_LATENCY_LIMIT_MS}ms"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Hardened pipeline benchmark")
    parser.add_argument(
        "--malicious",
        type=Path,
        default=_ROOT / "data/benchmark/malicious_corpus.json",
    )
    parser.add_argument(
        "--benign",
        type=Path,
        default=_ROOT / "data/benchmark/benign_eval_751.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_ROOT / "docs/results/hardened-benchmark-2026-03-10.json",
    )
    args = parser.parse_args()

    if not args.malicious.exists():
        print(f"ERROR: malicious corpus not found: {args.malicious}", file=sys.stderr)
        sys.exit(1)
    if not args.benign.exists():
        print(f"ERROR: benign eval not found: {args.benign}", file=sys.stderr)
        sys.exit(1)

    print("\nHardened pipeline benchmark (v4 ONNX + Mahalanobis)")
    print(f"  Malicious corpus: {args.malicious}")
    print(f"  Benign eval:      {args.benign}")
    print(f"  Output:           {args.output}")

    # Load Tier 1.5 classifier (with Mahalanobis if available).
    from cloneguard.mini_semantic import MiniSemanticClassifier

    classifier = MiniSemanticClassifier()
    if not classifier.available:
        print("ERROR: MiniSemanticClassifier not available", file=sys.stderr)
        sys.exit(1)

    mahal_available = classifier._mahalanobis is not None
    print(f"\n  Mahalanobis detector: {'LOADED' if mahal_available else 'NOT LOADED'}")
    if mahal_available:
        print(f"  Mahalanobis threshold: {classifier._mahalanobis.threshold:.4f}")

    # Create shared Tier 0 engine (reuse across samples).
    engine = _make_tier0_engine()

    # --- Malicious corpus evaluation ---
    print("\n[1/3] Evaluating malicious corpus...")
    malicious_samples = _load_corpus(args.malicious)
    n_mal = len(malicious_samples)

    per_category: dict[str, dict] = {}
    total_flagged = 0
    total_tier0 = 0
    total_tier15 = 0
    total_mahal_flagged = 0
    total_mahal_anomalous_score: list[float] = []

    for sample in malicious_samples:
        # Corpus uses 'payload' key; fall back to 'text' for compatibility.
        text = sample.get("payload", sample.get("text", ""))
        category = sample.get("category", "unknown")

        tier0_detected, _ = _tier0_scan(engine, text)
        tier15_verdict, conf, anomaly_score, anomaly_flagged = _tier15_classify(classifier, text)
        combined = _combined_verdict(tier0_detected, tier15_verdict, anomaly_flagged)

        if category not in per_category:
            per_category[category] = {"total": 0, "flagged": 0, "tier0": 0, "tier15": 0, "mahal": 0}
        per_category[category]["total"] += 1
        if combined == "FLAGGED":
            per_category[category]["flagged"] += 1
            total_flagged += 1
        if tier0_detected:
            per_category[category]["tier0"] += 1
            total_tier0 += 1
        if tier15_verdict in ("MALICIOUS", "SUSPICIOUS"):
            per_category[category]["tier15"] += 1
            total_tier15 += 1
        if anomaly_flagged:
            per_category[category]["mahal"] += 1
            total_mahal_flagged += 1
        if anomaly_score > 0:
            total_mahal_anomalous_score.append(anomaly_score)

    recall_overall = total_flagged / n_mal if n_mal > 0 else 0.0
    recall_per_category = {
        cat: round(d["flagged"] / d["total"], 4) if d["total"] > 0 else 0.0
        for cat, d in per_category.items()
    }

    # Vocabulary-attack categories (PWWS/synonym attacks).
    vocab_cats = {"synonym_substitution", "social_engineering", "counter_defensive"}
    vocab_total = sum(d["total"] for c, d in per_category.items() if c in vocab_cats)
    vocab_flagged = sum(d["flagged"] for c, d in per_category.items() if c in vocab_cats)
    asr_vocab = 1.0 - (vocab_flagged / vocab_total) if vocab_total > 0 else 0.0
    asr_all = 1.0 - recall_overall

    mahal_detection_rate = total_mahal_flagged / n_mal if n_mal > 0 else 0.0

    print(f"  {n_mal} samples | overall recall: {recall_overall:.1%}")
    print(f"  Tier 0: {total_tier0 / n_mal:.1%} | Tier 1.5: {total_tier15 / n_mal:.1%}")
    print(f"  Mahalanobis flagged: {total_mahal_flagged}/{n_mal} ({mahal_detection_rate:.1%})")

    # --- Benign eval evaluation ---
    print("\n[2/3] Evaluating benign eval set...")
    benign_texts = _load_benign(args.benign)
    n_ben = len(benign_texts)

    benign_flagged = 0
    benign_mahal_flagged = 0
    benign_tier0_flagged = 0
    benign_tier15_flagged = 0

    for sample in benign_texts:
        text = sample.get("text", sample) if isinstance(sample, dict) else sample
        content_type = (
            sample.get("content_type", "readme") if isinstance(sample, dict) else "readme"
        )
        source_path = _CONTENT_TYPE_PATHS.get(content_type, "README.md")

        tier0_detected, _ = _tier0_scan(engine, text, source_path=source_path)
        tier15_verdict, conf, anomaly_score, anomaly_flagged = _tier15_classify(classifier, text)
        combined = _combined_verdict(tier0_detected, tier15_verdict, anomaly_flagged)

        if combined == "FLAGGED":
            benign_flagged += 1
        if tier0_detected:
            benign_tier0_flagged += 1
        if tier15_verdict in ("MALICIOUS", "SUSPICIOUS"):
            benign_tier15_flagged += 1
        if anomaly_flagged:
            benign_mahal_flagged += 1

    fpr_overall = benign_flagged / n_ben if n_ben > 0 else 0.0
    fpr_tier0 = benign_tier0_flagged / n_ben if n_ben > 0 else 0.0
    fpr_tier15 = benign_tier15_flagged / n_ben if n_ben > 0 else 0.0
    mahal_fpr = benign_mahal_flagged / n_ben if n_ben > 0 else 0.0

    print(f"  {n_ben} samples | overall FPR: {fpr_overall:.1%}")
    print(f"  Tier 0 FPR: {fpr_tier0:.1%} | Tier 1.5 FPR: {fpr_tier15:.1%}")
    print(f"  Mahalanobis FPR: {benign_mahal_flagged}/{n_ben} ({mahal_fpr:.1%})")

    # --- Latency measurement ---
    print("\n[3/3] Measuring latency (Tier 1.5 + Mahalanobis)...")
    latency = _run_latency_measurement(classifier)
    print(f"  p50={latency['p50_ms']:.2f}ms, p95={latency['p95_ms']:.2f}ms | {latency['note']}")

    # --- Compute deltas from v3 baseline ---
    # Note: fpr_change comparison is approximate (different benign eval sets).
    # tier15_fpr_change is more apples-to-apples (same Tier 1.5 logic, different corpus).
    delta_from_v3 = {
        "recall_change": round(recall_overall - _V3_RECALL, 4),
        "fpr_change": round(fpr_overall - _V3_FPR, 4),
        "tier15_fpr_change": round(fpr_tier15 - _V3_TIER15_FPR, 4),
        "asr_change": round(asr_all - _V3_ASR, 4),
        "v3_recall": _V3_RECALL,
        "v3_fpr": _V3_FPR,
        "v3_tier15_fpr": _V3_TIER15_FPR,
        "v3_asr": _V3_ASR,
        "note": (
            "fpr_change uses different benign eval sets (757-sample v4 vs 234-sample v3); "
            "tier15_fpr_change is more comparable"
        ),
    }

    # --- Assemble output ---
    results = {
        "date": "2026-03-10",
        "model_version": "v4",
        "training": {
            "rounds": 2,
            "freelb": True,
            "augmented_samples": 6472,
            "pwws_r1": 88,
            "pwws_r2": 44,
        },
        "recall": {
            "overall": round(recall_overall, 4),
            "per_category": recall_per_category,
            "tier0_contribution": round(total_tier0 / n_mal, 4),
            "tier15_contribution": round(total_tier15 / n_mal, 4),
        },
        "fpr": {
            "overall": round(fpr_overall, 4),
            "tier0": round(fpr_tier0, 4),
            "tier15": round(fpr_tier15, 4),
        },
        "mahalanobis": {
            "detection_rate": round(mahal_detection_rate, 4),
            "fpr": round(mahal_fpr, 4),
            "threshold": round(classifier._mahalanobis.threshold, 4) if mahal_available else 0.0,
            "available": mahal_available,
            "note": (
                f"Detection rate {mahal_detection_rate:.1%} on adversarial corpus; "
                f"FPR {mahal_fpr:.1%} on benign eval"
            ),
        },
        "asr": {
            "all_categories": round(asr_all, 4),
            "vocabulary_attacks": round(asr_vocab, 4),
        },
        "latency": latency,
        "delta_from_v3": delta_from_v3,
        "sample_counts": {
            "malicious": n_mal,
            "benign": n_ben,
        },
    }

    # Write output.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary.
    rc_delta = delta_from_v3["recall_change"]
    fp_delta = delta_from_v3["fpr_change"]
    asr_delta = delta_from_v3["asr_change"]
    lat_gate = "PASS" if latency["gate_pass"] else "FAIL"

    print("\n=== Hardened Pipeline Benchmark Summary ===")
    print(
        f"  Recall:           {recall_overall:.1%} (v3: {_V3_RECALL:.1%}, delta: {rc_delta:+.1%})"
    )
    print(f"  FPR:              {fpr_overall:.1%}  (v3: {_V3_FPR:.1%},  delta: {fp_delta:+.1%})")
    print(f"  ASR (all):        {asr_all:.1%}  (v3: {_V3_ASR:.1%},  delta: {asr_delta:+.1%})")
    print(f"  ASR (vocab):      {asr_vocab:.1%}")
    print(f"  Mahal detection:  {mahal_detection_rate:.1%}")
    print(f"  Mahal FPR:        {mahal_fpr:.1%}")
    print(
        f"  Latency p95:      {latency['p95_ms']:.2f}ms ({lat_gate} <= {_P95_LATENCY_LIMIT_MS}ms)"
    )
    print(f"\n  Results written to: {args.output}")

    gate_result = (
        "PASS"
        if latency["gate_pass"]
        else (f"FAIL (p95={latency['p95_ms']:.1f}ms > {_P95_LATENCY_LIMIT_MS}ms)")
    )
    print(f"\nHARD-05 LATENCY GATE: {gate_result}")


if __name__ == "__main__":
    main()
