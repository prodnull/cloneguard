#!/usr/bin/env python3
"""Adversarial robustness benchmark for CloneGuard's Tier 1.5 ONNX classifier.

Measures the operating envelope: per-category recall, per-scan-mode FPR,
and threshold sensitivity across adversarial and benign corpora.

Three phases:
  1. Score all samples (raw malicious_prob via ONNX)
  2. Threshold sweep (precision/recall/F1/FPR per scan mode at each threshold)
  3. Breakdown reports (per-category recall, per-content-type FPR, worst evasions)

Usage:
  python scripts/adversarial_benchmark.py
  python scripts/adversarial_benchmark.py \
    --compare docs/results/adversarial-benchmark-2026-03-09.json
  python scripts/adversarial_benchmark.py --sweep-only scores.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

sys.path.insert(0, "src")

MALICIOUS_CORPUS = Path("data/benchmark/malicious_corpus.json")
BENIGN_CORPUS = Path("data/benchmark/benign_corpus.json")
RESULTS_DIR = Path("docs/results")

THRESHOLDS = [round(0.50 + i * 0.05, 2) for i in range(10)]  # 0.50 .. 0.95
CURRENT_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScoredMalicious:
    id: str
    category: str
    payload: str
    malicious_prob: float
    difficulty: str
    base_attack: str


@dataclass
class ScoredBenign:
    id: str
    content_type: str
    scan_mode: str
    text: str
    malicious_prob: float
    provenance: str


# ---------------------------------------------------------------------------
# Raw scoring — bypasses classify() to get the probability directly
# ---------------------------------------------------------------------------


def _score_raw(classifier: object, text: str) -> float:
    """Run ONNX inference and return raw malicious probability.

    Bypasses classify() thresholds and sliding window to get the unmodified
    softmax output for a single 256-token window. This is intentional: the
    benchmark must measure the model's raw discriminative ability, not the
    post-hoc decision logic.
    """
    import numpy as np

    tokenizer = classifier._tokenizer  # type: ignore[attr-defined]
    session = classifier._session  # type: ignore[attr-defined]

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

    probs = np.exp(logits) / np.exp(logits).sum()
    return float(probs[1])


def _score_production(classifier: object, text: str) -> float:
    """Score using the production classify() path including sliding window.

    Returns the effective malicious probability that the production system
    would use for its decision. For short inputs this matches _score_raw().
    For long inputs the sliding window may produce a higher score.
    """
    result = classifier.classify(text)  # type: ignore[attr-defined]
    # classify() returns MiniClassification where:
    #   MALICIOUS/SUSPICIOUS: confidence = malicious_prob
    #   SAFE: confidence = 1.0 - malicious_prob
    if result.verdict == "SAFE":
        return 1.0 - result.confidence
    else:
        return result.confidence


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def load_malicious_corpus() -> list[dict]:
    if not MALICIOUS_CORPUS.exists():
        print(f"ERROR: Malicious corpus not found at {MALICIOUS_CORPUS}", file=sys.stderr)
        print(
            "Run scripts/build_malicious_corpus.py first, or create the file manually.",
            file=sys.stderr,
        )
        sys.exit(1)
    data = json.loads(MALICIOUS_CORPUS.read_text())
    if isinstance(data, dict):
        # Allow top-level wrapper: {"samples": [...]}
        data = data.get("samples", data.get("payloads", []))
    print(f"Loaded {len(data)} malicious samples from {MALICIOUS_CORPUS}")
    return data


def load_benign_corpus() -> list[dict]:
    if not BENIGN_CORPUS.exists():
        print(f"ERROR: Benign corpus not found at {BENIGN_CORPUS}", file=sys.stderr)
        print(
            "Run scripts/build_benign_corpus.py first, or create the file manually.",
            file=sys.stderr,
        )
        sys.exit(1)
    data = json.loads(BENIGN_CORPUS.read_text())
    if isinstance(data, dict):
        data = data.get("samples", data.get("content", []))
    print(f"Loaded {len(data)} benign samples from {BENIGN_CORPUS}")
    return data


def check_allowlist_status() -> None:
    """Warn if the malicious corpus is not in the CloneGuard allowlist."""
    try:
        from cloneguard.allowlist import Allowlist

        al = Allowlist()
        content = MALICIOUS_CORPUS.read_bytes()
        if not al.is_allowed(content):
            print(
                "WARNING: malicious_corpus.json is NOT in the allowlist. "
                "It will trigger self-detection during repo scans.",
                file=sys.stderr,
            )
            print(
                '  Fix: cloneguard allow data/benchmark/malicious_corpus.json '
                '--reason "Adversarial benchmark corpus"',
                file=sys.stderr,
            )
    except Exception:
        # Allowlist check is advisory; don't block the benchmark.
        pass


# ---------------------------------------------------------------------------
# Phase 1: Score all samples
# ---------------------------------------------------------------------------


def score_all_samples(
    malicious_data: list[dict],
    benign_data: list[dict],
    production_mode: bool = False,
) -> tuple[list[ScoredMalicious], list[ScoredBenign]]:
    """Score every sample through the ONNX classifier, returning raw probabilities.

    If production_mode is True, uses classify() with sliding window instead of
    raw single-window scoring. This measures production behavior including
    truncation evasion defense.
    """
    from cloneguard.mini_semantic import MiniSemanticClassifier

    classifier = MiniSemanticClassifier()
    if not classifier.available:
        print("ERROR: Tier 1.5 ONNX model is not available.", file=sys.stderr)
        sys.exit(1)

    score_fn = _score_production if production_mode else _score_raw
    mode_label = "production (sliding window)" if production_mode else "raw (single window)"
    print(f"Scoring mode: {mode_label}")

    scored_mal: list[ScoredMalicious] = []
    scored_ben: list[ScoredBenign] = []

    print(f"\nScoring {len(malicious_data)} malicious samples...")
    t0 = time.perf_counter()
    for i, sample in enumerate(malicious_data):
        text = sample.get("payload", sample.get("text", ""))
        prob = score_fn(classifier, text)
        scored_mal.append(
            ScoredMalicious(
                id=sample.get("id", f"mal-{i:04d}"),
                category=sample.get("category", "unknown"),
                payload=text,
                malicious_prob=prob,
                difficulty=sample.get("difficulty", "unknown"),
                base_attack=sample.get("base_attack", ""),
            )
        )
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(malicious_data)}", file=sys.stderr)
    mal_elapsed = time.perf_counter() - t0

    print(f"Scoring {len(benign_data)} benign samples...")
    t1 = time.perf_counter()
    for i, sample in enumerate(benign_data):
        text = sample.get("text", sample.get("content", ""))
        prob = score_fn(classifier, text)
        scored_ben.append(
            ScoredBenign(
                id=sample.get("id", f"ben-{i:04d}"),
                content_type=sample.get("content_type", "unknown"),
                scan_mode=sample.get("scan_mode", "STANDARD"),
                text=text,
                malicious_prob=prob,
                provenance=sample.get("provenance", "unknown"),
            )
        )
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(benign_data)}", file=sys.stderr)
    ben_elapsed = time.perf_counter() - t1

    total = len(scored_mal) + len(scored_ben)
    total_elapsed = mal_elapsed + ben_elapsed
    print(
        f"Scored {total} samples in {total_elapsed:.1f}s "
        f"({total_elapsed * 1000 / max(total, 1):.1f}ms/sample)"
    )
    return scored_mal, scored_ben


def save_scores(
    scored_mal: list[ScoredMalicious], scored_ben: list[ScoredBenign], path: Path
) -> None:
    """Cache raw scores to JSON for --sweep-only reuse."""
    obj = {
        "malicious": [
            {
                "id": s.id,
                "category": s.category,
                "malicious_prob": s.malicious_prob,
                "difficulty": s.difficulty,
                "base_attack": s.base_attack,
                "payload_preview": s.payload[:200],
            }
            for s in scored_mal
        ],
        "benign": [
            {
                "id": s.id,
                "content_type": s.content_type,
                "scan_mode": s.scan_mode,
                "malicious_prob": s.malicious_prob,
                "provenance": s.provenance,
                "text_preview": s.text[:200],
            }
            for s in scored_ben
        ],
    }
    path.write_text(json.dumps(obj, indent=2))
    print(f"Scores cached to {path}")


def load_scores(path: Path) -> tuple[list[ScoredMalicious], list[ScoredBenign]]:
    """Load cached scores from JSON."""
    obj = json.loads(path.read_text())
    scored_mal = [
        ScoredMalicious(
            id=s["id"],
            category=s["category"],
            payload=s.get("payload_preview", ""),
            malicious_prob=s["malicious_prob"],
            difficulty=s.get("difficulty", "unknown"),
            base_attack=s.get("base_attack", ""),
        )
        for s in obj["malicious"]
    ]
    scored_ben = [
        ScoredBenign(
            id=s["id"],
            content_type=s["content_type"],
            scan_mode=s["scan_mode"],
            text=s.get("text_preview", ""),
            malicious_prob=s["malicious_prob"],
            provenance=s.get("provenance", "unknown"),
        )
        for s in obj["benign"]
    ]
    print(f"Loaded cached scores: {len(scored_mal)} malicious, {len(scored_ben)} benign")
    return scored_mal, scored_ben


# ---------------------------------------------------------------------------
# Phase 2: Threshold sweep
# ---------------------------------------------------------------------------


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    """Compute classification metrics. Mirrors benchmark_tiers.compute_metrics."""
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
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def threshold_sweep(
    scored_mal: list[ScoredMalicious],
    scored_ben: list[ScoredBenign],
) -> tuple[dict, dict[str, tuple[float, float]]]:
    """Sweep thresholds and compute metrics per scan mode at each threshold.

    Returns a dict keyed by threshold string, each containing per-mode metrics.
    """
    scan_modes = ["STRICT", "STANDARD", "LENIENT"]
    results: dict[str, dict] = {}
    best_f1: dict[str, tuple[float, float]] = {m: (0.0, 0.5) for m in scan_modes}

    for threshold in THRESHOLDS:
        thr_key = f"{threshold:.2f}"
        results[thr_key] = {}

        for mode in scan_modes:
            # Malicious samples: test against all modes (attacker doesn't choose mode)
            y_true: list[int] = []
            y_pred: list[int] = []

            for s in scored_mal:
                y_true.append(1)
                y_pred.append(1 if s.malicious_prob > threshold else 0)

            # Benign samples: only those matching this scan mode
            mode_benign = [s for s in scored_ben if s.scan_mode == mode]
            for s in mode_benign:
                y_true.append(0)
                y_pred.append(1 if s.malicious_prob > threshold else 0)

            metrics = compute_metrics(y_true, y_pred)
            results[thr_key][mode] = metrics

            if metrics["f1"] > best_f1[mode][0]:
                best_f1[mode] = (metrics["f1"], threshold)

    return results, best_f1  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Phase 3: Breakdown reports
# ---------------------------------------------------------------------------


def per_category_recall(
    scored_mal: list[ScoredMalicious],
) -> dict:
    """Compute recall per adversarial category at each threshold."""
    categories: dict[str, list[float]] = {}
    for s in scored_mal:
        categories.setdefault(s.category, []).append(s.malicious_prob)

    result: dict[str, dict] = {}
    for cat, probs in sorted(categories.items()):
        total = len(probs)
        cat_result: dict[str, object] = {"total": total}
        for threshold in THRESHOLDS:
            detected = sum(1 for p in probs if p > threshold)
            recall = detected / max(total, 1)
            cat_result[f"{threshold:.2f}"] = {
                "detected": detected,
                "recall": round(recall, 4),
            }
        result[cat] = cat_result

    return result


def per_content_type_fpr(
    scored_ben: list[ScoredBenign],
) -> dict:
    """Compute FPR per content type at each threshold."""
    types: dict[str, list[ScoredBenign]] = {}
    for s in scored_ben:
        types.setdefault(s.content_type, []).append(s)

    result: dict[str, dict] = {}
    for ct, samples in sorted(types.items()):
        total = len(samples)
        real_count = sum(1 for s in samples if s.provenance == "real")
        synthetic_count = total - real_count
        ct_result: dict[str, object] = {
            "total": total,
            "real": real_count,
            "synthetic": synthetic_count,
        }
        for threshold in THRESHOLDS:
            fps = sum(1 for s in samples if s.malicious_prob > threshold)
            fpr_val = fps / max(total, 1)
            ct_result[f"{threshold:.2f}"] = {
                "false_positives": fps,
                "fpr": round(fpr_val, 4),
            }
        result[ct] = ct_result

    return result


def worst_evasions(scored_mal: list[ScoredMalicious], top_n: int = 10) -> list[dict]:
    """Top N malicious samples with the lowest malicious_prob (most likely to evade)."""
    ranked = sorted(scored_mal, key=lambda s: s.malicious_prob)
    return [
        {
            "id": s.id,
            "category": s.category,
            "malicious_prob": round(s.malicious_prob, 4),
            "difficulty": s.difficulty,
            "text_preview": s.payload[:120],
        }
        for s in ranked[:top_n]
    ]


def compute_delta(
    current_report: dict, previous_path: Path
) -> dict | None:
    """Compare current report against a previous benchmark JSON."""
    if not previous_path.exists():
        print(f"WARNING: Previous report not found at {previous_path}", file=sys.stderr)
        return None

    prev = json.loads(previous_path.read_text())
    delta: dict = {"category_recall": {}, "content_type_fpr": {}}

    # Per-category recall delta at current threshold
    thr_key = f"{CURRENT_THRESHOLD:.2f}"
    cur_cats = current_report.get("per_category_recall", {})
    prev_cats = prev.get("per_category_recall", {})
    for cat in set(cur_cats) | set(prev_cats):
        cur_recall = cur_cats.get(cat, {}).get(thr_key, {}).get("recall", 0.0)
        prev_recall = prev_cats.get(cat, {}).get(thr_key, {}).get("recall", 0.0)
        delta["category_recall"][cat] = {
            "current": cur_recall,
            "previous": prev_recall,
            "change": round(cur_recall - prev_recall, 4),
        }

    # Per-content-type FPR delta at current threshold
    cur_types = current_report.get("per_content_type_fpr", {})
    prev_types = prev.get("per_content_type_fpr", {})
    for ct in set(cur_types) | set(prev_types):
        cur_fpr = cur_types.get(ct, {}).get(thr_key, {}).get("fpr", 0.0)
        prev_fpr = prev_types.get(ct, {}).get(thr_key, {}).get("fpr", 0.0)
        delta["content_type_fpr"][ct] = {
            "current": cur_fpr,
            "previous": prev_fpr,
            "change": round(cur_fpr - prev_fpr, 4),
        }

    return delta


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def print_markdown_summary(
    report: dict,
    best_f1: dict[str, tuple[float, float]],
    delta: dict | None = None,
) -> None:
    """Print a clean markdown summary table to stdout."""
    meta = report["meta"]
    print(f"\n# Adversarial Benchmark Results — {meta['date']}")
    print(f"\nModel: `{meta['model_version']}` | "
          f"Malicious: {meta['corpus_malicious_count']} | "
          f"Benign: {meta['corpus_benign_count']}")

    # Optimal thresholds
    print("\n## Optimal Thresholds (max F1 per scan mode)\n")
    print("| Scan Mode | Threshold | F1    |")
    print("|-----------|-----------|-------|")
    for mode in ["STRICT", "STANDARD", "LENIENT"]:
        f1_val, thr = best_f1[mode]
        print(f"| {mode:<9} | {thr:.2f}      | {f1_val:.4f} |")

    # Threshold sweep at current threshold
    thr_key = f"{CURRENT_THRESHOLD:.2f}"
    sweep = report["threshold_sweep"].get(thr_key, {})
    if sweep:
        print(f"\n## Metrics at Current Threshold ({thr_key})\n")
        print("| Scan Mode | Precision | Recall | F1     | FPR    | TP  | FP  | TN  | FN  |")
        print("|-----------|-----------|--------|--------|--------|-----|-----|-----|-----|")
        for mode in ["STRICT", "STANDARD", "LENIENT"]:
            m = sweep.get(mode, {})
            if m:
                print(
                    f"| {mode:<9} | {m['precision']:.4f}    | "
                    f"{m['recall']:.4f} | {m['f1']:.4f} | "
                    f"{m['fpr']:.4f} | "
                    f"{m['tp']:<3} | {m['fp']:<3} | {m['tn']:<3} | {m['fn']:<3} |"
                )

    # Per-category recall at current threshold
    cats = report.get("per_category_recall", {})
    if cats:
        print(f"\n## Per-Category Recall at Threshold {thr_key}\n")
        print("| Category                    | Total | Detected | Recall |")
        print("|-----------------------------|-------|----------|--------|")
        for cat, info in sorted(cats.items()):
            thr_info = info.get(thr_key, {})
            det = thr_info.get("detected", 0)
            rec = thr_info.get("recall", 0.0)
            print(f"| {cat:<27} | {info['total']:>5} | {det:>8} | {rec:.4f} |")

    # Per-content-type FPR at current threshold
    types = report.get("per_content_type_fpr", {})
    if types:
        print(f"\n## Per-Content-Type FPR at Threshold {thr_key}\n")
        print("| Content Type          | Total | Real | Synth | FPs | FPR    |")
        print("|-----------------------|-------|------|-------|-----|--------|")
        for ct, info in sorted(types.items()):
            thr_info = info.get(thr_key, {})
            fps = thr_info.get("false_positives", 0)
            fpr_val = thr_info.get("fpr", 0.0)
            print(
                f"| {ct:<21} | {info['total']:>5} | "
                f"{info['real']:>4} | {info['synthetic']:>5} | "
                f"{fps:>3} | {fpr_val:.4f} |"
            )

    # Worst evasions
    evasions = report.get("worst_evasions", [])
    if evasions:
        print("\n## Worst Evasions (lowest malicious_prob)\n")
        print("| # | ID                | Category              | Prob   | Preview              |")
        print("|---|-------------------|-----------------------|--------|----------------------|")
        for i, e in enumerate(evasions, 1):
            preview = e["text_preview"][:40].replace("|", "\\|")
            print(
                f"| {i} | {e['id']:<17} | {e['category']:<21} | "
                f"{e['malicious_prob']:.4f} | {preview:<20} |"
            )

    # Delta report
    if delta:
        print("\n## Delta vs. Previous Benchmark\n")
        cat_delta = delta.get("category_recall", {})
        if cat_delta:
            print("### Category Recall Changes\n")
            print("| Category                    | Previous | Current | Change |")
            print("|-----------------------------|----------|---------|--------|")
            for cat, d in sorted(cat_delta.items()):
                sign = "+" if d["change"] >= 0 else ""
                print(
                    f"| {cat:<27} | {d['previous']:.4f}   | "
                    f"{d['current']:.4f}  | {sign}{d['change']:.4f} |"
                )

        fpr_delta = delta.get("content_type_fpr", {})
        if fpr_delta:
            print("\n### Content-Type FPR Changes\n")
            print("| Content Type          | Previous | Current | Change |")
            print("|-----------------------|----------|---------|--------|")
            for ct, d in sorted(fpr_delta.items()):
                sign = "+" if d["change"] >= 0 else ""
                print(
                    f"| {ct:<21} | {d['previous']:.4f}   | "
                    f"{d['current']:.4f}  | {sign}{d['change']:.4f} |"
                )

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Adversarial robustness benchmark for CloneGuard Tier 1.5 ONNX classifier",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        default=None,
        help="Path to previous benchmark JSON for delta comparison",
    )
    parser.add_argument(
        "--sweep-only",
        type=Path,
        default=None,
        help="Skip scoring; load cached scores from JSON and run sweep + reports only",
    )
    parser.add_argument(
        "--save-scores",
        type=Path,
        default=None,
        help="Save raw scores to JSON for later --sweep-only reuse",
    )
    parser.add_argument(
        "--eval-corpus",
        type=Path,
        default=None,
        help="Path to held-out benign eval corpus (avoids data leakage from training)",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Use production classify() path with sliding window instead of raw scoring",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Phase 1: Score all samples (or load cached)
    # -----------------------------------------------------------------------

    if args.sweep_only:
        scored_mal, scored_ben = load_scores(args.sweep_only)
    else:
        malicious_data = load_malicious_corpus()
        if args.eval_corpus:
            benign_data = json.loads(args.eval_corpus.read_text())
            if isinstance(benign_data, dict):
                benign_data = benign_data.get("samples", benign_data.get("content", []))
            print(f"Loaded {len(benign_data)} benign samples from {args.eval_corpus} (held-out eval set)")
        else:
            benign_data = load_benign_corpus()
        check_allowlist_status()
        scored_mal, scored_ben = score_all_samples(
            malicious_data, benign_data, production_mode=args.production
        )

        if args.save_scores:
            save_scores(scored_mal, scored_ben, args.save_scores)

    # -----------------------------------------------------------------------
    # Phase 2: Threshold sweep
    # -----------------------------------------------------------------------

    print("\nRunning threshold sweep...")
    sweep_results, best_f1 = threshold_sweep(scored_mal, scored_ben)

    # -----------------------------------------------------------------------
    # Phase 3: Breakdown reports
    # -----------------------------------------------------------------------

    print("Computing per-category recall...")
    cat_recall = per_category_recall(scored_mal)

    print("Computing per-content-type FPR...")
    ct_fpr = per_content_type_fpr(scored_ben)

    print("Identifying worst evasions...")
    evasions = worst_evasions(scored_mal)

    # -----------------------------------------------------------------------
    # Assemble report
    # -----------------------------------------------------------------------

    today = date.today().isoformat()
    report: dict = {
        "meta": {
            "date": today,
            "model_version": "v2-minilm-l6-128h",
            "corpus_malicious_count": len(scored_mal),
            "corpus_benign_count": len(scored_ben),
            "current_threshold": CURRENT_THRESHOLD,
            "thresholds_swept": THRESHOLDS,
            "optimal_thresholds": {
                mode: {"threshold": thr, "f1": round(f1, 4)}
                for mode, (f1, thr) in best_f1.items()
            },
        },
        "threshold_sweep": sweep_results,
        "per_category_recall": cat_recall,
        "per_content_type_fpr": ct_fpr,
        "worst_evasions": evasions,
    }

    # Delta comparison
    delta = None
    if args.compare:
        delta = compute_delta(report, args.compare)
        if delta:
            report["delta"] = delta

    # -----------------------------------------------------------------------
    # Write JSON report
    # -----------------------------------------------------------------------

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = RESULTS_DIR / f"adversarial-benchmark-{today}.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nJSON report written to {report_path}")

    # -----------------------------------------------------------------------
    # Stdout markdown summary
    # -----------------------------------------------------------------------

    print_markdown_summary(report, best_f1, delta)


if __name__ == "__main__":
    main()
