#!/usr/bin/env python3
"""Multi-tier pipeline benchmark for CloneGuard.

Measures the combined detection pipeline (Tier 0 regex + Tier 1.5 ONNX) on
adversarial and benign corpora, showing what each tier catches independently
and what the combined system achieves.

Key metrics:
  - Per-tier detection (what each tier catches alone)
  - Combined detection (union of both tiers)
  - FPR by production severity (BLOCKED vs WARNING vs CLEAN)
  - Per-category contribution analysis (which tier covers which attack type)

Usage:
  python scripts/multitier_benchmark.py
  python scripts/multitier_benchmark.py --eval-corpus data/benchmark/benign_corpus_eval.json
  python scripts/multitier_benchmark.py --production  # sliding window for Tier 1.5
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

# Production thresholds from mini_semantic.py
TIER15_MALICIOUS_THRESHOLD = 0.8
TIER15_SUSPICIOUS_THRESHOLD = 0.5


@dataclass
class TierResult:
    """Per-sample result from a single tier."""
    tier0_detected: bool  # Tier 0 regex matched
    tier0_severity: str | None  # "critical", "high", "medium", "low", None
    tier0_pattern_ids: list[str]
    tier15_malicious_prob: float  # Raw or production score
    tier15_verdict: str  # "MALICIOUS", "SUSPICIOUS", "SAFE"
    combined_status: str  # "BLOCKED", "WARNING", "CLEAN" (production logic)


@dataclass
class ScoredSample:
    """A scored sample with both tier results."""
    id: str
    text: str
    is_malicious: bool
    category: str  # attack category or content_type
    scan_mode: str  # STRICT, STANDARD, LENIENT
    tier: TierResult


def load_corpus(malicious_path: Path, benign_path: Path) -> tuple[list[dict], list[dict]]:
    mal_data = json.loads(malicious_path.read_text())
    if isinstance(mal_data, dict):
        mal_data = mal_data.get("samples", mal_data.get("payloads", []))

    ben_data = json.loads(benign_path.read_text())
    if isinstance(ben_data, dict):
        ben_data = ben_data.get("samples", ben_data.get("content", []))

    return mal_data, ben_data


def score_tier0(engine, text: str, source_path: str) -> tuple[bool, str | None, list[str]]:
    """Run Tier 0 regex on a sample. Returns (detected, max_severity, pattern_ids)."""
    result = engine.scan(text, source_path=source_path)
    if not result.matches:
        return False, None, []

    severity_order = ["critical", "high", "medium", "low"]
    max_sev = None
    for s in severity_order:
        if any(m.severity.value == s for m in result.matches):
            max_sev = s
            break

    pattern_ids = [m.pattern_id for m in result.matches]
    return True, max_sev, pattern_ids


def score_tier15_raw(classifier, text: str) -> float:
    """Raw ONNX inference — single 256-token window."""
    import numpy as np

    inputs = classifier._tokenizer(
        text, return_tensors="np", truncation=True, max_length=256, padding="max_length",
    )
    logits = classifier._session.run(
        None, {"input_ids": inputs["input_ids"], "attention_mask": inputs["attention_mask"]},
    )[0][0]
    probs = np.exp(logits) / np.exp(logits).sum()
    return float(probs[1])


def score_tier15_production(classifier, text: str) -> float:
    """Production classify() path with sliding window."""
    result = classifier.classify(text)
    if result.verdict == "SAFE":
        return 1.0 - result.confidence
    return result.confidence


def combined_status(
    tier0_detected: bool,
    tier0_severity: str | None,
    tier15_verdict: str,
    tier15_confidence: float,
    scan_mode: str,
) -> str:
    """Replicate production verdict merging logic from scanner.py.

    Rules:
      - Tier 0 CRITICAL → BLOCKED always
      - Tier 0 HIGH + STRICT mode → BLOCKED
      - Tier 0 HIGH + other modes → WARNING
      - Tier 0 MEDIUM/LOW → WARNING
      - Tier 0 CLEAN + Tier 1.5 MALICIOUS → WARNING (not BLOCKED by itself)
      - Tier 0 HIT + Tier 1.5 MALICIOUS (≥0.8) → BLOCKED
      - Tier 0 CLEAN + Tier 1.5 SAFE → CLEAN
    """
    if not tier0_detected and tier15_verdict == "SAFE":
        return "CLEAN"

    if tier0_detected:
        if tier0_severity == "critical":
            return "BLOCKED"
        if tier0_severity == "high" and scan_mode == "STRICT":
            return "BLOCKED"
        # Tier 0 hit + Tier 1.5 MALICIOUS with high confidence → BLOCKED
        if tier15_verdict == "MALICIOUS" and tier15_confidence >= 0.8:
            return "BLOCKED"
        return "WARNING"

    # Tier 0 clean but Tier 1.5 flagged
    if tier15_verdict in ("MALICIOUS", "SUSPICIOUS"):
        return "WARNING"

    return "CLEAN"


def score_all(
    mal_data: list[dict],
    ben_data: list[dict],
    production_mode: bool = False,
) -> list[ScoredSample]:
    from cloneguard.mini_semantic import MiniSemanticClassifier
    from cloneguard.patterns import PatternEngine

    engine = PatternEngine()
    classifier = MiniSemanticClassifier()
    assert classifier.available, "Tier 1.5 ONNX model required"

    score_fn = score_tier15_production if production_mode else score_tier15_raw
    mode_label = "production (sliding window)" if production_mode else "raw (single window)"
    print(f"Tier 1.5 scoring mode: {mode_label}")
    print(f"Tier 0 rules loaded: {len(engine.rules)}")

    results: list[ScoredSample] = []

    # Score malicious samples
    print(f"\nScoring {len(mal_data)} malicious samples...")
    t0 = time.perf_counter()
    for i, sample in enumerate(mal_data):
        text = sample.get("payload", sample.get("text", ""))
        category = sample.get("category", "unknown")

        # Tier 0: use a plausible source path for mode detection
        # Malicious payloads target agent configs → STRICT mode
        source_path = "CLAUDE.md"
        t0_detected, t0_sev, t0_pids = score_tier0(engine, text, source_path)

        # Tier 1.5
        t15_prob = score_fn(classifier, text)
        if t15_prob > TIER15_MALICIOUS_THRESHOLD:
            t15_verdict = "MALICIOUS"
        elif t15_prob > TIER15_SUSPICIOUS_THRESHOLD:
            t15_verdict = "SUSPICIOUS"
        else:
            t15_verdict = "SAFE"

        status = combined_status(t0_detected, t0_sev, t15_verdict, t15_prob, "STRICT")

        results.append(ScoredSample(
            id=sample.get("id", f"mal-{i:04d}"),
            text=text,
            is_malicious=True,
            category=category,
            scan_mode="STRICT",
            tier=TierResult(
                tier0_detected=t0_detected,
                tier0_severity=t0_sev,
                tier0_pattern_ids=t0_pids,
                tier15_malicious_prob=t15_prob,
                tier15_verdict=t15_verdict,
                combined_status=status,
            ),
        ))
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(mal_data)}", file=sys.stderr)

    mal_elapsed = time.perf_counter() - t0

    # Score benign samples
    print(f"Scoring {len(ben_data)} benign samples...")
    t1 = time.perf_counter()
    for i, sample in enumerate(ben_data):
        text = sample.get("text", sample.get("content", ""))
        content_type = sample.get("content_type", "unknown")
        scan_mode = sample.get("scan_mode", "STANDARD")

        # Use content_type to infer a plausible source path for Tier 0 mode detection
        source_paths = {
            "agent_instructions": "CLAUDE.md",
            "readme": "README.md",
            "config": "package.json",
            "workflow": ".github/workflows/ci.yml",
            "test_file": "tests/test_main.py",
            "env_config": ".env.example",
            "security_doc": "SECURITY.md",
            "build_script": "Makefile",
        }
        source_path = source_paths.get(content_type, "README.md")

        t0_detected, t0_sev, t0_pids = score_tier0(engine, text, source_path)
        t15_prob = score_fn(classifier, text)
        if t15_prob > TIER15_MALICIOUS_THRESHOLD:
            t15_verdict = "MALICIOUS"
        elif t15_prob > TIER15_SUSPICIOUS_THRESHOLD:
            t15_verdict = "SUSPICIOUS"
        else:
            t15_verdict = "SAFE"

        mode_lower = scan_mode.lower()
        # Map scan_mode to what PatternEngine would infer
        inferred_mode = engine._detect_mode(source_path).value.upper()
        status = combined_status(t0_detected, t0_sev, t15_verdict, t15_prob, inferred_mode)

        results.append(ScoredSample(
            id=sample.get("id", f"ben-{i:04d}"),
            text=text,
            is_malicious=False,
            category=content_type,
            scan_mode=scan_mode,
            tier=TierResult(
                tier0_detected=t0_detected,
                tier0_severity=t0_sev,
                tier0_pattern_ids=t0_pids,
                tier15_malicious_prob=t15_prob,
                tier15_verdict=t15_verdict,
                combined_status=status,
            ),
        ))
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(ben_data)}", file=sys.stderr)

    ben_elapsed = time.perf_counter() - t1
    total = len(results)
    total_elapsed = mal_elapsed + ben_elapsed
    print(f"Scored {total} samples in {total_elapsed:.1f}s "
          f"({total_elapsed * 1000 / max(total, 1):.1f}ms/sample)")
    return results


def analyze_recall(samples: list[ScoredSample]) -> dict:
    """Per-category recall analysis for malicious samples."""
    malicious = [s for s in samples if s.is_malicious]
    categories: dict[str, list[ScoredSample]] = {}
    for s in malicious:
        categories.setdefault(s.category, []).append(s)

    result: dict[str, dict] = {}
    for cat, cat_samples in sorted(categories.items()):
        total = len(cat_samples)
        tier0_caught = sum(1 for s in cat_samples if s.tier.tier0_detected)
        tier15_caught = sum(1 for s in cat_samples if s.tier.tier15_verdict != "SAFE")
        either_caught = sum(
            1 for s in cat_samples
            if s.tier.tier0_detected or s.tier.tier15_verdict != "SAFE"
        )
        both_caught = sum(
            1 for s in cat_samples
            if s.tier.tier0_detected and s.tier.tier15_verdict != "SAFE"
        )
        combined_blocked = sum(1 for s in cat_samples if s.tier.combined_status == "BLOCKED")
        combined_warning = sum(1 for s in cat_samples if s.tier.combined_status == "WARNING")
        combined_flagged = combined_blocked + combined_warning

        result[cat] = {
            "total": total,
            "tier0_recall": round(tier0_caught / max(total, 1), 4),
            "tier15_recall": round(tier15_caught / max(total, 1), 4),
            "union_recall": round(either_caught / max(total, 1), 4),
            "overlap": both_caught,
            "combined_blocked": combined_blocked,
            "combined_warned": combined_warning,
            "combined_clean": total - combined_flagged,
            "combined_detection_rate": round(combined_flagged / max(total, 1), 4),
        }
    return result


def analyze_fpr(samples: list[ScoredSample]) -> dict:
    """Per-content-type FPR analysis for benign samples, split by severity."""
    benign = [s for s in samples if not s.is_malicious]
    types: dict[str, list[ScoredSample]] = {}
    for s in benign:
        types.setdefault(s.category, []).append(s)

    result: dict[str, dict] = {}
    for ct, ct_samples in sorted(types.items()):
        total = len(ct_samples)
        tier0_fp = sum(1 for s in ct_samples if s.tier.tier0_detected)
        tier15_fp = sum(1 for s in ct_samples if s.tier.tier15_verdict != "SAFE")
        combined_blocked = sum(1 for s in ct_samples if s.tier.combined_status == "BLOCKED")
        combined_warned = sum(1 for s in ct_samples if s.tier.combined_status == "WARNING")
        combined_clean = sum(1 for s in ct_samples if s.tier.combined_status == "CLEAN")

        result[ct] = {
            "total": total,
            "tier0_fpr": round(tier0_fp / max(total, 1), 4),
            "tier15_fpr": round(tier15_fp / max(total, 1), 4),
            "combined_block_rate": round(combined_blocked / max(total, 1), 4),
            "combined_warn_rate": round(combined_warned / max(total, 1), 4),
            "combined_clean_rate": round(combined_clean / max(total, 1), 4),
            "false_blocks": combined_blocked,
            "false_warnings": combined_warned,
        }
    return result


def analyze_totals(samples: list[ScoredSample]) -> dict:
    """Aggregate totals across all samples."""
    malicious = [s for s in samples if s.is_malicious]
    benign = [s for s in samples if not s.is_malicious]

    # Malicious detection
    mal_tier0 = sum(1 for s in malicious if s.tier.tier0_detected)
    mal_tier15 = sum(1 for s in malicious if s.tier.tier15_verdict != "SAFE")
    mal_either = sum(
        1 for s in malicious
        if s.tier.tier0_detected or s.tier.tier15_verdict != "SAFE"
    )
    mal_blocked = sum(1 for s in malicious if s.tier.combined_status == "BLOCKED")
    mal_warned = sum(1 for s in malicious if s.tier.combined_status == "WARNING")

    # Benign false positives
    ben_tier0 = sum(1 for s in benign if s.tier.tier0_detected)
    ben_tier15 = sum(1 for s in benign if s.tier.tier15_verdict != "SAFE")
    ben_blocked = sum(1 for s in benign if s.tier.combined_status == "BLOCKED")
    ben_warned = sum(1 for s in benign if s.tier.combined_status == "WARNING")

    return {
        "malicious": {
            "total": len(malicious),
            "tier0_detected": mal_tier0,
            "tier15_detected": mal_tier15,
            "either_detected": mal_either,
            "combined_blocked": mal_blocked,
            "combined_warned": mal_warned,
            "combined_missed": len(malicious) - mal_blocked - mal_warned,
            "tier0_recall": round(mal_tier0 / max(len(malicious), 1), 4),
            "tier15_recall": round(mal_tier15 / max(len(malicious), 1), 4),
            "union_recall": round(mal_either / max(len(malicious), 1), 4),
            "combined_detection_rate": round(
                (mal_blocked + mal_warned) / max(len(malicious), 1), 4
            ),
        },
        "benign": {
            "total": len(benign),
            "tier0_fps": ben_tier0,
            "tier15_fps": ben_tier15,
            "false_blocks": ben_blocked,
            "false_warnings": ben_warned,
            "true_clean": len(benign) - ben_blocked - ben_warned,
            "tier0_fpr": round(ben_tier0 / max(len(benign), 1), 4),
            "tier15_fpr": round(ben_tier15 / max(len(benign), 1), 4),
            "false_block_rate": round(ben_blocked / max(len(benign), 1), 4),
            "false_warn_rate": round(ben_warned / max(len(benign), 1), 4),
        },
    }


def print_report(
    totals: dict,
    recall: dict,
    fpr: dict,
    production_mode: bool,
) -> None:
    mode_str = "Production (sliding window)" if production_mode else "Raw (single window)"
    mal = totals["malicious"]
    ben = totals["benign"]

    print(f"\n{'=' * 72}")
    print(f"MULTI-TIER PIPELINE BENCHMARK — {date.today().isoformat()}")
    print(f"Mode: {mode_str}")
    print(f"Malicious: {mal['total']} | Benign: {ben['total']}")
    print(f"{'=' * 72}")

    # --- Aggregate ---
    print(f"\n## Aggregate Detection (Malicious Samples)\n")
    print(f"| Metric              | Tier 0 (regex) | Tier 1.5 (ONNX) | Union (either) |")
    print(f"|---------------------|----------------|-----------------|----------------|")
    print(f"| Detected            | {mal['tier0_detected']:>14} | {mal['tier15_detected']:>15} | {mal['either_detected']:>14} |")
    print(f"| Recall              | {mal['tier0_recall']:>13.1%} | {mal['tier15_recall']:>14.1%} | {mal['union_recall']:>13.1%} |")

    print(f"\n## Production Verdict (Malicious Samples)\n")
    print(f"| Verdict   | Count | Rate   |")
    print(f"|-----------|-------|--------|")
    print(f"| BLOCKED   | {mal['combined_blocked']:>5} | {mal['combined_blocked']/max(mal['total'],1):>5.1%} |")
    print(f"| WARNING   | {mal['combined_warned']:>5} | {mal['combined_warned']/max(mal['total'],1):>5.1%} |")
    print(f"| CLEAN     | {mal['combined_missed']:>5} | {mal['combined_missed']/max(mal['total'],1):>5.1%} |")

    print(f"\n## Aggregate False Positives (Benign Samples)\n")
    print(f"| Metric              | Tier 0 (regex) | Tier 1.5 (ONNX) | Combined Pipeline |")
    print(f"|---------------------|----------------|-----------------|-------------------|")
    print(f"| False positives     | {ben['tier0_fps']:>14} | {ben['tier15_fps']:>15} | {ben['false_blocks']+ben['false_warnings']:>17} |")
    print(f"| FPR                 | {ben['tier0_fpr']:>13.1%} | {ben['tier15_fpr']:>14.1%} | {(ben['false_blocks']+ben['false_warnings'])/max(ben['total'],1):>16.1%} |")

    print(f"\n## Production Verdict (Benign Samples)\n")
    print(f"| Verdict   | Count | Rate   | Impact       |")
    print(f"|-----------|-------|--------|--------------|")
    print(f"| BLOCKED   | {ben['false_blocks']:>5} | {ben['false_blocks']/max(ben['total'],1):>5.1%} | Stops work   |")
    print(f"| WARNING   | {ben['false_warnings']:>5} | {ben['false_warnings']/max(ben['total'],1):>5.1%} | User reviews |")
    print(f"| CLEAN     | {ben['true_clean']:>5} | {ben['true_clean']/max(ben['total'],1):>5.1%} | Silent pass  |")

    # --- Per-category recall ---
    print(f"\n## Per-Category Recall (Tier Contribution)\n")
    print(f"| Category                    | Total | Tier 0 | Tier 1.5 | Union  | Blocked | Warned |")
    print(f"|-----------------------------|-------|--------|----------|--------|---------|--------|")
    for cat, info in sorted(recall.items()):
        print(
            f"| {cat:<27} | {info['total']:>5} | "
            f"{info['tier0_recall']:>5.0%} | {info['tier15_recall']:>7.0%} | "
            f"{info['union_recall']:>5.0%} | "
            f"{info['combined_blocked']:>7} | {info['combined_warned']:>6} |"
        )

    # --- Per-content-type FPR ---
    print(f"\n## Per-Content-Type False Positives (Production Severity)\n")
    print(f"| Content Type          | Total | T0 FPR | T1.5 FPR | Blocks | Warns  | Clean  |")
    print(f"|-----------------------|-------|--------|----------|--------|--------|--------|")
    for ct, info in sorted(fpr.items()):
        print(
            f"| {ct:<21} | {info['total']:>5} | "
            f"{info['tier0_fpr']:>5.0%} | {info['tier15_fpr']:>7.0%} | "
            f"{info['combined_block_rate']:>5.0%} | "
            f"{info['combined_warn_rate']:>5.0%} | "
            f"{info['combined_clean_rate']:>5.0%} |"
        )

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-tier pipeline benchmark for CloneGuard",
    )
    parser.add_argument(
        "--eval-corpus", type=Path, default=None,
        help="Path to held-out benign eval corpus (avoids data leakage)",
    )
    parser.add_argument(
        "--production", action="store_true",
        help="Use production classify() with sliding window for Tier 1.5",
    )
    args = parser.parse_args()

    # Load corpora
    mal_data = json.loads(MALICIOUS_CORPUS.read_text())
    if isinstance(mal_data, dict):
        mal_data = mal_data.get("samples", mal_data.get("payloads", []))
    print(f"Loaded {len(mal_data)} malicious samples")

    if args.eval_corpus:
        ben_data = json.loads(args.eval_corpus.read_text())
        if isinstance(ben_data, dict):
            ben_data = ben_data.get("samples", ben_data.get("content", []))
        print(f"Loaded {len(ben_data)} benign samples from {args.eval_corpus} (held-out)")
    else:
        ben_data = json.loads(BENIGN_CORPUS.read_text())
        if isinstance(ben_data, dict):
            ben_data = ben_data.get("samples", ben_data.get("content", []))
        print(f"Loaded {len(ben_data)} benign samples from {BENIGN_CORPUS}")

    # Score everything
    scored = score_all(mal_data, ben_data, production_mode=args.production)

    # Analyze
    totals = analyze_totals(scored)
    recall = analyze_recall(scored)
    fpr = analyze_fpr(scored)

    # Print report
    print_report(totals, recall, fpr, args.production)

    # Save JSON
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    report = {
        "meta": {
            "date": today,
            "production_mode": args.production,
            "malicious_count": len(mal_data),
            "benign_count": len(ben_data),
            "eval_corpus": str(args.eval_corpus) if args.eval_corpus else None,
        },
        "totals": totals,
        "per_category_recall": recall,
        "per_content_type_fpr": fpr,
        "per_sample": [
            {
                "id": s.id,
                "is_malicious": s.is_malicious,
                "category": s.category,
                "scan_mode": s.scan_mode,
                "tier0_detected": s.tier.tier0_detected,
                "tier0_severity": s.tier.tier0_severity,
                "tier15_prob": round(s.tier.tier15_malicious_prob, 4),
                "tier15_verdict": s.tier.tier15_verdict,
                "combined_status": s.tier.combined_status,
            }
            for s in scored
        ],
    }
    report_path = RESULTS_DIR / f"multitier-benchmark-{today}.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"JSON report saved to {report_path}")


if __name__ == "__main__":
    main()
