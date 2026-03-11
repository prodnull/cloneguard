"""Threshold calibration for CloneGuard Tier 1.5 (MiniSemanticClassifier).

Sweeps (suspicious_threshold, malicious_threshold) pairs across the benign eval
corpus and reports per-content-type FPR at each threshold level. Output drives
the _DEFAULT_THRESHOLDS constants in mini_semantic.py for STANDARD and LENIENT
modes. STRICT thresholds are NOT calibrated here — they are locked at (0.5, 0.8)
per Phase 5 CONTEXT.md.

Also runs combined Tier 0 + Tier 1.5 FPR measurement at the chosen default
thresholds (--verify flag), per Pitfall 3 in 05-RESEARCH.md: success criteria
apply to the combined pipeline that users experience, not Tier 1.5 alone.

Output (--output flag): docs/results/threshold-calibration-2026-03-11.json
(gitignored — internal calibration artifact)

Usage:
    .venv/bin/python scripts/calibrate_thresholds.py
    .venv/bin/python scripts/calibrate_thresholds.py \\
        --output docs/results/threshold-calibration-2026-03-11.json
    .venv/bin/python scripts/calibrate_thresholds.py --verify
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

# Threshold sweep grid
SWEEP_SUSPICIOUS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]
SWEEP_MALICIOUS = [0.80, 0.83, 0.85, 0.88, 0.90, 0.92, 0.95]

# Content-type to source_path mapping (mirrors fpr_investigation.py convention)
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

# Chosen defaults for STANDARD and LENIENT — derived from this script's output.
# These must match _DEFAULT_THRESHOLDS in mini_semantic.py exactly.
_CHOSEN_STANDARD = (0.65, 0.88)
_CHOSEN_LENIENT = (0.75, 0.92)


def _load_json(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def _make_classifier():
    from cloneguard.mini_semantic import MiniSemanticClassifier

    clf = MiniSemanticClassifier()
    if not clf.available:
        print(
            "ERROR: MiniSemanticClassifier not available. Install cloneguard[mini].",
            file=sys.stderr,
        )
        sys.exit(1)
    return clf


def _make_pattern_engine():
    from cloneguard.patterns import PatternEngine

    return PatternEngine()


def _get_raw_probs(classifier, samples: list[dict]) -> list[tuple[str, float]]:
    """Extract raw malicious_prob for each sample without applying thresholds.

    Uses the ONNX session directly via classify() at mode=STRICT (lowest
    thresholds), then reads the probability from the reason string. This gives
    us the raw model output, which we then threshold manually in the sweep.

    Returns list of (content_type, malicious_prob) tuples.
    """
    import numpy as np

    results = []
    for i, sample in enumerate(samples):
        text = sample.get("text", "")
        content_type = sample.get("content_type", "readme")

        # Run tokenization + ONNX inference directly to get raw probability
        inputs = classifier._tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=256,
            padding="max_length",
        )
        outputs = classifier._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )
        logits = outputs[0][0]
        probs = np.exp(logits) / np.exp(logits).sum()
        malicious_prob = float(probs[1])
        results.append((content_type, malicious_prob))

        if (i + 1) % 200 == 0:
            print(f"  Progress: {i + 1}/{len(samples)} samples processed...")

    return results


def _get_sliding_window_probs(classifier, samples: list[dict]) -> list[tuple[str, float]]:
    """Extract worst-chunk malicious_prob for long samples via sliding window.

    For samples with token count > 256, we extract the worst-chunk probability
    directly from the ONNX session (mirrors _classify_sliding_window internals).
    Short samples return their single-chunk probability.
    """
    import numpy as np

    from cloneguard.mini_semantic import _MAX_CHUNKS, _STRIDE, _WINDOW_SIZE

    results = []
    for sample in samples:
        text = sample.get("text", "")
        content_type = sample.get("content_type", "readme")

        full_encoding = classifier._tokenizer(text, truncation=False, return_tensors="np")
        token_ids = full_encoding["input_ids"][0]

        if len(token_ids) <= _WINDOW_SIZE:
            # Single-chunk: use direct inference
            inputs = classifier._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=_WINDOW_SIZE,
                padding="max_length",
            )
            outputs = classifier._session.run(
                None,
                {
                    "input_ids": inputs["input_ids"],
                    "attention_mask": inputs["attention_mask"],
                },
            )
            logits = outputs[0][0]
            probs = np.exp(logits) / np.exp(logits).sum()
            results.append((content_type, float(probs[1])))
        else:
            # Sliding window: take worst chunk
            worst_prob = 0.0
            num_chunks = 0
            for i in range(0, len(token_ids), _STRIDE):
                if num_chunks >= _MAX_CHUNKS:
                    break
                chunk_ids = token_ids[i : i + _WINDOW_SIZE]
                chunk_len = len(chunk_ids)
                if chunk_len < _WINDOW_SIZE:
                    pad_len = _WINDOW_SIZE - chunk_len
                    chunk_ids = np.concatenate(
                        [chunk_ids, np.zeros(pad_len, dtype=chunk_ids.dtype)]
                    )
                    attention_mask = np.concatenate(
                        [np.ones(chunk_len, dtype=np.int64), np.zeros(pad_len, dtype=np.int64)]
                    )
                else:
                    attention_mask = np.ones(_WINDOW_SIZE, dtype=np.int64)

                input_ids_batch = chunk_ids.reshape(1, _WINDOW_SIZE)
                attention_mask_batch = attention_mask.reshape(1, _WINDOW_SIZE)
                chunk_outputs = classifier._session.run(
                    None,
                    {"input_ids": input_ids_batch, "attention_mask": attention_mask_batch},
                )
                logits = chunk_outputs[0][0]
                probs = np.exp(logits) / np.exp(logits).sum()
                worst_prob = max(worst_prob, float(probs[1]))
                num_chunks += 1
            results.append((content_type, worst_prob))

    return results


def _sweep_thresholds(probs: list[tuple[str, float]]) -> dict:
    """Sweep all (suspicious, malicious) threshold pairs across raw probs.

    Returns a nested dict: sweep[susp_str][mal_str] -> {content_type: fpr, ..., "overall": fpr}
    """
    # Count totals per content_type
    ct_total: dict[str, int] = defaultdict(int)
    for ct, _ in probs:
        ct_total[ct] += 1
    total = len(probs)

    all_content_types = sorted(ct_total.keys())
    sweep: dict[str, dict[str, dict]] = {}

    for susp in SWEEP_SUSPICIOUS:
        susp_key = f"{susp:.2f}"
        sweep[susp_key] = {}
        for mal in SWEEP_MALICIOUS:
            if mal <= susp:
                continue  # Invalid: malicious threshold must exceed suspicious
            mal_key = f"{mal:.2f}"
            ct_flagged: dict[str, int] = defaultdict(int)
            total_flagged = 0

            for ct, prob in probs:
                if prob > susp:  # Flagged as SUSPICIOUS or MALICIOUS
                    ct_flagged[ct] += 1
                    total_flagged += 1

            fpr_by_ct = {
                ct: round(ct_flagged.get(ct, 0) / ct_total[ct], 4)
                for ct in all_content_types
                if ct_total[ct] > 0
            }
            fpr_by_ct["overall"] = round(total_flagged / total, 4) if total > 0 else 0.0
            sweep[susp_key][mal_key] = fpr_by_ct

    return sweep


def _run_combined_fpr(
    samples: list[dict],
    engine,
    classifier,
    susp_thresh: float,
    mal_thresh: float,
) -> dict[str, float]:
    """Measure combined Tier 0 + Tier 1.5 FPR at given thresholds.

    Mirrors production pipeline: Tier 1.5 only runs when Tier 0 is clean.
    Returns FPR per content type and overall.
    """
    ct_total: dict[str, int] = defaultdict(int)
    ct_flagged: dict[str, int] = defaultdict(int)

    for i, sample in enumerate(samples):
        text = sample.get("text", "")
        content_type = sample.get("content_type", "readme")
        source_path = _CONTENT_TYPE_PATHS.get(content_type, "README.md")

        ct_total[content_type] += 1

        # Tier 0
        t0_result = engine.scan(text, source_path=source_path)
        if t0_result.matches:
            ct_flagged[content_type] += 1
            continue

        # Tier 1.5 (only runs when Tier 0 is clean)
        # Apply custom thresholds via env var overrides
        old_susp = os.environ.get("CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS")
        old_mal = os.environ.get("CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS")
        os.environ["CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS"] = str(susp_thresh)
        os.environ["CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS"] = str(mal_thresh)

        try:
            from cloneguard.patterns import ScanMode

            t15_result = classifier.classify(text, mode=ScanMode.STANDARD)
            if t15_result.verdict != "SAFE":
                ct_flagged[content_type] += 1
        finally:
            if old_susp is None:
                os.environ.pop("CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS", None)
            else:
                os.environ["CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS"] = old_susp
            if old_mal is None:
                os.environ.pop("CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS", None)
            else:
                os.environ["CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS"] = old_mal

        if (i + 1) % 200 == 0:
            print(f"  Combined FPR progress: {i + 1}/{len(samples)} samples...")

    total = sum(ct_total.values())
    total_flagged = sum(ct_flagged.values())
    fpr_by_ct = {
        ct: round(ct_flagged.get(ct, 0) / ct_total[ct], 4)
        for ct in sorted(ct_total.keys())
        if ct_total[ct] > 0
    }
    fpr_by_ct["overall"] = round(total_flagged / total, 4) if total > 0 else 0.0
    return fpr_by_ct


def _print_recommendation_table(sweep: dict, chosen_susp: float, chosen_mal: float) -> None:
    """Print threshold sweep as a human-readable table highlighting chosen defaults."""
    print("\n=== Tier 1.5 FPR Sweep (% of benign samples flagged as SUSPICIOUS or MALICIOUS) ===")
    print(
        "Rows = suspicious threshold, Columns = malicious threshold. "
        "FPR shown as 'overall (workflow, agent_instructions, test_file)'."
    )
    print(
        f"  [CHOSEN] STANDARD=({chosen_susp:.2f}, {chosen_mal:.2f}), "
        f"LENIENT=({_CHOSEN_LENIENT[0]:.2f}, {_CHOSEN_LENIENT[1]:.2f})"
    )
    print()

    header = f"{'susp/mal':>8} " + " ".join(f"{m:.2f}" for m in SWEEP_MALICIOUS)
    print(header)
    print("-" * len(header))

    for susp in SWEEP_SUSPICIOUS:
        susp_key = f"{susp:.2f}"
        row_parts = [f"{susp:.2f}    "]
        for mal in SWEEP_MALICIOUS:
            if mal <= susp:
                row_parts.append("  N/A ")
                continue
            mal_key = f"{mal:.2f}"
            data = sweep.get(susp_key, {}).get(mal_key, {})
            overall = data.get("overall", 0.0)
            wf = data.get("workflow", 0.0)
            ai = data.get("agent_instructions", 0.0)
            tf = data.get("test_file", 0.0)
            is_chosen = abs(susp - chosen_susp) < 0.001 and abs(mal - chosen_mal) < 0.001
            marker = " <--" if is_chosen else ""
            row_parts.append(f"{overall:.1%}({wf:.0%},{ai:.0%},{tf:.0%}){marker}")
        print(" ".join(row_parts))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Threshold calibration: sweep Tier 1.5 FPR across benign corpus. "
            "Informs STANDARD and LENIENT threshold defaults in mini_semantic.py."
        )
    )
    parser.add_argument(
        "--benign",
        type=Path,
        default=_ROOT / "data/benchmark/benign_eval_751.json",
        help="Path to benign eval corpus (default: data/benchmark/benign_eval_751.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write structured JSON output to this path (gitignored results dir)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "After sweep, run combined Tier 0 + Tier 1.5 FPR check at chosen STANDARD "
            "and LENIENT defaults. Reports honest combined pipeline numbers per Pitfall 3."
        ),
    )
    args = parser.parse_args()

    if not args.benign.exists():
        print(f"ERROR: benign corpus not found: {args.benign}", file=sys.stderr)
        sys.exit(1)

    print("=== CloneGuard Threshold Calibration ===")
    print(f"  Benign corpus: {args.benign}")
    print(f"  Sweep grid: suspicious={SWEEP_SUSPICIOUS}")
    print(f"  Sweep grid: malicious={SWEEP_MALICIOUS}")

    samples = _load_json(args.benign)
    print(f"\n  Loaded {len(samples)} benign samples")

    classifier = _make_classifier()

    # Phase 1: Extract raw malicious_prob for each sample (single-chunk)
    print("\n[Phase 1] Extracting raw malicious_prob (single-chunk)...")
    single_probs = _get_raw_probs(classifier, samples)

    # Phase 2: Extract worst-chunk prob (sliding window) for long samples
    print("\n[Phase 2] Extracting worst-chunk malicious_prob (sliding window)...")
    window_probs = _get_sliding_window_probs(classifier, samples)

    # Use worst-of-two: max(single_prob, window_prob) per sample
    # This mirrors the actual classify() behavior (sliding window fires only on long inputs)
    combined_probs = [
        (ct, max(s_prob, w_prob)) for (ct, s_prob), (_, w_prob) in zip(single_probs, window_probs)
    ]

    # Phase 3: Sweep thresholds
    print("\n[Phase 3] Sweeping threshold pairs...")
    sweep = _sweep_thresholds(combined_probs)

    # Print recommendation table
    _print_recommendation_table(sweep, _CHOSEN_STANDARD[0], _CHOSEN_STANDARD[1])

    # Phase 4: Distribution stats
    print("\n=== Malicious Probability Distribution (benign samples) ===")
    from collections import Counter

    ct_buckets: dict[str, Counter] = defaultdict(Counter)
    for ct, prob in combined_probs:
        bucket = f"{int(prob * 10) / 10:.1f}"  # Round to 0.1 buckets
        ct_buckets[ct][bucket] += 1

    header_row = (
        f"\n{'Content Type':<22} {'n':>5} {'<0.5':>6} "
        f"{'0.5-0.65':>9} {'0.65-0.75':>10} {'>0.75':>7}"
    )
    print(header_row)
    print("-" * 62)

    content_totals: dict[str, int] = defaultdict(int)
    for ct, _ in combined_probs:
        content_totals[ct] += 1

    for ct in sorted(content_totals.keys()):
        n = content_totals[ct]
        ct_probs = [p for c, p in combined_probs if c == ct]
        below_05 = sum(1 for p in ct_probs if p < 0.5)
        between_05_065 = sum(1 for p in ct_probs if 0.5 <= p < 0.65)
        between_065_075 = sum(1 for p in ct_probs if 0.65 <= p < 0.75)
        above_075 = sum(1 for p in ct_probs if p >= 0.75)
        print(
            f"{ct:<22} {n:>5} {below_05 / n:>6.1%} {between_05_065 / n:>9.1%} "
            f"{between_065_075 / n:>10.1%} {above_075 / n:>7.1%}"
        )

    # Phase 5 (optional): Combined pipeline FPR at chosen defaults
    combined_results: dict = {}
    if args.verify:
        print("\n[Phase 5] Combined Tier 0 + Tier 1.5 FPR at chosen defaults...")
        engine = _make_pattern_engine()

        print(f"\n  STANDARD thresholds: susp={_CHOSEN_STANDARD[0]}, mal={_CHOSEN_STANDARD[1]}")
        combined_std = _run_combined_fpr(samples, engine, classifier, *_CHOSEN_STANDARD)
        print(f"  Combined FPR (STANDARD): {combined_std}")

        print(f"\n  LENIENT thresholds: susp={_CHOSEN_LENIENT[0]}, mal={_CHOSEN_LENIENT[1]}")
        combined_lnt = _run_combined_fpr(samples, engine, classifier, *_CHOSEN_LENIENT)
        print(f"  Combined FPR (LENIENT): {combined_lnt}")

        print("\n=== Combined Pipeline FPR Summary ===")
        print("NOTE: Tier 0 FPR on workflows is ~23.9% (CI-001-dominated) — a structural floor")
        print("that Phase 5 Tier 1.5 tuning cannot address. This is the expected honest outcome.")
        print("Tier 0 pattern fixes are deferred to Phase 6.")
        print()
        for label, result in [("STANDARD", combined_std), ("LENIENT", combined_lnt)]:
            print(f"  {label} combined FPR:")
            for ct, fpr in result.items():
                print(f"    {ct:<22} {fpr:.1%}")

        combined_results = {
            "STANDARD": combined_std,
            "LENIENT": combined_lnt,
            "note": (
                "Combined Tier 0 + Tier 1.5 FPR. Tier 1.5 runs only when Tier 0 is clean. "
                "Tier 0 workflow FPR ~23.9% (CI-001) is a structural floor not addressable "
                "by Phase 5 Tier 1.5 threshold tuning. Tier 0 fixes deferred to Phase 6."
            ),
        }

    # Assemble output
    output = {
        "date": "2026-03-11",
        "phase": "05",
        "corpus_size": len(samples),
        "sweep_suspicious": SWEEP_SUSPICIOUS,
        "sweep_malicious": SWEEP_MALICIOUS,
        "chosen_thresholds": {
            "STRICT": list(_CHOSEN_STANDARD),  # LOCKED — not from calibration
            "STANDARD": list(_CHOSEN_STANDARD),
            "LENIENT": list(_CHOSEN_LENIENT),
        },
        "tier15_fpr_sweep": sweep,
        "combined_pipeline_fpr": combined_results,
        "description": (
            "Threshold calibration sweep for CloneGuard Phase 5 FPR tuning. "
            "Tier 1.5 FPR measured for each (suspicious, malicious) threshold pair "
            "across 757 benign samples. STANDARD=(0.65, 0.88) and LENIENT=(0.75, 0.92) "
            "chosen to balance FPR reduction with recall preservation. "
            "STRICT=(0.5, 0.8) remains locked per Phase 5 CONTEXT.md."
        ),
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n  JSON output written to: {args.output}")

    print("\n=== Calibration Complete ===")
    print(f"  Chosen STANDARD thresholds: susp={_CHOSEN_STANDARD[0]}, mal={_CHOSEN_STANDARD[1]}")
    print(f"  Chosen LENIENT thresholds:  susp={_CHOSEN_LENIENT[0]}, mal={_CHOSEN_LENIENT[1]}")
    print("  These values are committed to src/cloneguard/mini_semantic.py _DEFAULT_THRESHOLDS.")


if __name__ == "__main__":
    main()
