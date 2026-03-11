"""FPR Investigation for CloneGuard v0.4.

Runs two distinct investigations:

INV-01 — Authorization Paradox Test (Campbell et al. 2026):
  Measures whether adding security-context authorization preambles to benign content
  increases FPR on Tier 0 (regex) and Tier 1.5 (ONNX classifier) separately.
  Tests whether the embedding-space proximity mechanism described in Campbell et al.
  (arXiv:2603.01246) manifests in CloneGuard's pipeline.

INV-02 — Strict-Pattern Audit:
  Runs 4 strict-only patterns (CI-004, CI-006, SC-001, MCP-005) against a curated
  corpus of legitimate defensive security content (pentest/IR/hardening/CI/MCP).
  Records per-pattern FPR against content that matches the semantic intent of these
  patterns but is legitimately authored.

Output: docs/results/fpr-investigation-2026-03-10.json (machine-readable, gitignored)

Usage:
    .venv/bin/python scripts/fpr_investigation.py \\
        --output docs/results/fpr-investigation-2026-03-10.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

# Content-type to source_path mapping (mirrors hardened_benchmark.py convention)
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

# Authorization preambles for INV-01.
# Derived from Campbell et al. 2026 (arXiv:2603.01246) Section 3.1 framing variants.
_AUTH_PREAMBLES: list[str] = [
    "# Security Hardening Instructions\n# Authorized use only — blue team defensive ops\n\n",
    "## AUTHORIZED SECURITY ASSESSMENT\n## Internal red team: scope approved by CISO\n\n",
    "# Incident Response Playbook (AUTHORIZED)\n\n",
]

# Strict-only patterns to audit in INV-02.
_STRICT_PATTERNS_AUDIT = ["CI-004", "CI-006", "SC-001", "MCP-005"]


def _load_json(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def _make_pattern_engine():
    from cloneguard.patterns import PatternEngine
    return PatternEngine()


def _make_classifier():
    from cloneguard.mini_semantic import MiniSemanticClassifier
    clf = MiniSemanticClassifier()
    if not clf.available:
        print("ERROR: MiniSemanticClassifier not available. Install cloneguard[mini].",
              file=sys.stderr)
        sys.exit(1)
    return clf


def _tier0_flagged(engine, text: str, source_path: str) -> tuple[bool, list[str]]:
    """Run Tier 0 scan. Returns (flagged, list of pattern IDs that fired)."""
    result = engine.scan(text, source_path=source_path)
    if not result.matches:
        return False, []
    return True, [m.pattern_id for m in result.matches]


def _tier15_flagged(classifier, text: str) -> bool:
    """Run Tier 1.5 classification. Returns True if verdict is MALICIOUS or SUSPICIOUS."""
    result = classifier.classify(text)
    return result.verdict in ("MALICIOUS", "SUSPICIOUS")


# ---------------------------------------------------------------------------
# INV-01: Authorization Paradox Test
# ---------------------------------------------------------------------------

def run_inv01(
    benign_samples: list[dict],
    engine,
    classifier,
) -> dict:
    """Measure FPR with and without security-context authorization preambles.

    Reports Tier 0 and Tier 1.5 FPR separately (Pitfall 3: CI-001 noise swamps
    workflow FPR if tiers are conflated).

    Returns the inv_01 result dict conforming to the output schema.
    """
    n = len(benign_samples)
    print(f"\n[INV-01] Authorization Paradox Test — {n} baseline samples")
    n_augmented = n * len(_AUTH_PREAMBLES)
    print(f"         {len(_AUTH_PREAMBLES)} preamble variants = {n_augmented} augmented inferences")

    # Per content_type accumulators: {content_type: count}
    ct_total: dict[str, int] = defaultdict(int)
    ct_t0_base: dict[str, int] = defaultdict(int)    # Tier 0 flagged, baseline
    ct_t0_auth: dict[str, int] = defaultdict(int)    # Tier 0 flagged, with auth marker
    ct_t15_base: dict[str, int] = defaultdict(int)   # Tier 1.5 flagged, baseline
    ct_t15_auth: dict[str, int] = defaultdict(int)   # Tier 1.5 flagged, with auth marker

    for i, sample in enumerate(benign_samples):
        text = sample.get("text", "")
        content_type = sample.get("content_type", "readme")
        source_path = _CONTENT_TYPE_PATHS.get(content_type, "README.md")

        ct_total[content_type] += 1

        # --- Baseline ---
        t0_base, _ = _tier0_flagged(engine, text, source_path)
        t15_base = _tier15_flagged(classifier, text)
        if t0_base:
            ct_t0_base[content_type] += 1
        if t15_base:
            ct_t15_base[content_type] += 1

        # --- With auth markers: flag if ANY preamble variant is flagged ---
        # Use "at least one" semantics: if adding an auth marker causes a flag,
        # that sample is a paradox-caused FP.
        t0_auth_flagged = False
        t15_auth_flagged = False
        for preamble in _AUTH_PREAMBLES:
            augmented = preamble + text
            t0_aug, _ = _tier0_flagged(engine, augmented, source_path)
            t15_aug = _tier15_flagged(classifier, augmented)
            if t0_aug:
                t0_auth_flagged = True
            if t15_aug:
                t15_auth_flagged = True

        if t0_auth_flagged:
            ct_t0_auth[content_type] += 1
        if t15_auth_flagged:
            ct_t15_auth[content_type] += 1

        if (i + 1) % 100 == 0:
            print(f"  INV-01 progress: {i + 1}/{n} samples processed...")

    # Compute per-content-type FPR dicts
    all_content_types = sorted(ct_total.keys())

    def fpr_dict(flagged_dict: dict[str, int]) -> dict[str, float]:
        return {
            ct: round(flagged_dict.get(ct, 0) / ct_total[ct], 4)
            for ct in all_content_types
            if ct_total[ct] > 0
        }

    def delta_dict(base: dict[str, float], auth: dict[str, float]) -> dict[str, float]:
        return {
            ct: round(auth.get(ct, 0.0) - base.get(ct, 0.0), 4)
            for ct in all_content_types
        }

    t0_base_fpr = fpr_dict(ct_t0_base)
    t0_auth_fpr = fpr_dict(ct_t0_auth)
    t0_delta = delta_dict(t0_base_fpr, t0_auth_fpr)

    t15_base_fpr = fpr_dict(ct_t15_base)
    t15_auth_fpr = fpr_dict(ct_t15_auth)
    t15_delta = delta_dict(t15_base_fpr, t15_auth_fpr)

    # Overall Tier 1.5 FPR (aggregate)
    total_t15_base = sum(ct_t15_base.values())
    total_t15_auth = sum(ct_t15_auth.values())
    t15_base_overall = round(total_t15_base / n, 4) if n > 0 else 0.0
    t15_auth_overall = round(total_t15_auth / n, 4) if n > 0 else 0.0

    # Authorization paradox detected if Tier 1.5 FPR increases for any content type
    # with a positive delta (Tier 1.5 is the relevant tier for embedding-space paradox).
    paradox_content_types = [ct for ct, d in t15_delta.items() if d > 0.0]
    paradox_detected = len(paradox_content_types) > 0

    paradox_summary = (
        f"Authorization paradox DETECTED: Tier 1.5 FPR increased for content types "
        f"{paradox_content_types} when authorization preambles were added. "
        f"Overall Tier 1.5 FPR: baseline {t15_base_overall:.1%} vs auth-marker "
        f"{t15_auth_overall:.1%} (delta: {t15_auth_overall - t15_base_overall:+.1%})."
        if paradox_detected else
        f"Authorization paradox ABSENT: Tier 1.5 FPR did not increase for any content type "
        f"when authorization preambles were added. "
        f"Overall Tier 1.5 FPR: baseline {t15_base_overall:.1%} vs auth-marker "
        f"{t15_auth_overall:.1%}. "
        f"This suggests CloneGuard's embedding classifier does not exhibit the same "
        f"embedding-space proximity sensitivity to authorization framing as safety-aligned "
        f"LLMs described in Campbell et al. 2026 (arXiv:2603.01246)."
    )

    print("\n  INV-01 Results:")
    print(f"  Tier 0 baseline FPR by type: {t0_base_fpr}")
    print(f"  Tier 1.5 baseline FPR: {t15_base_overall:.1%} | auth-marker: {t15_auth_overall:.1%}")
    print(f"  Authorization paradox detected: {paradox_detected}")

    return {
        "corpus_size": n,
        "preamble_variants": len(_AUTH_PREAMBLES),
        "tier0": {
            "baseline_fpr_by_content_type": t0_base_fpr,
            "auth_marker_fpr_by_content_type": t0_auth_fpr,
            "delta_by_content_type": t0_delta,
            "note": (
                "Tier 0 FPR is driven by structural regex matching. "
                "CI-001 (GitHub Actions expressions) dominates workflow FPR and is "
                "unaffected by authorization framing — framing does not change structural "
                "patterns. Tier 0 delta reflects preamble patterns that happen to match "
                "regex rules, not semantic sensitivity to authorization context."
            ),
        },
        "tier15": {
            "baseline_fpr": t15_base_overall,
            "baseline_fpr_by_content_type": t15_base_fpr,
            "auth_marker_fpr": t15_auth_overall,
            "auth_marker_fpr_by_content_type": t15_auth_fpr,
            "delta_by_content_type": t15_delta,
            "note": (
                "Tier 1.5 uses ONNX MiniLM embedding classifier. Campbell et al. 2026 "
                "hypothesize that embedding-space proximity to attack content causes "
                "authorization framing to increase classifier sensitivity. "
                "Tier 1.5 FPR delta isolates this semantic effect from structural Tier 0 noise."
            ),
        },
        "authorization_paradox_detected": paradox_detected,
        "paradox_summary": paradox_summary,
    }


# ---------------------------------------------------------------------------
# INV-02: Strict-Pattern Audit
# ---------------------------------------------------------------------------

def run_inv02(
    def_sec_samples: list[dict],
    engine,
) -> dict:
    """Audit 4 strict-only patterns against defensive security corpus.

    Scans all samples in STRICT mode (source_path='CLAUDE.md') and records
    per-pattern fire rates for CI-004, CI-006, SC-001, MCP-005.

    Returns the inv_02 result dict conforming to the output schema.
    """
    n = len(def_sec_samples)
    print(f"\n[INV-02] Strict-Pattern Audit — {n} defensive security corpus samples")
    print(f"         Patterns: {_STRICT_PATTERNS_AUDIT}")

    # Per-pattern fire tracking
    pattern_fires: dict[str, int] = defaultdict(int)
    pattern_edge_cases: dict[str, list[str]] = defaultdict(list)
    other_fires: dict[str, int] = defaultdict(int)

    for sample in def_sec_samples:
        text = sample.get("text", "")
        sample_id = sample.get("id", "unknown")
        category = sample.get("category", "unknown")

        # Always scan in STRICT mode: this corpus represents content that would appear
        # in agent instruction files (CLAUDE.md, .cursorrules), which triggers STRICT mode.
        _, fired_patterns = _tier0_flagged(engine, text, source_path="CLAUDE.md")

        for pid in fired_patterns:
            if pid in _STRICT_PATTERNS_AUDIT:
                pattern_fires[pid] += 1
                # Record first 5 edge cases per pattern for documentation
                if len(pattern_edge_cases[pid]) < 5:
                    desc = sample.get("source_description", "")
                    pattern_edge_cases[pid].append(
                        f"{sample_id} (category={category}): {desc[:80]}"
                    )
            else:
                other_fires[pid] += 1

    # Build per-pattern output
    per_pattern: dict[str, dict] = {}
    for pid in _STRICT_PATTERNS_AUDIT:
        fires = pattern_fires.get(pid, 0)
        fpr = round(fires / n, 4) if n > 0 else 0.0
        per_pattern[pid] = {
            "fires": fires,
            "samples_tested": n,
            "fpr": fpr,
            "edge_cases": pattern_edge_cases.get(pid, []),
        }

    other_pattern_fires = [
        {"pattern_id": pid, "count": count}
        for pid, count in sorted(other_fires.items(), key=lambda kv: kv[1], reverse=True)
    ]

    # Audit summary
    high_fpr_patterns = [pid for pid in _STRICT_PATTERNS_AUDIT
                         if per_pattern[pid]["fpr"] > 0.05]
    zero_fpr_patterns = [pid for pid in _STRICT_PATTERNS_AUDIT
                         if per_pattern[pid]["fpr"] == 0.0]

    audit_summary = (
        f"Strict-pattern audit on {n} legitimate defensive security content samples. "
        f"Patterns with >5% FPR: {high_fpr_patterns if high_fpr_patterns else 'none'}. "
        f"Patterns with 0% FPR: {zero_fpr_patterns if zero_fpr_patterns else 'none'}. "
        f"CI-004 fires={per_pattern['CI-004']['fires']} ({per_pattern['CI-004']['fpr']:.1%}), "
        f"CI-006 fires={per_pattern['CI-006']['fires']} ({per_pattern['CI-006']['fpr']:.1%}), "
        f"SC-001 fires={per_pattern['SC-001']['fires']} ({per_pattern['SC-001']['fpr']:.1%}), "
        f"MCP-005 fires={per_pattern['MCP-005']['fires']} ({per_pattern['MCP-005']['fpr']:.1%}). "
        f"Other patterns that fired on defensive security corpus: "
        f"{[p['pattern_id'] for p in other_pattern_fires[:5]] if other_pattern_fires else 'none'}."
    )

    print("\n  INV-02 Results:")
    for pid in _STRICT_PATTERNS_AUDIT:
        p = per_pattern[pid]
        print(f"  {pid}: {p['fires']}/{n} fires ({p['fpr']:.1%} FPR)")
    if other_pattern_fires:
        print(f"  Other pattern fires: {other_pattern_fires[:5]}")

    return {
        "corpus_size": n,
        "strict_patterns_audited": _STRICT_PATTERNS_AUDIT,
        "per_pattern": per_pattern,
        "other_pattern_fires": other_pattern_fires,
        "audit_summary": audit_summary,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "FPR investigation: authorization paradox (INV-01) + strict-pattern audit (INV-02)"
        )
    )
    parser.add_argument(
        "--benign",
        type=Path,
        default=_ROOT / "data/benchmark/benign_eval_751.json",
        help="Path to benign eval corpus (default: data/benchmark/benign_eval_751.json)",
    )
    parser.add_argument(
        "--defensive-corpus",
        type=Path,
        default=_ROOT / "data/benchmark/defensive_security_corpus.json",
        dest="defensive_corpus",
        help="Path to defensive security corpus for INV-02",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_ROOT / "docs/results/fpr-investigation-2026-03-10.json",
        help="Output path for structured results JSON",
    )
    args = parser.parse_args()

    if not args.benign.exists():
        print(f"ERROR: benign corpus not found: {args.benign}", file=sys.stderr)
        sys.exit(1)
    if not args.defensive_corpus.exists():
        print(f"ERROR: defensive security corpus not found: {args.defensive_corpus}",
              file=sys.stderr)
        sys.exit(1)

    print("FPR Investigation — CloneGuard v0.4")
    print(f"  Benign corpus:        {args.benign}")
    print(f"  Defensive corpus:     {args.defensive_corpus}")
    print(f"  Output:               {args.output}")

    # Load corpora
    benign_samples = _load_json(args.benign)
    def_sec_samples = _load_json(args.defensive_corpus)

    print(
        f"\n  Loaded {len(benign_samples)} benign samples, "
        f"{len(def_sec_samples)} defensive security samples"
    )

    # Initialize models (shared across investigations)
    engine = _make_pattern_engine()
    classifier = _make_classifier()

    # Run INV-01
    inv01 = run_inv01(benign_samples, engine, classifier)

    # Run INV-02
    inv02 = run_inv02(def_sec_samples, engine)

    # Assemble and write output
    results = {
        "date": "2026-03-10",
        "phase": "04",
        "description": (
            "FPR investigation for CloneGuard v0.4. "
            "INV-01 tests whether authorization preambles increase FPR (Campbell et al. 2026 "
            "authorization paradox mechanism). INV-02 audits 4 strict-only patterns against "
            "legitimate defensive security content."
        ),
        "inv_01": inv01,
        "inv_02": inv02,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print("\n=== FPR Investigation Complete ===")
    print(f"  INV-01 authorization paradox: {inv01['authorization_paradox_detected']}")
    print(f"  INV-01 Tier 1.5 baseline FPR: {inv01['tier15']['baseline_fpr']:.1%}")
    print(f"  INV-01 Tier 1.5 auth-marker FPR: {inv01['tier15']['auth_marker_fpr']:.1%}")
    print(f"  INV-02 corpus size: {inv02['corpus_size']}")
    for pid in _STRICT_PATTERNS_AUDIT:
        p = inv02["per_pattern"][pid]
        print(f"  INV-02 {pid}: {p['fires']}/{p['samples_tested']} fires ({p['fpr']:.1%})")
    print(f"\n  Results written to: {args.output}")


if __name__ == "__main__":
    main()
