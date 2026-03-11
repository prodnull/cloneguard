"""Schema validation tests for FPR investigation output and corpus structure.

Tests:
- test_defensive_corpus_structure: validates data/benchmark/defensive_security_corpus.json
- test_results_schema: validates docs/results/fpr-investigation-2026-03-10.json schema
- test_inv01_tier_separation: INV-01 reports Tier 0 and Tier 1.5 separately
- test_inv01_fpr_range: all FPR values in [0.0, 1.0]
- test_inv01_paradox_field: authorization_paradox_detected is bool
- test_inv02_strict_patterns: all 4 strict-only patterns present in per_pattern
- test_inv02_fpr_range: all INV-02 per-pattern FPR values in [0.0, 1.0]
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

_CORPUS_PATH = _ROOT / "data/benchmark/defensive_security_corpus.json"
_RESULTS_PATH = _ROOT / "docs/results/fpr-investigation-2026-03-10.json"

_REQUIRED_SAMPLE_FIELDS = {"id", "content_type", "text", "source_description", "category"}
_EXPECTED_CATEGORIES = {
    "pentest",
    "ir",
    "hardening",
    "cicd_in_instructions",
    "security_tooling",
    "mcp_config",
}
_STRICT_PATTERNS = ["CI-004", "CI-006", "SC-001", "MCP-005"]


# ---------------------------------------------------------------------------
# Corpus structure tests (always run — file is committed)
# ---------------------------------------------------------------------------


def test_defensive_corpus_structure() -> None:
    """Defensive security corpus must have 80+ samples with correct schema."""
    assert _CORPUS_PATH.exists(), f"Corpus not found: {_CORPUS_PATH}"

    with open(_CORPUS_PATH) as f:
        samples = json.load(f)

    assert isinstance(samples, list), "Corpus must be a JSON array"
    assert len(samples) >= 80, f"Corpus must have at least 80 samples, found {len(samples)}"

    # All samples must have required fields
    for i, sample in enumerate(samples):
        missing = _REQUIRED_SAMPLE_FIELDS - set(sample.keys())
        assert not missing, f"Sample {i} (id={sample.get('id', '?')}) missing fields: {missing}"

    # Content type must be agent_instructions (strict-mode relevant)
    for i, sample in enumerate(samples):
        assert sample["content_type"] == "agent_instructions", (
            f"Sample {i} (id={sample['id']}) has content_type={sample['content_type']!r}, "
            f"expected 'agent_instructions'"
        )

    # Categories must be valid
    observed_categories = {s["category"] for s in samples}
    unknown = observed_categories - _EXPECTED_CATEGORIES
    assert not unknown, f"Unknown categories in corpus: {unknown}"

    # Corpus must cover at least 4 of 6 expected categories
    assert len(observed_categories) >= 4, (
        f"Corpus must cover at least 4 categories, found: {observed_categories}"
    )

    # IDs must be unique
    ids = [s["id"] for s in samples]
    assert len(ids) == len(set(ids)), "Duplicate IDs in corpus"

    # Text content must be non-empty and realistic length (>= 20 chars)
    for sample in samples:
        assert len(sample["text"]) >= 20, (
            f"Sample {sample['id']} text too short: {len(sample['text'])} chars"
        )


def test_defensive_corpus_category_coverage() -> None:
    """Each expected category must have at least 5 samples."""
    assert _CORPUS_PATH.exists(), f"Corpus not found: {_CORPUS_PATH}"

    with open(_CORPUS_PATH) as f:
        samples = json.load(f)

    from collections import Counter

    cat_counts = Counter(s["category"] for s in samples)

    for cat in _EXPECTED_CATEGORIES:
        assert cat_counts.get(cat, 0) >= 5, (
            f"Category '{cat}' has only {cat_counts.get(cat, 0)} samples (minimum 5 required)"
        )


# ---------------------------------------------------------------------------
# Results schema validation tests (skip if file doesn't exist yet)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def results() -> dict:
    """Load investigation results, skip if not yet generated."""
    if not _RESULTS_PATH.exists():
        pytest.skip(
            f"FPR investigation results not yet generated: {_RESULTS_PATH}. "
            f"Run: .venv/bin/python scripts/fpr_investigation.py"
        )
    with open(_RESULTS_PATH) as f:
        return json.load(f)


def test_results_top_level_keys(results: dict) -> None:
    """Results must have required top-level keys."""
    required = {"date", "phase", "inv_01", "inv_02"}
    missing = required - set(results.keys())
    assert not missing, f"Missing top-level keys: {missing}"


def test_results_metadata(results: dict) -> None:
    """Date and phase must be correct."""
    assert results["date"] == "2026-03-10", f"Expected date '2026-03-10', got {results['date']!r}"
    assert results["phase"] == "04", f"Expected phase '04', got {results['phase']!r}"


def test_inv01_tier_separation(results: dict) -> None:
    """INV-01 must report Tier 0 and Tier 1.5 separately (not conflated)."""
    inv01 = results["inv_01"]
    assert "tier0" in inv01, "INV-01 must have 'tier0' subsection"
    assert "tier15" in inv01, "INV-01 must have 'tier15' subsection"

    tier0 = inv01["tier0"]
    assert "baseline_fpr_by_content_type" in tier0
    assert "auth_marker_fpr_by_content_type" in tier0
    assert "delta_by_content_type" in tier0

    tier15 = inv01["tier15"]
    assert "baseline_fpr" in tier15
    assert "baseline_fpr_by_content_type" in tier15
    assert "auth_marker_fpr" in tier15
    assert "auth_marker_fpr_by_content_type" in tier15
    assert "delta_by_content_type" in tier15


def test_inv01_fpr_range(results: dict) -> None:
    """All FPR values in INV-01 must be floats in [0.0, 1.0]."""
    inv01 = results["inv_01"]

    for tier_key in ("tier0", "tier15"):
        tier = inv01[tier_key]
        for fpr_key in (
            "baseline_fpr_by_content_type",
            "auth_marker_fpr_by_content_type",
            "delta_by_content_type",
        ):
            if fpr_key in tier:
                for ct, val in tier[fpr_key].items():
                    assert isinstance(val, (int, float)), (
                        f"INV-01 {tier_key}.{fpr_key}[{ct}] must be numeric, got {type(val)}"
                    )
                    # Delta can be negative (FPR decreased with auth marker)
                    if fpr_key != "delta_by_content_type":
                        assert 0.0 <= val <= 1.0, (
                            f"INV-01 {tier_key}.{fpr_key}[{ct}] = {val} out of [0, 1]"
                        )

    # Overall Tier 1.5 FPR values
    tier15 = inv01["tier15"]
    for key in ("baseline_fpr", "auth_marker_fpr"):
        val = tier15[key]
        assert isinstance(val, (int, float)), f"INV-01 tier15.{key} must be numeric"
        assert 0.0 <= val <= 1.0, f"INV-01 tier15.{key} = {val} out of [0, 1]"


def test_inv01_paradox_field(results: dict) -> None:
    """authorization_paradox_detected must be a boolean."""
    inv01 = results["inv_01"]
    assert "authorization_paradox_detected" in inv01, (
        "INV-01 must have 'authorization_paradox_detected' field"
    )
    val = inv01["authorization_paradox_detected"]
    assert isinstance(val, bool), (
        f"'authorization_paradox_detected' must be bool, got {type(val)}: {val!r}"
    )
    assert "paradox_summary" in inv01, "INV-01 must have 'paradox_summary' string"
    assert isinstance(inv01["paradox_summary"], str)
    assert len(inv01["paradox_summary"]) > 20, "paradox_summary must be substantive"


def test_inv01_corpus_size(results: dict) -> None:
    """INV-01 must report a corpus size consistent with benign_eval_751.json."""
    inv01 = results["inv_01"]
    assert "corpus_size" in inv01
    # The benign eval has 757 samples
    assert inv01["corpus_size"] >= 700, (
        f"INV-01 corpus_size={inv01['corpus_size']} — expected ~757 from benign_eval_751.json"
    )


def test_inv02_strict_patterns(results: dict) -> None:
    """INV-02 must cover all 4 strict-only patterns in per_pattern."""
    inv02 = results["inv_02"]
    assert "per_pattern" in inv02, "INV-02 must have 'per_pattern' dict"
    per_pattern = inv02["per_pattern"]

    for pid in _STRICT_PATTERNS:
        assert pid in per_pattern, f"Pattern {pid} missing from INV-02 per_pattern"

    # Each pattern entry must have fires, samples_tested, fpr
    for pid in _STRICT_PATTERNS:
        entry = per_pattern[pid]
        assert "fires" in entry, f"{pid}: missing 'fires'"
        assert "samples_tested" in entry, f"{pid}: missing 'samples_tested'"
        assert "fpr" in entry, f"{pid}: missing 'fpr'"
        assert isinstance(entry["fires"], int), f"{pid}: fires must be int"
        assert isinstance(entry["samples_tested"], int), f"{pid}: samples_tested must be int"
        assert entry["samples_tested"] > 0, f"{pid}: samples_tested must be > 0"


def test_inv02_fpr_range(results: dict) -> None:
    """All per-pattern FPR values in INV-02 must be in [0.0, 1.0]."""
    inv02 = results["inv_02"]
    per_pattern = inv02.get("per_pattern", {})

    for pid in _STRICT_PATTERNS:
        if pid in per_pattern:
            fpr = per_pattern[pid]["fpr"]
            assert isinstance(fpr, (int, float)), f"{pid}: fpr must be numeric, got {type(fpr)}"
            assert 0.0 <= fpr <= 1.0, f"{pid}: fpr={fpr} out of [0.0, 1.0]"
            fires = per_pattern[pid]["fires"]
            samples = per_pattern[pid]["samples_tested"]
            assert fires <= samples, f"{pid}: fires={fires} cannot exceed samples_tested={samples}"


def test_inv02_not_all_fire(results: dict) -> None:
    """No strict-only pattern should have 100% FPR on the defensive corpus.

    100% FPR would indicate the pattern is over-broad or the corpus is wrong.
    This assertion would fail if CI-004 fires on every sample (which would
    indicate the pattern is matching content it shouldn't).
    """
    inv02 = results["inv_02"]
    per_pattern = inv02.get("per_pattern", {})

    for pid in _STRICT_PATTERNS:
        if pid in per_pattern:
            fpr = per_pattern[pid]["fpr"]
            assert fpr < 1.0, (
                f"{pid}: FPR={fpr:.1%} is 100% — pattern is likely over-broad or "
                f"corpus has a systematic issue. Investigate before proceeding."
            )


def test_inv02_audit_summary_present(results: dict) -> None:
    """INV-02 must have an audit_summary string."""
    inv02 = results["inv_02"]
    assert "audit_summary" in inv02, "INV-02 must have 'audit_summary'"
    assert isinstance(inv02["audit_summary"], str)
    assert len(inv02["audit_summary"]) > 30, "audit_summary must be substantive"


def test_inv02_corpus_size(results: dict) -> None:
    """INV-02 corpus_size must match the defensive security corpus."""
    inv02 = results["inv_02"]
    assert "corpus_size" in inv02

    # Load actual corpus to verify
    if _CORPUS_PATH.exists():
        with open(_CORPUS_PATH) as f:
            corpus = json.load(f)
        assert inv02["corpus_size"] == len(corpus), (
            f"INV-02 corpus_size={inv02['corpus_size']} does not match "
            f"actual corpus size {len(corpus)}"
        )
