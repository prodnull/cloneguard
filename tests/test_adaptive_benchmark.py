"""Schema validation tests for adaptive PWWS benchmark output.

These tests validate the JSON schema produced by scripts/adaptive_pwws_benchmark.py.
They do NOT require TextAttack or .venv-transfer — they validate a fixture dict
that mirrors the real output structure.

Run with: .venv/bin/python -m pytest tests/test_adaptive_benchmark.py -x -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture: minimal valid adaptive benchmark output
# ---------------------------------------------------------------------------

VALID_RESULT: dict = {
    "date": "2026-03-10",
    "model_version": "v4",
    "attack_method": "pwws",
    "corpus_size": 185,
    "pre_filtered_count": 150,
    "pre_misclassified_skipped": 35,
    "adaptive_asr": 0.25,
    "attacks_successful": 38,
    "attacks_failed": 112,
    "confidence_interval": {
        "ci_low": 0.18,
        "ci_high": 0.32,
        "method": "wilson",
        "alpha": 0.05,
    },
    "per_category": {
        "synonym_substitution": {"total": 20, "evaded": 10, "asr": 0.50},
        "encoding_evasion": {"total": 20, "evaded": 5, "asr": 0.25},
        "homoglyph_unicode": {"total": 20, "evaded": 8, "asr": 0.40},
        "fragmentation": {"total": 20, "evaded": 0, "asr": 0.0},
        "truncation_padding": {"total": 20, "evaded": 5, "asr": 0.25},
        "implicit_instruction": {"total": 20, "evaded": 0, "asr": 0.0},
        "structural_dilution": {"total": 20, "evaded": 2, "asr": 0.10},
        "social_engineering": {"total": 20, "evaded": 4, "asr": 0.20},
        "counter_defensive": {"total": 20, "evaded": 4, "asr": 0.20},
    },
    "comparison_to_training_rounds": {
        "round_2_benchmark_asr": 0.20,
        "round_2_generation_asr": 0.317,
        "note": (
            "Round-2 numbers measured during training; "
            "this adaptive ASR measured on final v4 model as test-time attack"
        ),
    },
    "metadata": {
        "model_version": "v4",
        "attack_method": "pwws",
        "model_path": "src/cloneguard/model/mini_semantic.onnx",
        "time_limit_minutes": 90,
        "distinguishing_note": (
            "Adaptive attack: fresh PWWS against final v4 model. "
            "NOT the round-2 training-time ASR (20.0%)."
        ),
    },
}


# ---------------------------------------------------------------------------
# Helper: validate a result dict against the schema
# ---------------------------------------------------------------------------


def validate_result(result: dict) -> None:
    """Validate that a benchmark result dict conforms to the expected schema.

    Raises AssertionError if any required field is missing or invalid.
    """
    required_top_keys = {
        "adaptive_asr",
        "per_category",
        "confidence_interval",
        "metadata",
    }
    missing = required_top_keys - set(result.keys())
    assert not missing, f"Missing top-level keys: {missing}"

    asr = result["adaptive_asr"]
    assert isinstance(asr, (int, float)), "adaptive_asr must be numeric"
    assert 0.0 <= asr <= 1.0, f"adaptive_asr={asr} out of [0, 1]"

    per_cat = result["per_category"]
    assert isinstance(per_cat, dict), "per_category must be a dict"
    assert len(per_cat) >= 5, f"per_category has only {len(per_cat)} categories (need >= 5)"
    for cat_name, cat_data in per_cat.items():
        assert "asr" in cat_data, f"per_category['{cat_name}'] missing 'asr'"
        cat_asr = cat_data["asr"]
        assert 0.0 <= cat_asr <= 1.0, f"per_category['{cat_name}'].asr={cat_asr} out of [0, 1]"

    ci = result["confidence_interval"]
    assert "ci_low" in ci, "confidence_interval missing ci_low"
    assert "ci_high" in ci, "confidence_interval missing ci_high"

    meta = result["metadata"]
    assert meta.get("model_version") == "v4", (
        f"metadata.model_version must be 'v4', got {meta.get('model_version')!r}"
    )
    assert meta.get("attack_method") == "pwws", (
        f"metadata.attack_method must be 'pwws', got {meta.get('attack_method')!r}"
    )
    assert "distinguishing_note" in meta, "metadata missing distinguishing_note"

    note = meta["distinguishing_note"]
    assert "NOT" in note or "not" in note, (
        "distinguishing_note must explicitly state this is NOT "
        "the round-2 training-time measurement"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRequiredTopLevelKeys:
    """Test 1: Output JSON has required top-level keys."""

    def test_has_adaptive_asr(self) -> None:
        assert "adaptive_asr" in VALID_RESULT

    def test_has_per_category(self) -> None:
        assert "per_category" in VALID_RESULT

    def test_has_confidence_interval(self) -> None:
        assert "confidence_interval" in VALID_RESULT

    def test_has_metadata(self) -> None:
        assert "metadata" in VALID_RESULT

    def test_missing_key_raises(self) -> None:
        """validate_result should fail when a required key is absent."""
        bad = dict(VALID_RESULT)
        del bad["adaptive_asr"]
        with pytest.raises(AssertionError, match="Missing top-level keys"):
            validate_result(bad)


class TestAdaptiveAsrRange:
    """Test 2: adaptive_asr is a float in [0.0, 1.0]."""

    def test_asr_is_float(self) -> None:
        asr = VALID_RESULT["adaptive_asr"]
        assert isinstance(asr, (int, float))

    def test_asr_in_range(self) -> None:
        asr = VALID_RESULT["adaptive_asr"]
        assert 0.0 <= asr <= 1.0

    def test_asr_above_1_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["adaptive_asr"] = 1.5
        with pytest.raises(AssertionError):
            validate_result(bad)

    def test_asr_below_0_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["adaptive_asr"] = -0.1
        with pytest.raises(AssertionError):
            validate_result(bad)


class TestPerCategorySchema:
    """Test 3: per_category dict has at least 5 categories with asr values in [0.0, 1.0]."""

    def test_at_least_5_categories(self) -> None:
        assert len(VALID_RESULT["per_category"]) >= 5

    def test_all_category_asr_in_range(self) -> None:
        for cat_name, cat_data in VALID_RESULT["per_category"].items():
            assert 0.0 <= cat_data["asr"] <= 1.0, (
                f"Category {cat_name!r} ASR out of range: {cat_data['asr']}"
            )

    def test_fewer_than_5_categories_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["per_category"] = {
            "cat_a": {"total": 5, "evaded": 1, "asr": 0.2},
            "cat_b": {"total": 5, "evaded": 2, "asr": 0.4},
        }
        with pytest.raises(AssertionError, match="only 2 categories"):
            validate_result(bad)


class TestMetadataSchema:
    """Test 4: metadata contains model_version='v4', attack_method='pwws', distinguishing_note."""

    def test_model_version_v4(self) -> None:
        assert VALID_RESULT["metadata"]["model_version"] == "v4"

    def test_attack_method_pwws(self) -> None:
        assert VALID_RESULT["metadata"]["attack_method"] == "pwws"

    def test_distinguishing_note_present(self) -> None:
        assert "distinguishing_note" in VALID_RESULT["metadata"]

    def test_wrong_model_version_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["metadata"] = dict(VALID_RESULT["metadata"])
        bad["metadata"]["model_version"] = "v3"
        with pytest.raises(AssertionError, match="model_version must be 'v4'"):
            validate_result(bad)


class TestConfidenceInterval:
    """Test 5: confidence_interval has ci_low and ci_high fields."""

    def test_has_ci_low(self) -> None:
        assert "ci_low" in VALID_RESULT["confidence_interval"]

    def test_has_ci_high(self) -> None:
        assert "ci_high" in VALID_RESULT["confidence_interval"]

    def test_missing_ci_low_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["confidence_interval"] = {"ci_high": 0.32, "method": "wilson", "alpha": 0.05}
        with pytest.raises(AssertionError, match="ci_low"):
            validate_result(bad)


class TestDistinguishingNote:
    """Test 6: distinguishing_note explicitly states NOT the round-2 training-time measurement."""

    def test_note_contains_not(self) -> None:
        note = VALID_RESULT["metadata"]["distinguishing_note"]
        assert "NOT" in note or "not" in note, (
            "distinguishing_note must contain 'NOT' to disavow round-2 conflation"
        )

    def test_note_without_not_fails(self) -> None:
        bad = dict(VALID_RESULT)
        bad["metadata"] = dict(VALID_RESULT["metadata"])
        bad["metadata"]["distinguishing_note"] = "This is an adaptive attack measurement."
        with pytest.raises(AssertionError, match="NOT"):
            validate_result(bad)


class TestRealOutputFile:
    """Integration test: validate real benchmark output file if it exists."""

    RESULT_PATH = Path("docs/results/adaptive-pwws-benchmark-2026-03-10.json")

    def test_real_output_schema(self) -> None:
        """If the benchmark has been run, validate its schema."""
        if not self.RESULT_PATH.exists():
            pytest.skip("Benchmark not yet run — skipping real output validation")
        with open(self.RESULT_PATH) as f:
            result = json.load(f)
        validate_result(result)

    def test_real_output_asr_not_exactly_round2(self) -> None:
        """Adaptive ASR must differ from round-2 training-time ASR (20.0%)."""
        if not self.RESULT_PATH.exists():
            pytest.skip("Benchmark not yet run")
        with open(self.RESULT_PATH) as f:
            result = json.load(f)
        asr = result["adaptive_asr"]
        assert asr != 0.20, (
            f"adaptive_asr={asr} equals round-2 training ASR (0.20) — "
            "this suggests the wrong number was written, not a fresh attack measurement"
        )
