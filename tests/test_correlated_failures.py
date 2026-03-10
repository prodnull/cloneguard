"""Schema validation tests for correlated failure analysis output.

Validates docs/results/correlated-failures-2026-03-10.json structure,
ensuring per-sample both-miss records have all required fields and
consistent internal counts.

These tests validate the JSON artifact directly — no pipeline invocation needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CORRELATED_FAILURES_JSON = Path("docs/results/correlated-failures-2026-03-10.json")


@pytest.fixture(scope="module")
def cf_data() -> dict:
    """Load correlated failure results JSON."""
    if not CORRELATED_FAILURES_JSON.exists():
        pytest.skip(f"Correlated failure results not yet generated: {CORRELATED_FAILURES_JSON}")
    with open(CORRELATED_FAILURES_JSON) as f:
        return json.load(f)


class TestCorrelatedFailureSchema:
    """BENCH-03: correlated failure output schema validation."""

    def test_has_both_miss_samples_key(self, cf_data: dict) -> None:
        """Output must contain 'both_miss_samples' key with a list value."""
        assert "both_miss_samples" in cf_data, "Missing required key: both_miss_samples"
        assert isinstance(cf_data["both_miss_samples"], list), "both_miss_samples must be a list"

    def test_per_sample_required_fields(self, cf_data: dict) -> None:
        """Each both-miss sample must have all required fields."""
        required_fields = {
            "id",
            "category",
            "text_preview",
            "tier0_detected",
            "tier15_verdict",
            "anomaly_score",
            "anomaly_flagged",
        }
        for i, sample in enumerate(cf_data["both_miss_samples"]):
            missing = required_fields - set(sample.keys())
            assert not missing, (
                f"both_miss_samples[{i}] missing fields: {missing} | sample: {sample}"
            )

    def test_both_miss_tier_verdicts(self, cf_data: dict) -> None:
        """All both-miss samples must have tier0_detected=False and tier15_verdict='SAFE'."""
        for i, sample in enumerate(cf_data["both_miss_samples"]):
            assert sample["tier0_detected"] is False, (
                f"both_miss_samples[{i}] has tier0_detected={sample['tier0_detected']} "
                f"(expected False)"
            )
            assert sample["tier15_verdict"] == "SAFE", (
                f"both_miss_samples[{i}] has tier15_verdict={sample['tier15_verdict']!r} "
                f"(expected 'SAFE')"
            )

    def test_summary_total_both_miss_count(self, cf_data: dict) -> None:
        """Summary total_both_miss must match len(both_miss_samples)."""
        assert "total_both_miss" in cf_data, "Missing required key: total_both_miss"
        expected = len(cf_data["both_miss_samples"])
        actual = cf_data["total_both_miss"]
        assert actual == expected, (
            f"total_both_miss={actual} does not match len(both_miss_samples)={expected}"
        )

    def test_per_category_breakdown_present(self, cf_data: dict) -> None:
        """Output must include per_category_both_miss with per-category counts."""
        assert "per_category_both_miss" in cf_data, "Missing required key: per_category_both_miss"
        assert isinstance(cf_data["per_category_both_miss"], dict), (
            "per_category_both_miss must be a dict"
        )
        per_cat = cf_data["per_category_both_miss"]
        for cat, counts in per_cat.items():
            assert "total" in counts, f"per_category_both_miss[{cat!r}] missing 'total'"
            assert "both_miss" in counts, f"per_category_both_miss[{cat!r}] missing 'both_miss'"
            assert isinstance(counts["total"], int), (
                f"per_category_both_miss[{cat!r}]['total'] must be int"
            )
            assert isinstance(counts["both_miss"], int), (
                f"per_category_both_miss[{cat!r}]['both_miss'] must be int"
            )
            assert counts["both_miss"] <= counts["total"], (
                f"per_category_both_miss[{cat!r}]: both_miss > total"
            )

    def test_per_category_counts_sum_to_total(self, cf_data: dict) -> None:
        """Sum of per-category both_miss counts must equal total_both_miss."""
        per_cat = cf_data.get("per_category_both_miss", {})
        category_sum = sum(v["both_miss"] for v in per_cat.values())
        total = cf_data.get("total_both_miss", -1)
        assert category_sum == total, (
            f"Sum of per-category both_miss counts ({category_sum}) "
            f"does not match total_both_miss ({total})"
        )

    def test_metadata_fields_present(self, cf_data: dict) -> None:
        """Output must include date, model_version, corpus_size, both_miss_rate."""
        for field in ("date", "model_version", "corpus_size", "both_miss_rate"):
            assert field in cf_data, f"Missing required metadata field: {field}"
        assert isinstance(cf_data["both_miss_rate"], float), "both_miss_rate must be float"
        assert 0.0 <= cf_data["both_miss_rate"] <= 1.0, (
            f"both_miss_rate={cf_data['both_miss_rate']} out of [0, 1]"
        )
