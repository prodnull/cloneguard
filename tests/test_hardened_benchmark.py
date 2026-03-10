"""Test stubs for HARD-04: hardened benchmark output schema validation.

Validates that docs/results/hardened-benchmark-2026-03-10.json exists and
contains all required fields with valid types. These tests verify the
benchmark ran successfully and produced well-formed output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BENCHMARK_JSON = Path("docs/results/hardened-benchmark-2026-03-10.json")


@pytest.fixture(scope="module")
def benchmark_data() -> dict:
    """Load the benchmark results JSON."""
    if not BENCHMARK_JSON.exists():
        pytest.skip(f"Benchmark results not yet generated: {BENCHMARK_JSON}")
    with open(BENCHMARK_JSON) as f:
        return json.load(f)


class TestBenchmarkOutputSchema:
    """HARD-04: benchmark output contains all required top-level keys."""

    def test_required_top_level_keys(self, benchmark_data: dict) -> None:
        """All required top-level keys must be present."""
        required = {"recall", "fpr", "mahalanobis", "asr", "latency", "delta_from_v3"}
        missing = required - set(benchmark_data.keys())
        assert not missing, f"Missing required keys: {missing}"

    def test_metadata_fields(self, benchmark_data: dict) -> None:
        """date, model_version, training fields should be present."""
        assert "date" in benchmark_data, "Missing 'date' field"
        assert "model_version" in benchmark_data, "Missing 'model_version' field"

    def test_recall_fields(self, benchmark_data: dict) -> None:
        """recall.overall must be float in [0, 1]; per_category must be a dict."""
        recall = benchmark_data["recall"]
        assert "overall" in recall, "Missing recall.overall"
        assert isinstance(recall["overall"], (int, float)), "recall.overall must be numeric"
        assert 0.0 <= recall["overall"] <= 1.0, f"recall.overall={recall['overall']} out of [0, 1]"
        assert "per_category" in recall, "Missing recall.per_category"
        assert isinstance(recall["per_category"], dict), "recall.per_category must be a dict"

    def test_fpr_fields(self, benchmark_data: dict) -> None:
        """fpr.overall must be float in [0, 1]."""
        fpr = benchmark_data["fpr"]
        assert "overall" in fpr, "Missing fpr.overall"
        assert isinstance(fpr["overall"], (int, float)), "fpr.overall must be numeric"
        assert 0.0 <= fpr["overall"] <= 1.0, f"fpr.overall={fpr['overall']} out of [0, 1]"

    def test_mahalanobis_fields(self, benchmark_data: dict) -> None:
        """mahalanobis section must have detection_rate, fpr, and threshold."""
        mah = benchmark_data["mahalanobis"]
        for key in ("detection_rate", "fpr", "threshold"):
            assert key in mah, f"Missing mahalanobis.{key}"
            assert isinstance(mah[key], (int, float)), f"mahalanobis.{key} must be numeric"
        assert 0.0 <= mah["fpr"] <= 1.0, f"mahalanobis.fpr={mah['fpr']} out of [0, 1]"

    def test_asr_fields(self, benchmark_data: dict) -> None:
        """asr section must be present with numeric values."""
        asr = benchmark_data["asr"]
        assert isinstance(asr, dict), "asr must be a dict"
        for key, val in asr.items():
            assert isinstance(val, (int, float)), f"asr.{key} must be numeric"

    def test_latency_fields(self, benchmark_data: dict) -> None:
        """latency must contain p50_ms, p95_ms, and gate_pass."""
        lat = benchmark_data["latency"]
        for key in ("p50_ms", "p95_ms", "gate_pass"):
            assert key in lat, f"Missing latency.{key}"
        assert isinstance(lat["p50_ms"], (int, float)), "latency.p50_ms must be numeric"
        assert isinstance(lat["p95_ms"], (int, float)), "latency.p95_ms must be numeric"
        assert isinstance(lat["gate_pass"], bool), "latency.gate_pass must be bool"

    def test_delta_fields(self, benchmark_data: dict) -> None:
        """delta_from_v3 must contain recall_change, fpr_change, asr_change."""
        delta = benchmark_data["delta_from_v3"]
        for key in ("recall_change", "fpr_change", "asr_change"):
            assert key in delta, f"Missing delta_from_v3.{key}"
            assert isinstance(delta[key], (int, float)), f"delta_from_v3.{key} must be numeric"


class TestBenchmarkValues:
    """Spot-check benchmark values for plausible ranges."""

    def test_recall_not_zero(self, benchmark_data: dict) -> None:
        """Combined pipeline recall should be > 0 (some detection)."""
        assert benchmark_data["recall"]["overall"] > 0.0, (
            "Overall recall is 0 — pipeline detects nothing"
        )

    def test_mahalanobis_threshold_matches_calibration(self, benchmark_data: dict) -> None:
        """Mahalanobis threshold should be positive (calibration sanity check)."""
        assert benchmark_data["mahalanobis"]["threshold"] > 0.0

    def test_latency_p95_gate(self, benchmark_data: dict) -> None:
        """HARD-05: p95 latency gate must pass (<= 25ms per sample on M-series CPU)."""
        lat = benchmark_data["latency"]
        assert lat["gate_pass"], (
            f"HARD-05 latency gate FAILED: p95={lat['p95_ms']:.1f}ms (limit 25ms)"
        )
