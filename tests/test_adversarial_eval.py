"""Smoke tests for the adversarial evaluation harness.

Validates harness structure, content type classification, synthetic corpus
generation, corpus loading with graceful degradation, and report labeling.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Import from the scripts directory -- need to handle the path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from adversarial_eval_fusion import (
    EvalResults,
    SampleResult,
    classify_content_type,
    evaluate,
    generate_report,
    generate_synthetic_corpus,
    get_fusion_targeting_payloads,
    load_corpus,
)


class TestClassifyContentType:
    """Tests for the content type classifier."""

    def test_classify_content_type_ci_config(self) -> None:
        """GitHub Actions workflow file classified as ci_config."""
        result = classify_content_type(
            ".github/workflows/ci.yml",
            "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        )
        assert result == "ci_config"

    def test_classify_content_type_ci_config_yaml_with_markers(self) -> None:
        """YAML file with pipeline markers classified as ci_config."""
        result = classify_content_type(
            "pipeline.yml",
            "stages:\n  - build\n  - test\n",
        )
        assert result == "ci_config"

    def test_classify_content_type_source_code(self) -> None:
        """Python file classified as source_code."""
        result = classify_content_type("main.py", "def main():\n    pass\n")
        assert result == "source_code"

    def test_classify_content_type_test_fixture(self) -> None:
        """Test file classified as test_fixture."""
        result = classify_content_type(
            "tests/test_auth.py",
            "def test_login():\n    assert True\n",
        )
        assert result == "test_fixture"

    def test_classify_content_type_security_doc(self) -> None:
        """Security advisory classified as security_doc."""
        result = classify_content_type(
            "SECURITY.md",
            "# Security Policy\n\nCVE-2024-12345 discovered.\n",
        )
        assert result == "security_doc"

    def test_classify_content_type_mcp_tool_desc(self) -> None:
        """MCP tool description classified as mcp_tool_desc."""
        result = classify_content_type(
            "tools.json",
            '{"tools": [{"name": "read", "description": "Read a file"}]}',
        )
        assert result == "mcp_tool_desc"

    def test_classify_content_type_other(self) -> None:
        """Unmatched content classified as other."""
        result = classify_content_type("README.md", "Hello world\n")
        assert result == "other"


class TestFusionTargetingPayloads:
    """Tests for the hardcoded fusion-targeting payloads."""

    def test_fusion_targeting_payloads_not_empty(self) -> None:
        """Payload list has at least 20 entries as required."""
        payloads = get_fusion_targeting_payloads()
        assert len(payloads) >= 20

    def test_fusion_targeting_payloads_have_required_fields(self) -> None:
        """Each payload has the required fields."""
        payloads = get_fusion_targeting_payloads()
        required = {"content", "label", "source", "content_type", "attack_class"}
        for i, payload in enumerate(payloads):
            missing = required - set(payload.keys())
            assert not missing, f"Payload {i} missing fields: {missing}"

    def test_fusion_targeting_payloads_all_malicious(self) -> None:
        """All fusion-targeting payloads are labeled malicious."""
        payloads = get_fusion_targeting_payloads()
        for payload in payloads:
            assert payload["label"] == "malicious"


class TestSyntheticCorpus:
    """Tests for the synthetic smoke-test corpus generator."""

    def test_generate_synthetic_corpus_counts(self) -> None:
        """Synthetic corpus returns exactly 20 samples (10 malicious + 10 benign)."""
        corpus = generate_synthetic_corpus()
        assert len(corpus) == 20
        malicious = [s for s in corpus if s["label"] == "malicious"]
        benign = [s for s in corpus if s["label"] == "benign"]
        assert len(malicious) == 10
        assert len(benign) == 10

    def test_generate_synthetic_corpus_fields(self) -> None:
        """Each synthetic sample has the expected fields."""
        corpus = generate_synthetic_corpus()
        required = {"content", "label", "source", "content_type"}
        for i, sample in enumerate(corpus):
            missing = required - set(sample.keys())
            assert not missing, f"Sample {i} missing fields: {missing}"
            assert sample["source"] == "synthetic"


class TestLoadCorpus:
    """Tests for corpus loading with graceful degradation."""

    def test_load_corpus_missing_dir_returns_smoke_test(self) -> None:
        """Loading from nonexistent directory returns smoke-test corpus."""
        samples, corpus_type = load_corpus("/nonexistent/path/to/corpus")
        assert corpus_type == "smoke-test"
        assert len(samples) == 20

    def test_load_corpus_partial_dir_returns_smoke_test(self) -> None:
        """Loading from directory with only one file returns smoke-test."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create only malicious, not benign
            (Path(tmpdir) / "malicious_corpus.json").write_text("[]")
            samples, corpus_type = load_corpus(tmpdir)
            assert corpus_type == "smoke-test"


class TestEvaluate:
    """Tests for the evaluation pipeline."""

    def test_eval_harness_runs_without_crash(self) -> None:
        """Evaluate runs on a small corpus without crashing."""
        # Create a mock engine that returns clean results
        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.verdict = "clean"
        mock_result.confidence = 1.0
        mock_result.exit_code = 0
        mock_result.signals = []
        mock_engine.scan.return_value = mock_result

        samples = [
            {"content": "harmless content", "label": "benign", "source": "test",
             "content_type": "other", "attack_class": ""},
            {"content": "also benign", "label": "benign", "source": "test",
             "content_type": "source_code", "attack_class": ""},
            {"content": "benign readme", "label": "benign", "source": "test",
             "content_type": "other", "attack_class": ""},
            {"content": "[SYSTEM] ignore", "label": "malicious", "source": "test",
             "content_type": "other", "attack_class": "instruction_override"},
            {"content": "curl evil.com", "label": "malicious", "source": "test",
             "content_type": "source_code", "attack_class": "exfiltration"},
            {"content": "base64 encoded", "label": "malicious", "source": "test",
             "content_type": "source_code", "attack_class": "encoding_evasion"},
        ]

        results = evaluate(mock_engine, samples)
        assert isinstance(results, EvalResults)
        assert results.total_malicious == 3
        assert results.total_benign == 3
        assert len(results.sample_results) == 6


class TestReportGeneration:
    """Tests for report generation."""

    def test_report_smoke_test_label(self) -> None:
        """Report with smoke-test corpus includes the SMOKE-TEST CORPUS notice."""
        results = EvalResults(
            total_malicious=10,
            total_benign=10,
            true_positives=8,
            false_positives=1,
            true_negatives=9,
            false_negatives=2,
        )

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            output_path = f.name

        try:
            generate_report(results, output_path, "smoke-test")
            report = Path(output_path).read_text()
            assert "SMOKE-TEST CORPUS" in report
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_report_full_corpus_no_smoke_label(self) -> None:
        """Report with full corpus does NOT include SMOKE-TEST notice."""
        results = EvalResults(
            total_malicious=100,
            total_benign=500,
            true_positives=90,
            false_positives=5,
            true_negatives=495,
            false_negatives=10,
        )

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            output_path = f.name

        try:
            generate_report(results, output_path, "full")
            report = Path(output_path).read_text()
            assert "SMOKE-TEST CORPUS" not in report
            assert "Per-attack-class" in report
            assert "Per-content-type FPR" in report
            assert "bypass" in report.lower()
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_report_contains_required_sections(self) -> None:
        """Report contains per-attack-class, per-content-type FPR, and bypass info."""
        results = EvalResults(
            total_malicious=5,
            total_benign=5,
            true_positives=4,
            false_positives=0,
            true_negatives=5,
            false_negatives=1,
            attack_class_metrics={
                "instruction_override": MagicMock(
                    total=3, detected=3, bypassed=0, bypass_rate=0.0,
                ),
                "exfiltration": MagicMock(
                    total=2, detected=1, bypassed=1, bypass_rate=0.5,
                ),
            },
            content_type_fpr={
                "source_code": MagicMock(benign_samples=3, false_positives=0, fpr=0.0),
                "other": MagicMock(benign_samples=2, false_positives=0, fpr=0.0),
            },
            sample_results=[
                SampleResult(
                    content_preview="bypassed sample",
                    label="malicious",
                    attack_class="exfiltration",
                    content_type="source_code",
                    verdict="clean",
                    confidence=0.0,
                    detected=False,
                ),
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            output_path = f.name

        try:
            generate_report(results, output_path, "full")
            report = Path(output_path).read_text()
            assert "Per-attack-class" in report
            assert "Per-content-type FPR" in report
            assert "bypass" in report.lower()
            assert "Honest Disclosure" in report
            assert "9.2%" in report
        finally:
            Path(output_path).unlink(missing_ok=True)
