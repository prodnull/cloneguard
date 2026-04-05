"""Tests for SARIF 2.1.0 emitter (FNDN-03, D-08, D-09, D-10).

Validates that build_sarif() produces valid SARIF 2.1.0 JSON using sarif-pydantic,
maps CloneGuard verdicts to correct SARIF levels, includes partialFingerprints for
dedup, and caps results at 5,000 per GitHub Advanced Security limits.
"""

from __future__ import annotations

import json
from typing import Any

import pytest


def _make_scan_result(
    *,
    verdict: str = "detected",
    severity: str = "critical",
    rule_id: str = "RH-001",
    file_path: str = "README.md",
    line_number: int = 10,
    matched_text: str = "ignore previous instructions",
    message: str = "Authority impersonation detected",
) -> dict[str, Any]:
    """Helper to construct a scan result dict for build_sarif()."""
    return {
        "verdict": verdict,
        "severity": severity,
        "rule_id": rule_id,
        "file_path": file_path,
        "line_number": line_number,
        "matched_text": matched_text,
        "message": message,
    }


def _make_rules() -> list[Any]:
    """Build a minimal set of SARIF reportingDescriptor rules for tests."""
    from sarif_pydantic import Message, ReportingDescriptor

    return [
        ReportingDescriptor(
            id="RH-001",
            short_description=Message(text="Authority impersonation"),
        ),
        ReportingDescriptor(
            id="RH-002",
            short_description=Message(text="Credential harvesting"),
        ),
    ]


class TestSarifBasicStructure:
    """Test 1 + Test 9: Valid SARIF 2.1.0 JSON with correct schema URI."""

    def test_sarif_version_and_schema(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result()]
        rules = _make_rules()
        sarif = build_sarif(results, rules)

        # Serialize via sarif-pydantic (by_alias=True for camelCase)
        raw = json.loads(sarif.model_dump_json(by_alias=True, exclude_none=True))

        assert raw["version"] == "2.1.0"
        assert raw["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    def test_sarif_output_is_valid_json(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result()]
        rules = _make_rules()
        sarif = build_sarif(results, rules)

        # Must be parseable as valid JSON
        raw_str = sarif.model_dump_json(by_alias=True, exclude_none=True)
        parsed = json.loads(raw_str)
        assert isinstance(parsed, dict)
        assert "runs" in parsed


class TestSarifVerdictMapping:
    """Tests 2-5: Verdict-to-level mapping per D-09."""

    def test_detected_critical_maps_to_error(self) -> None:
        from sarif_pydantic import Level

        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="detected", severity="critical")]
        sarif = build_sarif(results, _make_rules())
        assert sarif.runs[0].results[0].level == Level.ERROR

    def test_detected_medium_maps_to_warning(self) -> None:
        from sarif_pydantic import Level

        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="detected", severity="medium")]
        sarif = build_sarif(results, _make_rules())
        assert sarif.runs[0].results[0].level == Level.WARNING

    def test_suspicious_maps_to_warning(self) -> None:
        from sarif_pydantic import Level

        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="suspicious", severity="")]
        sarif = build_sarif(results, _make_rules())
        assert sarif.runs[0].results[0].level == Level.WARNING

    def test_clean_verdict_not_emitted(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="clean")]
        sarif = build_sarif(results, _make_rules())
        assert len(sarif.runs[0].results) == 0

    def test_detected_low_maps_to_note(self) -> None:
        from sarif_pydantic import Level

        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="detected", severity="low")]
        sarif = build_sarif(results, _make_rules())
        assert sarif.runs[0].results[0].level == Level.NOTE

    def test_detected_high_maps_to_error(self) -> None:
        from sarif_pydantic import Level

        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(verdict="detected", severity="high")]
        sarif = build_sarif(results, _make_rules())
        assert sarif.runs[0].results[0].level == Level.ERROR


class TestSarifRules:
    """Test 6: Pattern rules mapped to reportingDescriptor rules."""

    def test_rules_in_tool_driver(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        rules = _make_rules()
        sarif = build_sarif([], rules)
        driver_rules = sarif.runs[0].tool.driver.rules
        assert len(driver_rules) == 2
        rule_ids = {r.id for r in driver_rules}
        assert "RH-001" in rule_ids
        assert "RH-002" in rule_ids


class TestSarifToolInfo:
    """Test 7: Tool driver name and version."""

    def test_tool_driver_name_and_version(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        sarif = build_sarif([], _make_rules())
        driver = sarif.runs[0].tool.driver
        assert driver.name == "cloneguard"
        # Version should match __version__
        from cloneguard import __version__

        assert driver.version == __version__


class TestSarifPhysicalLocation:
    """Test 8: Result includes physical location with file URI and line number."""

    def test_result_has_location(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result(file_path="src/main.py", line_number=42)]
        sarif = build_sarif(results, _make_rules())
        result = sarif.runs[0].results[0]
        loc = result.locations[0].physical_location
        assert loc.artifact_location.uri == "src/main.py"
        assert loc.region.start_line == 42


class TestSarifResultCap:
    """Test 10: Results capped at 5,000 per GitHub limits (T-03-03)."""

    def test_max_results_cap(self) -> None:
        from cloneguard.audit.sarif import _MAX_RESULTS, build_sarif

        assert _MAX_RESULTS == 5000

        # Create 5,100 results -- only first 5,000 non-clean should appear
        results = [
            _make_scan_result(rule_id=f"RH-{i:04d}", line_number=i)
            for i in range(5100)
        ]
        sarif = build_sarif(results, _make_rules())
        assert len(sarif.runs[0].results) <= 5000


class TestSarifFingerprints:
    """Verify partialFingerprints for deduplication across runs (T-03-02)."""

    def test_result_has_partial_fingerprints(self) -> None:
        from cloneguard.audit.sarif import build_sarif

        results = [_make_scan_result()]
        sarif = build_sarif(results, _make_rules())
        result = sarif.runs[0].results[0]
        assert result.partial_fingerprints is not None
        assert "primaryLocationLineHash" in result.partial_fingerprints


class TestSarifEmitterClass:
    """Test SARIFEmitter high-level class."""

    def test_emit_from_scan_results(self) -> None:
        from cloneguard.audit.sarif import SARIFEmitter

        emitter = SARIFEmitter()
        scan_results = [_make_scan_result()]
        output = emitter.emit_json(scan_results)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 1


class TestBuildRulesFromPatternEngine:
    """Test _build_rules_from_patterns extracts all pattern IDs."""

    def test_builds_reporting_descriptors(self) -> None:
        from cloneguard.audit.sarif import _build_rules_from_patterns
        from cloneguard.detection.patterns import PatternEngine

        engine = PatternEngine()
        rules = _build_rules_from_patterns(engine)
        # Should have at least some rules (204 patterns)
        assert len(rules) > 0
        # Each rule should have an id
        for r in rules:
            assert r.id is not None
            assert len(r.id) > 0
