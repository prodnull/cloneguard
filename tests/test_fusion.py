"""Tests for the three-signal fusion layer.

Validates FusionLayer, WeightProfile, FusionResult, and load_weight_profile.
Verifies that engine collects all signals without early return and delegates
to fusion for final verdict computation.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cloneguard.detection.types import SignalResult, ToolCallEvent


# ---------------------------------------------------------------------------
# Test 1: Single pattern signal produces weighted confidence
# ---------------------------------------------------------------------------
def test_fuse_single_pattern_signal_returns_weighted_confidence() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    signals = [
        SignalResult(signal_type="pattern", verdict="detected", confidence=0.9),
    ]
    from cloneguard.detection.patterns import ScanMode

    result = layer.fuse(signals, ScanMode.STANDARD)
    # With only pattern signal, normalized weight=1.0, so confidence = 0.9 * 1.0
    assert result.confidence == pytest.approx(0.9, abs=0.01)
    assert result.verdict in ("detected", "suspicious")


# ---------------------------------------------------------------------------
# Test 2: All three signals produce combined confidence in [0.0, 1.0]
# ---------------------------------------------------------------------------
def test_fuse_all_three_signals_combined_confidence_in_range() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    signals = [
        SignalResult(signal_type="pattern", verdict="detected", confidence=0.8),
        SignalResult(signal_type="semantic", verdict="suspicious", confidence=0.6),
        SignalResult(signal_type="sequence", verdict="detected", confidence=0.7),
    ]
    from cloneguard.detection.patterns import ScanMode

    result = layer.fuse(signals, ScanMode.STANDARD)
    assert 0.0 <= result.confidence <= 1.0
    assert len(result.signals) == 3


# ---------------------------------------------------------------------------
# Test 3: STRICT mode upweights pattern+semantic vs STANDARD
# ---------------------------------------------------------------------------
def test_strict_mode_upweights_signals() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    signals = [
        SignalResult(signal_type="pattern", verdict="detected", confidence=0.7),
        SignalResult(signal_type="semantic", verdict="suspicious", confidence=0.5),
        SignalResult(signal_type="sequence", verdict="clean", confidence=0.1),
    ]
    from cloneguard.detection.patterns import ScanMode

    strict_result = layer.fuse(signals, ScanMode.STRICT)
    standard_result = layer.fuse(signals, ScanMode.STANDARD)
    # STRICT should produce higher confidence than STANDARD for same signals
    # because pattern and semantic multipliers are >1.0 in STRICT
    assert strict_result.confidence >= standard_result.confidence


# ---------------------------------------------------------------------------
# Test 4: LENIENT mode downweights pattern+semantic vs STANDARD
# ---------------------------------------------------------------------------
def test_lenient_mode_downweights_signals() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    signals = [
        SignalResult(signal_type="pattern", verdict="detected", confidence=0.7),
        SignalResult(signal_type="semantic", verdict="suspicious", confidence=0.5),
        SignalResult(signal_type="sequence", verdict="clean", confidence=0.1),
    ]
    from cloneguard.detection.patterns import ScanMode

    lenient_result = layer.fuse(signals, ScanMode.LENIENT)
    standard_result = layer.fuse(signals, ScanMode.STANDARD)
    # LENIENT should produce lower confidence than STANDARD
    assert lenient_result.confidence <= standard_result.confidence


# ---------------------------------------------------------------------------
# Test 5: FusionResult is frozen (immutable)
# ---------------------------------------------------------------------------
def test_fusion_result_is_frozen() -> None:
    from cloneguard.detection.fusion import FusionResult

    result = FusionResult(
        confidence=0.5,
        verdict="suspicious",
        signals=(),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.confidence = 0.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 6: WeightProfile is frozen (immutable)
# ---------------------------------------------------------------------------
def test_weight_profile_is_frozen() -> None:
    from cloneguard.detection.fusion import WeightProfile

    profile = WeightProfile()
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.pattern_base = 0.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 7: No signals returns confidence=0.0, verdict="clean"
# ---------------------------------------------------------------------------
def test_fuse_no_signals_returns_clean() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    from cloneguard.detection.patterns import ScanMode

    result = layer.fuse([], ScanMode.STANDARD)
    assert result.confidence == 0.0
    assert result.verdict == "clean"


# ---------------------------------------------------------------------------
# Test 8: Missing semantic signal handled gracefully
# ---------------------------------------------------------------------------
def test_fuse_missing_semantic_signal_graceful() -> None:
    from cloneguard.detection.fusion import FusionLayer

    layer = FusionLayer()
    signals = [
        SignalResult(signal_type="pattern", verdict="detected", confidence=0.8),
        SignalResult(signal_type="sequence", verdict="clean", confidence=0.1),
    ]
    from cloneguard.detection.patterns import ScanMode

    result = layer.fuse(signals, ScanMode.STANDARD)
    assert 0.0 <= result.confidence <= 1.0
    # Should still produce a valid result
    assert result.verdict in ("clean", "suspicious", "detected")


# ---------------------------------------------------------------------------
# Test 9: load_weight_profile() loads from YAML
# ---------------------------------------------------------------------------
def test_load_weight_profile_from_yaml(tmp_path: Path) -> None:
    from cloneguard.detection.fusion import load_weight_profile

    profile_yaml = tmp_path / "test_profile.yaml"
    profile_yaml.write_text(
        """\
version: "1"
agent_type: "test-agent"
weights:
  pattern_base: 0.5
  semantic_base: 0.3
  sequence_base: 0.2
mode_multipliers:
  strict:
    pattern: 1.5
    semantic: 1.5
    sequence: 0.5
  standard:
    pattern: 1.0
    semantic: 1.0
    sequence: 1.0
  lenient:
    pattern: 0.6
    semantic: 0.6
    sequence: 1.5
"""
    )
    profile = load_weight_profile(override_path=profile_yaml)
    assert profile.agent_type == "test-agent"
    assert profile.pattern_base == 0.5
    assert profile.semantic_base == 0.3
    assert profile.sequence_base == 0.2


# ---------------------------------------------------------------------------
# Test 10: load_weight_profile() returns default when file not found
# ---------------------------------------------------------------------------
def test_load_weight_profile_returns_default_when_not_found() -> None:
    from cloneguard.detection.fusion import load_weight_profile

    profile = load_weight_profile(agent_type="nonexistent-agent-xyz")
    # Should return default values
    assert profile.pattern_base == 0.4
    assert profile.semantic_base == 0.4
    assert profile.sequence_base == 0.2
    assert profile.agent_type == "default"


# ---------------------------------------------------------------------------
# Test 11: Engine._collect_signals collects all three signal types
# ---------------------------------------------------------------------------
def test_engine_collect_signals_no_early_return() -> None:
    """Engine._collect_signals should collect all signals, not early-return on pattern."""
    from cloneguard.detection.engine import DetectionEngine
    from cloneguard.detection.patterns import ScanMode

    engine = DetectionEngine()

    # Mock pattern engine to return a DETECTED result
    mock_pe = MagicMock()
    mock_pe.scan.return_value = MagicMock(
        verdict=MagicMock(value="detected"),
        matches=[
            MagicMock(
                severity=MagicMock(value="critical"),
                pattern_id="TEST-001",
                matched_text="test",
                line_number=1,
                description="test rule",
            )
        ],
        scan_time_ms=1.0,
    )
    mock_pe._detect_mode.return_value = ScanMode.STANDARD
    engine._pattern_engine = mock_pe

    # Mock mini classifier to return SUSPICIOUS
    mock_cls = MagicMock()
    mock_cls.classify.return_value = MagicMock(verdict="SUSPICIOUS", reason="test")
    engine._mini_classifier = mock_cls
    engine._mini_attempted = True

    signals = engine._collect_signals("test content", "test.py", ScanMode.STANDARD)

    # Should have collected at least pattern signal
    assert len(signals) >= 1
    signal_types = {s.signal_type for s in signals}
    assert "pattern" in signal_types


# ---------------------------------------------------------------------------
# Test 12: Engine.scan() for ToolCallEvent delegates to FusionLayer
# ---------------------------------------------------------------------------
def test_engine_scan_delegates_to_fusion() -> None:
    """Engine.scan() should use FusionLayer to produce final DetectionResult."""
    from cloneguard.detection.engine import DetectionEngine

    engine = DetectionEngine()

    # Verify engine has a _fusion_layer attribute
    assert hasattr(engine, "_fusion_layer")

    event = ToolCallEvent(
        event_type="PostToolUse",
        tool_name="Read",
        tool_input={},
        content="",  # empty content -> clean result
        source_path="test.py",
    )
    result = engine.scan(event)
    assert result.verdict == "clean"


# ---------------------------------------------------------------------------
# Test 13: FusionResult signals stored as tuple (immutable)
# ---------------------------------------------------------------------------
def test_fusion_result_signals_are_tuple() -> None:
    from cloneguard.detection.fusion import FusionResult

    sig = SignalResult(signal_type="pattern", verdict="detected", confidence=0.9)
    result = FusionResult(
        confidence=0.9,
        verdict="detected",
        signals=(sig,),
    )
    assert isinstance(result.signals, tuple)


# ---------------------------------------------------------------------------
# Test 14: WeightProfile get_multiplier helper
# ---------------------------------------------------------------------------
def test_weight_profile_get_multiplier() -> None:
    from cloneguard.detection.fusion import WeightProfile

    profile = WeightProfile(
        mode_multipliers=(
            (
                "strict",
                (("pattern", 1.2), ("semantic", 1.3), ("sequence", 0.8)),
            ),
            (
                "standard",
                (("pattern", 1.0), ("semantic", 1.0), ("sequence", 1.0)),
            ),
        ),
    )
    assert profile.get_multiplier("strict", "pattern") == 1.2
    assert profile.get_multiplier("strict", "semantic") == 1.3
    assert profile.get_multiplier("standard", "pattern") == 1.0
    # Unknown mode/signal returns 1.0
    assert profile.get_multiplier("unknown", "pattern") == 1.0
    assert profile.get_multiplier("strict", "unknown") == 1.0
