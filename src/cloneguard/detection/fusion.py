"""Three-signal fusion layer for CloneGuard detection engine.

Replaces the sequential waterfall (pattern -> semantic -> sequence with early return)
with a context-weighted scoring system that collects ALL available signals before
producing a calibrated confidence score.

Design decisions (Phase 4, D-01 through D-09):
- WeightProfile and FusionResult are frozen dataclasses for immutability (T-04-04)
- Weight profiles loaded from package directory, not CWD or repo (T-04-01)
- Operator overrides from ~/.cloneguard/policy.yaml only
- Mode multipliers upweight STRICT signals and downweight LENIENT signals
- Missing signals handled gracefully via weight normalization

Fusion formula:
  For each signal: effective_weight = base_weight * mode_multiplier
  Normalize weights so they sum to 1.0 (handles missing signals)
  weighted_confidence = sum(signal.confidence * normalized_weight)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cloneguard.detection.patterns import ScanMode
from cloneguard.detection.types import SignalResult

logger = logging.getLogger(__name__)

# Package-internal profiles directory (T-04-01: never loaded from CWD or repo)
_PROFILES_DIR = Path(__file__).parent / "profiles"

# Default mode multipliers as nested tuples (frozen-compatible)
_DEFAULT_MODE_MULTIPLIERS: tuple[tuple[str, tuple[tuple[str, float], ...]], ...] = (
    ("strict", (("pattern", 1.2), ("semantic", 1.3), ("sequence", 0.8))),
    ("standard", (("pattern", 1.0), ("semantic", 1.0), ("sequence", 1.0))),
    ("lenient", (("pattern", 0.7), ("semantic", 0.7), ("sequence", 1.2))),
)


@dataclass(frozen=True)
class WeightProfile:
    """Immutable weight configuration for fusion scoring.

    Base weights define the relative importance of each signal type.
    Mode multipliers adjust weights per ScanMode context.
    Uses nested tuples instead of dicts for frozen dataclass compatibility.
    """

    pattern_base: float = 0.4
    semantic_base: float = 0.4
    sequence_base: float = 0.2
    mode_multipliers: tuple[tuple[str, tuple[tuple[str, float], ...]], ...] = (
        _DEFAULT_MODE_MULTIPLIERS
    )
    agent_type: str = "default"

    def get_multiplier(self, mode: str, signal: str) -> float:
        """Look up mode multiplier for a signal type. Returns 1.0 if not found."""
        for mode_name, signals in self.mode_multipliers:
            if mode_name == mode:
                for sig_name, mult in signals:
                    if sig_name == signal:
                        return mult
                return 1.0
        return 1.0


@dataclass(frozen=True)
class FusionResult:
    """Immutable result from FusionLayer.fuse().

    Contains a single calibrated confidence score, the computed verdict,
    and the per-signal breakdown. Signals stored as tuple for frozen compat.
    """

    confidence: float
    verdict: str  # "clean" | "suspicious" | "detected"
    signals: tuple[SignalResult, ...] = ()
    melon_triggered: bool = False
    melon_verdict: str = ""


class FusionLayer:
    """Fuses pattern, semantic, and sequence signals into a calibrated confidence score.

    Replaces the early-return waterfall in DetectionEngine.scan() with
    collect-then-fuse: all available signals are gathered first, then combined
    via weighted scoring with mode-dependent multipliers.
    """

    def __init__(self, profile: WeightProfile | None = None) -> None:
        self._profile = profile or WeightProfile()

    @property
    def profile(self) -> WeightProfile:
        return self._profile

    def fuse(
        self,
        signals: list[SignalResult],
        mode: ScanMode,
        agent_type: str = "default",
    ) -> FusionResult:
        """Fuse collected signals into a single calibrated result.

        For each signal:
          effective_weight = base_weight * mode_multiplier(mode, signal_type)
        Weights are normalized to sum to 1.0, handling missing signals gracefully.
        Verdict thresholds: detected >= 0.6 (if any signal is "detected"), suspicious >= 0.4.
        """
        if not signals:
            return FusionResult(confidence=0.0, verdict="clean", signals=())

        mode_str = mode.value

        # Base weight lookup by signal type
        base_weights: dict[str, float] = {
            "pattern": self._profile.pattern_base,
            "semantic": self._profile.semantic_base,
            "sequence": self._profile.sequence_base,
        }

        # Compute effective weights for each present signal
        effective_weights: list[float] = []
        for sig in signals:
            base = base_weights.get(sig.signal_type, 0.2)
            mult = self._profile.get_multiplier(mode_str, sig.signal_type)
            effective_weights.append(base * mult)

        # Normalize so weights sum to 1.0
        total_weight = sum(effective_weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in effective_weights]
        else:
            normalized_weights = [1.0 / len(signals)] * len(signals)

        # Compute weighted confidence
        weighted_confidence = sum(
            sig.confidence * nw for sig, nw in zip(signals, normalized_weights)
        )

        # Clamp to [0.0, 1.0]
        weighted_confidence = max(0.0, min(1.0, weighted_confidence))

        # Determine verdict
        any_detected = any(s.verdict == "detected" for s in signals)
        if any_detected and weighted_confidence >= 0.6:
            verdict = "detected"
        elif weighted_confidence >= 0.4:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return FusionResult(
            confidence=weighted_confidence,
            verdict=verdict,
            signals=tuple(signals),
        )


def load_weight_profile(
    agent_type: str = "default",
    override_path: Path | None = None,
) -> WeightProfile:
    """Load a WeightProfile from YAML.

    Search order:
    1. override_path (operator-specified, e.g. ~/.cloneguard/policy.yaml fusion.weights)
    2. profiles/{agent_type}.yaml in the package directory
    3. profiles/default.yaml in the package directory
    4. Hardcoded WeightProfile() defaults

    Returns WeightProfile() default on any error (file missing, parse error).
    Profiles are loaded from the package directory only (T-04-01).
    """
    paths_to_try: list[Path] = []

    if override_path is not None:
        paths_to_try.append(override_path)

    if agent_type != "default":
        paths_to_try.append(_PROFILES_DIR / f"{agent_type}.yaml")

    paths_to_try.append(_PROFILES_DIR / "default.yaml")

    for path in paths_to_try:
        try:
            if not path.exists():
                continue
            data = yaml.safe_load(path.read_text())
            if data is None:
                continue
            return _parse_weight_profile(data)
        except Exception:
            logger.warning("Failed to load weight profile from %s", path, exc_info=True)
            continue

    return WeightProfile()


def _parse_weight_profile(data: dict[str, Any]) -> WeightProfile:
    """Parse a YAML dict into a WeightProfile.

    Expected YAML structure:
      agent_type: "default"
      weights:
        pattern_base: 0.40
        semantic_base: 0.40
        sequence_base: 0.20
      mode_multipliers:
        strict: {pattern: 1.2, semantic: 1.3, sequence: 0.8}
        standard: {pattern: 1.0, semantic: 1.0, sequence: 1.0}
        lenient: {pattern: 0.7, semantic: 0.7, sequence: 1.2}
    """
    weights = data.get("weights", {})
    raw_mults = data.get("mode_multipliers", {})

    # Convert nested dicts to nested tuples for frozen dataclass compat
    mode_multipliers: list[tuple[str, tuple[tuple[str, float], ...]]] = []
    for mode_name, signal_dict in raw_mults.items():
        if isinstance(signal_dict, dict):
            signal_tuples = tuple(
                (str(k), float(v)) for k, v in signal_dict.items()
            )
            mode_multipliers.append((str(mode_name), signal_tuples))

    return WeightProfile(
        pattern_base=float(weights.get("pattern_base", 0.4)),
        semantic_base=float(weights.get("semantic_base", 0.4)),
        sequence_base=float(weights.get("sequence_base", 0.2)),
        mode_multipliers=tuple(mode_multipliers) if mode_multipliers else _DEFAULT_MODE_MULTIPLIERS,
        agent_type=str(data.get("agent_type", "default")),
    )
