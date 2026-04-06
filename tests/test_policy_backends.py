"""Tests for policy backends (enforcement/backends/).

Covers: PolicyBackend Protocol, YAMLPolicyBackend compile/validate,
get_policy_backend factory, round-trip through YAMLPolicyEngine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Lightweight stub for DetectionResult (avoids coupling to detection package)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _FakeDetectionResult:
    verdict: str = "clean"
    confidence: float = 1.0
    signals: list[Any] = field(default_factory=list)
    exit_code: int = 0
    message: str = ""
    source_path: str = ""


# ---------------------------------------------------------------------------
# YAML policy fixtures
# ---------------------------------------------------------------------------
BASIC_YAML_POLICY = """\
version: "1"
verdicts:
  thresholds:
    suspicious_floor: 0.25
    malicious_floor: 0.65
dry_run: false
"""

INVALID_YAML_POLICY = """\
version: "1"
verdicts:
  thresholds:
    suspicious_floor: "not_a_number"
"""

YAML_WITH_OVERRIDES = """\
version: "1"
verdicts:
  thresholds:
    suspicious_floor: 0.3
    malicious_floor: 0.7
  overrides:
    tool_name:
      Write:
        suspicious_floor: 0.2
        malicious_floor: 0.5
enforcement:
  suspicious:
    Write:
      filesystem_writable:
        - "/tmp"
      filesystem_readable:
        - "/usr"
      network_allow: []
dry_run: false
"""


# ---------------------------------------------------------------------------
# Task 1: PolicyBackend Protocol + YAMLPolicyBackend + get_policy_backend
# ---------------------------------------------------------------------------

class TestYAMLPolicyBackendName:
    def test_name_returns_yaml(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = YAMLPolicyBackend()
        assert backend.name == "yaml"


class TestYAMLPolicyBackendCompile:
    def test_compile_returns_policy_config_with_correct_thresholds(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend
        from cloneguard.enforcement.policy import PolicyConfig

        backend = YAMLPolicyBackend()
        config = backend.compile(BASIC_YAML_POLICY)
        assert isinstance(config, PolicyConfig)
        assert config.verdicts.thresholds.suspicious_floor == 0.25
        assert config.verdicts.thresholds.malicious_floor == 0.65
        assert config.dry_run is False

    def test_compile_invalid_yaml_raises_value_error(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = YAMLPolicyBackend()
        with pytest.raises(ValueError):
            backend.compile(INVALID_YAML_POLICY)


class TestYAMLPolicyBackendValidate:
    def test_validate_valid_yaml_returns_empty_list(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = YAMLPolicyBackend()
        errors = backend.validate(BASIC_YAML_POLICY)
        assert errors == []

    def test_validate_invalid_yaml_returns_error_list(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = YAMLPolicyBackend()
        errors = backend.validate(INVALID_YAML_POLICY)
        assert len(errors) > 0
        assert isinstance(errors[0], str)


class TestGetPolicyBackend:
    def test_get_yaml_backend(self) -> None:
        from cloneguard.enforcement.backends import get_policy_backend
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = get_policy_backend("yaml")
        assert isinstance(backend, YAMLPolicyBackend)

    def test_get_unknown_backend_raises_value_error(self) -> None:
        from cloneguard.enforcement.backends import get_policy_backend

        with pytest.raises(ValueError, match="Unknown policy backend"):
            get_policy_backend("unknown")


class TestYAMLPolicyBackendProtocol:
    def test_yaml_backend_satisfies_protocol(self) -> None:
        from cloneguard.enforcement.backends import PolicyBackend
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend

        backend = YAMLPolicyBackend()
        assert isinstance(backend, PolicyBackend)


class TestYAMLBackendRoundTrip:
    """Compile YAML -> PolicyConfig -> YAMLPolicyEngine -> PolicyDecision."""

    def test_round_trip_produces_correct_decision(self) -> None:
        from cloneguard.enforcement.backends.yaml_backend import YAMLPolicyBackend
        from cloneguard.enforcement.policy import YAMLPolicyEngine

        backend = YAMLPolicyBackend()
        config = backend.compile(YAML_WITH_OVERRIDES)
        engine = YAMLPolicyEngine(config)

        # Malicious detection above threshold -> block
        result = _FakeDetectionResult(verdict="detected", confidence=0.8)
        decision = engine.evaluate(result, tool_name="Write")
        assert decision.action == "block"
        assert decision.dry_run is False

        # Suspicious detection above suspicious threshold -> constrain
        result_sus = _FakeDetectionResult(verdict="suspicious", confidence=0.3)
        decision_sus = engine.evaluate(result_sus, tool_name="Write")
        assert decision_sus.action == "constrain"

        # Clean detection -> allow
        result_clean = _FakeDetectionResult(verdict="clean", confidence=0.0)
        decision_clean = engine.evaluate(result_clean, tool_name="Write")
        assert decision_clean.action == "allow"
