"""Tests for YAML policy engine (enforcement/policy.py).

Covers: PolicyConfig Pydantic validation, YAMLPolicyEngine loading and
evaluation, variable expansion, threshold gating, per-tool overrides,
dry-run defaults, singleton behavior, and repo-path security guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Lightweight stub for DetectionResult (avoids coupling to detection package)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _FakeDetectionResult:
    verdict: str = "clean"
    confidence: float = 1.0
    signals: list[object] = field(default_factory=list)
    exit_code: int = 0
    message: str = ""
    source_path: str = ""


# ---------------------------------------------------------------------------
# Valid YAML fixtures
# ---------------------------------------------------------------------------
FULL_YAML = """\
version: "1"
verdicts:
  thresholds:
    suspicious_floor: 0.3
    malicious_floor: 0.7
  overrides:
    tool_name:
      Bash:
        suspicious_floor: 0.2
        malicious_floor: 0.6
    agent_type:
      claude-code:
        suspicious_floor: 0.3
        malicious_floor: 0.7
enforcement:
  suspicious:
    Bash:
      filesystem_writable:
        - "${PROJECT_DIR}"
        - "/tmp"
      filesystem_readable:
        - "${PROJECT_DIR}"
        - "${VENV_DIR}"
        - "/usr"
      network_allow:
        - "registry.npmjs.org"
        - "pypi.org"
    Write:
      filesystem_writable:
        - "${PROJECT_DIR}"
      filesystem_readable:
        - "${PROJECT_DIR}"
  malicious:
    action: block
sandbox:
  preferred: auto
  fallback: noop
dry_run: true
"""

MINIMAL_YAML = """\
version: "1"
dry_run: false
"""

INVALID_YAML = """\
version: "1"
verdicts:
  thresholds:
    suspicious_floor: "not_a_number"
"""

MALFORMED_YAML = """\
key: [unterminated
"""


# ===================================================================
# PolicyConfig.from_yaml tests
# ===================================================================
class TestPolicyConfigFromYaml:
    """Test YAML parsing and Pydantic validation."""

    def test_full_yaml_loads_all_fields(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        cfg = PolicyConfig.from_yaml(FULL_YAML)
        assert cfg.version == "1"
        assert cfg.verdicts.thresholds.suspicious_floor == 0.3
        assert cfg.verdicts.thresholds.malicious_floor == 0.7
        assert cfg.dry_run is True
        assert cfg.sandbox.preferred == "auto"
        assert cfg.sandbox.fallback == "noop"

    def test_missing_fields_use_defaults(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        cfg = PolicyConfig.from_yaml("version: '1'\n")
        assert cfg.dry_run is True
        assert cfg.verdicts.thresholds.suspicious_floor == 0.3
        assert cfg.verdicts.thresholds.malicious_floor == 0.7

    def test_invalid_type_raises_value_error(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        with pytest.raises(ValueError, match="Policy validation error"):
            PolicyConfig.from_yaml(INVALID_YAML)

    def test_malformed_yaml_raises_value_error(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        with pytest.raises(ValueError, match="Invalid YAML"):
            PolicyConfig.from_yaml(MALFORMED_YAML)

    def test_empty_yaml_returns_defaults(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        cfg = PolicyConfig.from_yaml("")
        assert cfg.dry_run is True
        assert cfg.verdicts.thresholds.suspicious_floor == 0.3

    def test_non_mapping_yaml_raises_value_error(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        with pytest.raises(ValueError, match="must be a mapping"):
            PolicyConfig.from_yaml("- a list\n- not a dict\n")


# ===================================================================
# PolicyConfig.default() tests
# ===================================================================
class TestPolicyConfigDefault:
    """Test default config factory."""

    def test_default_dry_run_true(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        cfg = PolicyConfig.default()
        assert cfg.dry_run is True

    def test_default_thresholds(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig

        cfg = PolicyConfig.default()
        assert cfg.verdicts.thresholds.suspicious_floor == 0.3
        assert cfg.verdicts.thresholds.malicious_floor == 0.7


# ===================================================================
# YAMLPolicyEngine.load() tests
# ===================================================================
class TestYAMLPolicyEngineLoad:
    """Test loading policy from filesystem."""

    def test_load_from_file(self, tmp_path: Path) -> None:
        from cloneguard.enforcement.policy import YAMLPolicyEngine

        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(FULL_YAML, encoding="utf-8")
        engine = YAMLPolicyEngine.load(policy_path=policy_file)
        assert engine._config.verdicts.thresholds.suspicious_floor == 0.3

    def test_load_returns_default_when_missing(self, tmp_path: Path) -> None:
        from cloneguard.enforcement.policy import YAMLPolicyEngine

        missing = tmp_path / "nonexistent.yaml"
        engine = YAMLPolicyEngine.load(policy_path=missing)
        assert engine._config.dry_run is True
        assert engine._config.verdicts.thresholds.suspicious_floor == 0.3

    def test_load_never_reads_repo_resident_path(self, tmp_path: Path) -> None:
        """Config path under CWD is refused (D-18, T-02-07)."""
        from cloneguard.enforcement.policy import YAMLPolicyEngine

        # Create a policy file under a fake CWD
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        repo_policy = repo_dir / "policy.yaml"
        repo_policy.write_text(MINIMAL_YAML, encoding="utf-8")

        with patch("cloneguard.enforcement.policy.Path.cwd", return_value=repo_dir):
            engine = YAMLPolicyEngine.load(policy_path=repo_policy)
            # Should fall back to defaults because it refused the repo-resident path
            assert engine._config.dry_run is True  # Default, not the file's dry_run=false

    def test_load_handles_corrupt_yaml(self, tmp_path: Path) -> None:
        from cloneguard.enforcement.policy import YAMLPolicyEngine

        bad_file = tmp_path / "policy.yaml"
        bad_file.write_text(MALFORMED_YAML, encoding="utf-8")
        engine = YAMLPolicyEngine.load(policy_path=bad_file)
        assert engine._config.dry_run is True  # Falls back to default


# ===================================================================
# Variable expansion tests
# ===================================================================
class TestVariableExpansion:
    """Test ${PROJECT_DIR} and ${VENV_DIR} expansion."""

    def test_project_dir_expanded(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig, YAMLPolicyEngine

        cfg = PolicyConfig.from_yaml(FULL_YAML)
        engine = YAMLPolicyEngine(config=cfg)
        engine.set_variables(project_dir="/home/user/project", venv_dir="/home/user/.venv")

        result = engine.evaluate(
            _FakeDetectionResult(verdict="suspicious", confidence=0.5),
            tool_name="Bash",
        )
        assert "/home/user/project" in result.constraints.filesystem_writable

    def test_venv_dir_expanded(self) -> None:
        from cloneguard.enforcement.policy import PolicyConfig, YAMLPolicyEngine

        cfg = PolicyConfig.from_yaml(FULL_YAML)
        engine = YAMLPolicyEngine(config=cfg)
        engine.set_variables(project_dir="/home/user/project", venv_dir="/home/user/.venv")

        result = engine.evaluate(
            _FakeDetectionResult(verdict="suspicious", confidence=0.5),
            tool_name="Bash",
        )
        assert "/home/user/.venv" in result.constraints.filesystem_readable


# ===================================================================
# evaluate() tests
# ===================================================================
class TestEvaluate:
    """Test policy evaluation logic."""

    def _make_engine(self, yaml_str: str = FULL_YAML) -> object:
        from cloneguard.enforcement.policy import PolicyConfig, YAMLPolicyEngine

        cfg = PolicyConfig.from_yaml(yaml_str)
        engine = YAMLPolicyEngine(config=cfg)
        engine.set_variables(project_dir="/proj", venv_dir="/venv")
        return engine

    def test_clean_verdict_returns_allow(self) -> None:
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="clean", confidence=1.0),
        )
        assert result.action == "allow"

    def test_suspicious_above_floor_returns_constrain(self) -> None:
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="suspicious", confidence=0.5),
            tool_name="Bash",
        )
        assert result.action == "constrain"
        assert len(result.constraints.filesystem_writable) > 0

    def test_detected_above_floor_returns_block(self) -> None:
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="detected", confidence=0.9),
        )
        assert result.action == "block"

    def test_dry_run_propagated(self) -> None:
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="detected", confidence=0.9),
        )
        assert result.dry_run is True

    def test_dry_run_false_propagated(self) -> None:
        engine = self._make_engine(MINIMAL_YAML)
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="detected", confidence=0.9),
        )
        assert result.dry_run is False

    def test_per_tool_override_thresholds(self) -> None:
        """Bash override: suspicious_floor=0.2, malicious_floor=0.6."""
        engine = self._make_engine()
        # Confidence 0.25 is above Bash suspicious_floor (0.2) but below global (0.3)
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="suspicious", confidence=0.25),
            tool_name="Bash",
        )
        assert result.action == "constrain"

    def test_no_matching_tool_uses_global_thresholds(self) -> None:
        engine = self._make_engine()
        # No override for "UnknownTool"
        # Confidence 0.25 < global suspicious_floor 0.3 -> should be allow
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="suspicious", confidence=0.25),
            tool_name="UnknownTool",
        )
        assert result.action == "allow"

    def test_confidence_below_suspicious_floor_returns_allow(self) -> None:
        """Even with verdict="suspicious", confidence < floor -> allow."""
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="suspicious", confidence=0.1),
            tool_name="Write",
        )
        assert result.action == "allow"

    def test_detected_below_malicious_floor_falls_to_constrain(self) -> None:
        """verdict=detected but confidence < malicious_floor -> constrain (not block)."""
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="detected", confidence=0.5),
            tool_name="Bash",
        )
        assert result.action == "constrain"

    def test_no_constraints_for_unknown_tool(self) -> None:
        """Constrain for unknown tool returns empty constraints."""
        engine = self._make_engine()
        result = engine.evaluate(  # type: ignore[union-attr]
            _FakeDetectionResult(verdict="suspicious", confidence=0.5),
            tool_name="UnknownTool",
        )
        assert result.action == "constrain"
        assert result.constraints.filesystem_writable == ()


# ===================================================================
# Singleton tests
# ===================================================================
class TestSingleton:
    """Test get_policy_engine() singleton."""

    def test_singleton_returns_same_instance(self) -> None:
        import cloneguard.enforcement.policy as policy_mod

        # Reset singleton
        policy_mod._policy_engine = None

        with patch.object(policy_mod, "_POLICY_PATH", Path("/nonexistent/policy.yaml")):
            e1 = policy_mod.get_policy_engine()
            e2 = policy_mod.get_policy_engine()
            assert e1 is e2

        # Clean up
        policy_mod._policy_engine = None
