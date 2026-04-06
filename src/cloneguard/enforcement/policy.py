"""YAML policy engine -- maps detection verdicts to enforcement actions.

Loads operator configuration from ~/.cloneguard/policy.yaml (D-10, D-18, D-19).
Validates with Pydantic models (cold path at startup). Evaluates DetectionResult
against policy rules to produce PolicyDecision (frozen dataclass on hot path).

CRITICAL: Policy config is NEVER loaded from repo-resident paths (D-18).
The detection engine scans content; the policy engine decides what to do about it.
The policy engine NEVER inspects tool_input content directly (Pitfall 6 from research).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from cloneguard.enforcement.types import Constraints, PolicyDecision

logger = logging.getLogger(__name__)

# Operator-controlled config path (D-18, D-19)
_POLICY_PATH = Path.home() / ".cloneguard" / "policy.yaml"


# -----------------------------------------------------------------------
# Pydantic validation models (cold path -- loaded once at startup)
# -----------------------------------------------------------------------


class ThresholdConfig(BaseModel):
    """Global detection threshold floors."""

    model_config = ConfigDict(frozen=True)
    suspicious_floor: float = 0.3
    malicious_floor: float = 0.7


class ToolOverrides(BaseModel):
    """Per-tool or per-agent threshold overrides."""

    model_config = ConfigDict(frozen=True)
    suspicious_floor: float | None = None
    malicious_floor: float | None = None


class VerdictConfig(BaseModel):
    """Verdict classification thresholds and overrides."""

    model_config = ConfigDict(frozen=True)
    thresholds: ThresholdConfig = ThresholdConfig()
    overrides: dict[str, dict[str, ToolOverrides]] = {}


class ToolConstraintConfig(BaseModel):
    """Sandbox constraints for a specific tool under a verdict level."""

    model_config = ConfigDict(frozen=True)
    filesystem_writable: list[str] = []
    filesystem_readable: list[str] = []
    network_allow: list[str] = []


class EnforcementConfig(BaseModel):
    """Per-verdict enforcement rules with per-tool constraints."""

    model_config = ConfigDict(frozen=True)
    suspicious: dict[str, ToolConstraintConfig] = {}
    malicious: dict[str, Any] = {"action": "block"}


class SandboxConfig(BaseModel):
    """Sandbox backend selection."""

    model_config = ConfigDict(frozen=True)
    preferred: str = "auto"
    fallback: str = "noop"


class PolicyConfig(BaseModel):
    """Validated policy configuration loaded from YAML.

    All fields have safe defaults. dry_run=True is the fail-safe default
    per D-13 -- operators must explicitly set dry_run: false to enable
    enforcement.
    """

    model_config = ConfigDict(frozen=True)
    version: str = "1"
    verdicts: VerdictConfig = VerdictConfig()
    enforcement: EnforcementConfig = EnforcementConfig()
    sandbox: SandboxConfig = SandboxConfig()
    dry_run: bool = True  # D-13: default is dry-run enabled

    @classmethod
    def from_yaml(cls, yaml_str: str) -> PolicyConfig:
        """Parse and validate YAML string into PolicyConfig."""
        try:
            raw = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            msg = f"Invalid YAML: {e}"
            raise ValueError(msg) from e
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            msg = "Policy YAML must be a mapping"
            raise ValueError(msg)
        try:
            return cls.model_validate(raw)
        except ValidationError as e:
            msg = f"Policy validation error: {e}"
            raise ValueError(msg) from e

    @classmethod
    def default(cls) -> PolicyConfig:
        """Return default policy config (dry-run, standard thresholds)."""
        return cls()


# -----------------------------------------------------------------------
# YAMLPolicyEngine -- singleton that evaluates DetectionResults
# -----------------------------------------------------------------------


class YAMLPolicyEngine:
    """Evaluates DetectionResult against YAML policy to produce PolicyDecision (D-10).

    Pipeline position: DetectionEngine.scan() -> YAMLPolicyEngine.evaluate() -> PolicyDecision
    The policy engine NEVER inspects tool content. It maps verdict + confidence + context
    to an enforcement action.
    """

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self._config = config or PolicyConfig.default()
        self._variables: dict[str, str] = {}

    @classmethod
    def load(cls, policy_path: Path | None = None) -> YAMLPolicyEngine:
        """Load policy from operator-controlled path (D-18).

        Falls back to default config (dry-run) if file doesn't exist.
        NEVER reads from repo-resident paths.
        """
        path = policy_path or _POLICY_PATH
        # Security check: never read from CWD or repo paths (T-02-07)
        resolved = path.resolve()
        cwd = Path.cwd().resolve()
        if str(resolved).startswith(str(cwd)) and path != _POLICY_PATH:
            logger.warning("Refusing to load policy from repo-resident path: %s", path)
            return cls()

        if not path.exists():
            logger.debug("No policy file at %s, using defaults", path)
            return cls()

        try:
            yaml_str = path.read_text(encoding="utf-8")
            config = PolicyConfig.from_yaml(yaml_str)
            engine = cls(config)
            logger.info("Loaded policy from %s", path)
            return engine
        except (ValueError, OSError) as e:
            logger.warning("Failed to load policy from %s: %s. Using defaults.", path, e)
            return cls()

    def set_variables(self, project_dir: str = "", venv_dir: str = "") -> None:
        """Set variable expansion values for ${PROJECT_DIR} and ${VENV_DIR}."""
        if project_dir:
            self._variables["${PROJECT_DIR}"] = project_dir
        if venv_dir:
            self._variables["${VENV_DIR}"] = venv_dir
        # Also try to detect from environment
        if not project_dir:
            cwd = os.getcwd()
            self._variables.setdefault("${PROJECT_DIR}", cwd)
        if not venv_dir:
            venv = os.environ.get("VIRTUAL_ENV", "")
            if venv:
                self._variables.setdefault("${VENV_DIR}", venv)

    def evaluate(
        self,
        detection_result: Any,  # DetectionResult from detection.types
        tool_name: str = "",
        agent_type: str = "claude-code",
    ) -> PolicyDecision:
        """Map DetectionResult to PolicyDecision (D-03).

        SAFE (clean) -> allow (no constraints)
        SUSPICIOUS -> allow-but-constrain (sandbox tightened)
        MALICIOUS (detected) -> block (no execution)

        Confidence must meet threshold floor for the verdict to take effect.
        If confidence < suspicious_floor, treat as SAFE even if verdict is suspicious.
        """
        verdict: str = detection_result.verdict
        confidence: float = detection_result.confidence

        # Resolve thresholds: per-tool override > per-agent override > global
        thresholds = self._resolve_thresholds(tool_name, agent_type)

        # Apply threshold gating (D-02)
        if verdict == "detected" and confidence >= thresholds.malicious_floor:
            return PolicyDecision(
                action="block",
                dry_run=self._config.dry_run,
                matched_rule=f"malicious(confidence={confidence:.2f})",
            )

        if verdict in ("suspicious", "detected") and confidence >= thresholds.suspicious_floor:
            constraints = self._resolve_constraints(tool_name)
            return PolicyDecision(
                action="constrain",
                constraints=constraints,
                dry_run=self._config.dry_run,
                matched_rule=f"suspicious(tool={tool_name}, confidence={confidence:.2f})",
            )

        return PolicyDecision(
            action="allow",
            dry_run=self._config.dry_run,
            matched_rule="safe",
        )

    def _resolve_thresholds(self, tool_name: str, agent_type: str) -> ThresholdConfig:
        """Resolve effective thresholds: per-tool > per-agent > global."""
        overrides = self._config.verdicts.overrides

        # Check tool_name overrides first
        tool_overrides = overrides.get("tool_name", {}).get(tool_name)
        if tool_overrides:
            return ThresholdConfig(
                suspicious_floor=(
                    tool_overrides.suspicious_floor
                    if tool_overrides.suspicious_floor is not None
                    else self._config.verdicts.thresholds.suspicious_floor
                ),
                malicious_floor=(
                    tool_overrides.malicious_floor
                    if tool_overrides.malicious_floor is not None
                    else self._config.verdicts.thresholds.malicious_floor
                ),
            )

        # Check agent_type overrides
        agent_overrides = overrides.get("agent_type", {}).get(agent_type)
        if agent_overrides:
            return ThresholdConfig(
                suspicious_floor=(
                    agent_overrides.suspicious_floor
                    if agent_overrides.suspicious_floor is not None
                    else self._config.verdicts.thresholds.suspicious_floor
                ),
                malicious_floor=(
                    agent_overrides.malicious_floor
                    if agent_overrides.malicious_floor is not None
                    else self._config.verdicts.thresholds.malicious_floor
                ),
            )

        return self._config.verdicts.thresholds

    def _resolve_constraints(self, tool_name: str) -> Constraints:
        """Resolve constraints for a tool from enforcement config."""
        tool_cfg = self._config.enforcement.suspicious.get(tool_name)
        if tool_cfg is None:
            return Constraints()

        return Constraints(
            filesystem_writable=tuple(self._expand_vars(p) for p in tool_cfg.filesystem_writable),
            filesystem_readable=tuple(self._expand_vars(p) for p in tool_cfg.filesystem_readable),
            network_allow=tuple(tool_cfg.network_allow),
        )

    def _expand_vars(self, path: str) -> str:
        """Expand ${PROJECT_DIR} and ${VENV_DIR} in constraint paths."""
        result = path
        for var, value in self._variables.items():
            result = result.replace(var, value)
        return result


# -----------------------------------------------------------------------
# Module-level singleton
# -----------------------------------------------------------------------

_policy_engine: YAMLPolicyEngine | None = None


def get_policy_engine() -> YAMLPolicyEngine:
    """Return the module-level singleton YAMLPolicyEngine.

    Creates on first call, loading from ~/.cloneguard/policy.yaml.
    Subsequent calls return the same instance.
    """
    global _policy_engine  # noqa: PLW0603
    if _policy_engine is None:
        _policy_engine = YAMLPolicyEngine.load()
        _policy_engine.set_variables()
    return _policy_engine
