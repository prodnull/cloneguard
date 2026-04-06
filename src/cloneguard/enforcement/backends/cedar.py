"""Cedar policy backend -- compiles Cedar policies to PolicyConfig IR.

Uses cedarpy (Rust Cedar engine with Python bindings via PyO3) for in-process
policy validation. Designed for AWS Bedrock AgentCore integration.
(D-01, D-02, GOVN-02)

Key design decision (per D-02): Cedar's native model is permit/forbid on
principal-action-resource triples. This does not map directly to PolicyConfig's
threshold-based model. The solution: Cedar policies for CloneGuard use a
YAML wrapper document that contains:

  1. ``cedar_policies``: Raw Cedar policy text (validated for syntax via
     cedarpy.format_policies)
  2. ``config``: PolicyConfig-compatible dict (thresholds, enforcement, etc.)

The backend extracts configuration from the ``config`` section, NOT from Cedar
policy evaluation. Cedar policies are validated for syntax correctness and
stored alongside the PolicyConfig for future use (advanced permit/forbid rules).

This pattern keeps Cedar syntax validation separate from configuration
extraction, matching the OPA backend approach: the policy language is a DATA
source for configuration values, not the runtime evaluator.

Cedar policy file format::

    cedar_policies: |
      forbid(
          principal,
          action == Action::"tool_call",
          resource
      )
      when {
          resource.confidence >= 0.7
      };
    config:
      version: "1"
      verdicts:
        thresholds:
          suspicious_floor: 0.3
          malicious_floor: 0.7
      dry_run: false

T-05-03 mitigation: cedarpy validation is bounded. YAML wrapper parsed with
yaml.safe_load (no arbitrary object construction). Cold path only.

T-05-05 mitigation: Never log full policy source (may contain thresholds
operator considers sensitive). Log backend name and success/failure only.
"""

from __future__ import annotations

import logging

import yaml

from cloneguard.enforcement.policy import PolicyConfig

try:
    from cedarpy import format_policies as _format_policies
except ImportError as _exc:
    _import_error = _exc

    def _format_policies(policies: str) -> str:  # type: ignore[misc]
        """Stub that raises ImportError when cedarpy is not installed."""
        msg = (
            "cedarpy not installed. "
            "Install with: pip install 'cloneguard[cedar]' or pip install cedarpy"
        )
        raise ImportError(msg) from _import_error


logger = logging.getLogger(__name__)


class CedarPolicyBackend:
    """Compile Cedar-wrapped YAML policies to PolicyConfig IR.

    The source document is YAML containing a ``cedar_policies`` field
    (Cedar policy text, validated for syntax) and a ``config`` field
    (PolicyConfig-compatible dict).
    """

    def __init__(self) -> None:
        """Verify cedarpy is available at construction time.

        Raises ImportError immediately if cedarpy is not installed,
        rather than deferring to compile() time.
        """
        # Probe that cedarpy is importable with a minimal policy
        try:
            _format_policies("permit(principal, action, resource);")
        except ImportError:
            raise

    @property
    def name(self) -> str:
        """Backend name for logging and audit."""
        return "cedar"

    def compile(self, source: str) -> PolicyConfig:
        """Parse Cedar-wrapped YAML and compile to PolicyConfig.

        1. Parse the YAML wrapper with yaml.safe_load
        2. Extract and validate Cedar policy syntax via cedarpy
        3. Extract the config dict and validate via PolicyConfig

        Args:
            source: YAML document with ``cedar_policies`` and ``config``.

        Returns:
            Validated PolicyConfig object.

        Raises:
            ValueError: If YAML parsing fails, Cedar syntax is invalid,
                or the config section fails PolicyConfig validation.
        """
        # Parse YAML wrapper
        try:
            raw = yaml.safe_load(source)
        except yaml.YAMLError as e:
            msg = f"Invalid YAML wrapper: {e}"
            raise ValueError(msg) from e

        if not isinstance(raw, dict):
            msg = (
                "Cedar policy source must be a YAML document with "
                "'cedar_policies' and 'config' fields"
            )
            raise ValueError(msg)

        # Extract Cedar policies
        cedar_text = raw.get("cedar_policies")
        if not cedar_text or not isinstance(cedar_text, str):
            msg = (
                "Cedar policy source must contain a 'cedar_policies' "
                "field with Cedar policy text"
            )
            raise ValueError(msg)

        # Validate Cedar syntax via cedarpy.format_policies
        try:
            _format_policies(cedar_text)
        except (ValueError, Exception) as e:
            msg = f"Cedar policy syntax validation failed: {e}"
            raise ValueError(msg) from e

        # Extract config section
        config_dict = raw.get("config")
        if not isinstance(config_dict, dict):
            msg = (
                "Cedar policy source must contain a 'config' field "
                "with PolicyConfig-compatible values"
            )
            raise ValueError(msg)

        # Validate and create PolicyConfig
        try:
            config = PolicyConfig.model_validate(config_dict)
        except Exception as e:
            msg = f"Cedar policy config validation failed: {e}"
            raise ValueError(msg) from e

        logger.info("Cedar backend compiled policy successfully")
        return config

    def validate(self, source: str) -> list[str]:
        """Validate Cedar policy syntax and config without side effects.

        Returns:
            Empty list if valid, list with error message(s) otherwise.
        """
        try:
            self.compile(source)
        except ValueError as e:
            return [str(e)]
        return []
