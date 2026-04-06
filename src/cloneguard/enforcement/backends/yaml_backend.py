"""YAML policy backend -- thin wrapper around existing PolicyConfig.from_yaml.

This is the simplest backend: YAML is the canonical IR (D-02), so the
YAMLPolicyBackend delegates directly to PolicyConfig.from_yaml() for parsing
and PolicyConfig.model_validate() for validation. No translation layer needed.

Exists primarily so that the factory function get_policy_backend("yaml") returns
a consistent PolicyBackend interface alongside the OPA and Cedar backends.
"""

from __future__ import annotations

from cloneguard.enforcement.policy import PolicyConfig


class YAMLPolicyBackend:
    """Compile YAML policy source to PolicyConfig IR.

    Delegates to PolicyConfig.from_yaml() -- the canonical parser.
    """

    @property
    def name(self) -> str:
        """Backend name for logging and audit."""
        return "yaml"

    def compile(self, source: str) -> PolicyConfig:
        """Parse YAML string and return validated PolicyConfig.

        Args:
            source: YAML policy string.

        Returns:
            Validated PolicyConfig object.

        Raises:
            ValueError: If the YAML is invalid or fails PolicyConfig validation.
        """
        return PolicyConfig.from_yaml(source)

    def validate(self, source: str) -> list[str]:
        """Validate YAML policy syntax without side effects.

        Returns:
            Empty list if valid, list with error message(s) otherwise.
        """
        try:
            PolicyConfig.from_yaml(source)
        except ValueError as e:
            return [str(e)]
        return []
