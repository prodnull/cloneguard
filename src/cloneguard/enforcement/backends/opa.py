"""OPA/Rego policy backend -- compiles Rego modules to PolicyConfig IR.

Uses regopy (Microsoft's C++ Rego interpreter with Python bindings) for
in-process evaluation. No OPA server required. (D-01, D-02, GOVN-01)

Key design decision (per D-02): The Rego module is a DATA source that produces
configuration values. It is NOT an evaluation engine. CloneGuard queries the
Rego document ONCE at policy load time (cold path) to extract a PolicyConfig.
The YAMLPolicyEngine then evaluates against that PolicyConfig at runtime (hot
path). regopy.query() is NEVER called on the hot path.

Rego policy contract:
    The Rego module MUST define ``package cloneguard`` and produce a ``policy``
    document at ``data.cloneguard.policy`` with fields matching PolicyConfig.

Example::

    package cloneguard

    default suspicious_floor = 0.3
    default malicious_floor = 0.7

    policy = {
        "version": "1",
        "verdicts": {
            "thresholds": {
                "suspicious_floor": suspicious_floor,
                "malicious_floor": malicious_floor
            }
        },
        "dry_run": false
    }

Supported regopy version: >=1.3 (Rego v0.x-compatible syntax only).
Built-in subset: comparison, object manipulation, string operations.
Network/crypto built-ins (http.send, crypto.*) are NOT supported.

T-05-02 mitigation: regopy Interpreter has built-in evaluation limits.
PolicyConfig.model_validate() catches malformed output. Compilation
happens on cold path only (startup), never per-request.

T-05-05 mitigation: Never log full policy source (may contain thresholds
operator considers sensitive). Log backend name and success/failure only.
"""

from __future__ import annotations

import json
import logging

from cloneguard.enforcement.policy import PolicyConfig

try:
    from regopy import Interpreter
except ImportError as _exc:
    _import_error = _exc

    class Interpreter:  # type: ignore[no-redef]
        """Stub that raises ImportError when regopy is not installed."""

        def __init__(self) -> None:
            msg = (
                "regopy not installed. "
                "Install with: pip install 'cloneguard[opa]' or pip install regopy"
            )
            raise ImportError(msg) from _import_error


logger = logging.getLogger(__name__)

_QUERY_PATH = "data.cloneguard.policy"


class OPAPolicyBackend:
    """Compile OPA/Rego policy to PolicyConfig IR.

    Evaluates a Rego module that produces a structured document at
    ``data.cloneguard.policy`` matching PolicyConfig semantics, then
    validates and returns a PolicyConfig object.
    """

    def __init__(self) -> None:
        """Verify regopy is available at construction time.

        Raises ImportError immediately if regopy is not installed,
        rather than deferring to compile() time.
        """
        # Probe that regopy is importable by creating a throwaway interpreter
        _ = Interpreter()

    @property
    def name(self) -> str:
        """Backend name for logging and audit."""
        return "opa"

    def compile(self, source: str) -> PolicyConfig:
        """Parse Rego module and compile to PolicyConfig.

        Creates a regopy Interpreter, loads the Rego module, queries
        ``data.cloneguard.policy``, and validates the result against
        the PolicyConfig Pydantic model.

        Args:
            source: Rego policy module source text.

        Returns:
            Validated PolicyConfig object.

        Raises:
            ValueError: If the Rego is invalid, the query returns no
                result, or the output fails PolicyConfig validation.
        """
        try:
            rego = Interpreter()
            rego.add_module("policy.rego", source)
            output = rego.query(_QUERY_PATH)
        except Exception as e:
            msg = f"Rego compilation failed: {e}"
            raise ValueError(msg) from e

        # Parse the output JSON
        output_str = str(output)
        if output_str == "undefined":
            msg = (
                "Rego policy did not produce a document at "
                f"'{_QUERY_PATH}'. Ensure the module defines "
                "'package cloneguard' and a 'policy' rule."
            )
            raise ValueError(msg)

        try:
            parsed = json.loads(output_str)
        except json.JSONDecodeError as e:
            msg = f"Failed to parse Rego query output as JSON: {e}"
            raise ValueError(msg) from e

        # regopy wraps results in {"expressions": [...]}
        expressions = parsed.get("expressions", [])
        if not expressions:
            msg = (
                "Rego query returned empty expressions. Ensure the "
                "policy rule produces a non-empty document."
            )
            raise ValueError(msg)

        policy_dict = expressions[0]

        try:
            config = PolicyConfig.model_validate(policy_dict)
        except Exception as e:
            msg = f"Rego policy output failed PolicyConfig validation: {e}"
            raise ValueError(msg) from e

        logger.info("OPA backend compiled policy successfully")
        return config

    def validate(self, source: str) -> list[str]:
        """Validate Rego policy syntax without side effects.

        Returns:
            Empty list if valid, list with error message(s) otherwise.
        """
        try:
            self.compile(source)
        except ValueError as e:
            return [str(e)]
        return []
