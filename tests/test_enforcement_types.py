"""Tests for enforcement type contracts and Verdict enum transition.

Covers:
- Verdict enum SAFE/SUSPICIOUS/MALICIOUS names with backward-compatible aliases
- PolicyDecision frozen dataclass with defaults
- Constraints frozen dataclass with tuple fields
- EnforcementOutcome frozen dataclass
"""

from __future__ import annotations

import dataclasses

import pytest

from cloneguard.detection.patterns import Verdict
from cloneguard.enforcement.types import Constraints, EnforcementOutcome, PolicyDecision


class TestVerdictEnum:
    """Verdict enum transition: new names with backward-compatible string values."""

    def test_safe_value_is_clean(self) -> None:
        """SAFE preserves 'clean' string value for backward compat."""
        assert Verdict.SAFE.value == "clean"

    def test_suspicious_value(self) -> None:
        assert Verdict.SUSPICIOUS.value == "suspicious"

    def test_malicious_value_is_detected(self) -> None:
        """MALICIOUS preserves 'detected' string value for backward compat."""
        assert Verdict.MALICIOUS.value == "detected"

    def test_clean_alias_is_safe(self) -> None:
        """Old CLEAN name is an alias for SAFE (same enum member)."""
        assert Verdict.CLEAN is Verdict.SAFE

    def test_detected_alias_is_malicious(self) -> None:
        """Old DETECTED name is an alias for MALICIOUS (same enum member)."""
        assert Verdict.DETECTED is Verdict.MALICIOUS

    def test_value_lookup_clean(self) -> None:
        """Verdict('clean') resolves to SAFE (canonical name)."""
        assert Verdict("clean") is Verdict.SAFE

    def test_value_lookup_detected(self) -> None:
        """Verdict('detected') resolves to MALICIOUS (canonical name)."""
        assert Verdict("detected") is Verdict.MALICIOUS

    def test_value_lookup_suspicious(self) -> None:
        assert Verdict("suspicious") is Verdict.SUSPICIOUS


class TestPolicyDecision:
    """PolicyDecision frozen dataclass with sensible defaults."""

    def test_default_action_is_allow(self) -> None:
        pd = PolicyDecision()
        assert pd.action == "allow"

    def test_default_dry_run_is_true(self) -> None:
        pd = PolicyDecision()
        assert pd.dry_run is True

    def test_default_constraints_empty(self) -> None:
        pd = PolicyDecision()
        assert pd.constraints == Constraints()

    def test_default_matched_rule_empty(self) -> None:
        pd = PolicyDecision()
        assert pd.matched_rule == ""

    def test_frozen_raises_on_assignment(self) -> None:
        pd = PolicyDecision()
        with pytest.raises(dataclasses.FrozenInstanceError):
            pd.action = "block"  # type: ignore[misc]

    def test_custom_values(self) -> None:
        c = Constraints(
            filesystem_writable=("/tmp",),
            network_allow=("example.com",),
        )
        pd = PolicyDecision(action="constrain", constraints=c, dry_run=False, matched_rule="R-01")
        assert pd.action == "constrain"
        assert pd.constraints.filesystem_writable == ("/tmp",)
        assert pd.constraints.network_allow == ("example.com",)
        assert pd.dry_run is False
        assert pd.matched_rule == "R-01"


class TestConstraints:
    """Constraints frozen dataclass with immutable tuple fields."""

    def test_default_empty_tuples(self) -> None:
        c = Constraints()
        assert c.filesystem_writable == ()
        assert c.filesystem_readable == ()
        assert c.network_allow == ()

    def test_frozen_raises_on_assignment(self) -> None:
        c = Constraints()
        with pytest.raises(dataclasses.FrozenInstanceError):
            c.filesystem_writable = ("/tmp",)  # type: ignore[misc]

    def test_tuple_fields_are_immutable(self) -> None:
        """Tuples are used (not lists) so contents cannot be mutated in-place."""
        c = Constraints(filesystem_writable=("/tmp",))
        assert isinstance(c.filesystem_writable, tuple)
        assert isinstance(c.filesystem_readable, tuple)
        assert isinstance(c.network_allow, tuple)


class TestEnforcementOutcome:
    """EnforcementOutcome frozen dataclass."""

    def test_default_adapter_name_noop(self) -> None:
        eo = EnforcementOutcome()
        assert eo.adapter_name == "noop"

    def test_default_action_taken_allow(self) -> None:
        eo = EnforcementOutcome()
        assert eo.action_taken == "allow"

    def test_default_dry_run_true(self) -> None:
        eo = EnforcementOutcome()
        assert eo.dry_run is True

    def test_default_constraints_empty(self) -> None:
        eo = EnforcementOutcome()
        assert eo.constraints_applied == Constraints()

    def test_frozen_raises_on_assignment(self) -> None:
        eo = EnforcementOutcome()
        with pytest.raises(dataclasses.FrozenInstanceError):
            eo.adapter_name = "landlock"  # type: ignore[misc]

    def test_custom_values(self) -> None:
        c = Constraints(network_allow=("api.example.com",))
        eo = EnforcementOutcome(
            adapter_name="seatbelt",
            action_taken="constrain",
            constraints_applied=c,
            dry_run=False,
        )
        assert eo.adapter_name == "seatbelt"
        assert eo.action_taken == "constrain"
        assert eo.constraints_applied.network_allow == ("api.example.com",)
        assert eo.dry_run is False
