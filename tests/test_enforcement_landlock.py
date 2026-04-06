"""Tests for LandlockAdapter -- Linux Landlock LSM sandbox enforcement.

Covers:
- LandlockAdapter satisfies SandboxAdapter Protocol (isinstance check)
- restrict_filesystem stores writable and readable paths
- restrict_network stores allowed domains (Landlock v4)
- apply_restrictions calls prctl, landlock_create_ruleset, landlock_add_rule,
  landlock_restrict_self in correct order via ctypes syscalls
- Graceful degradation when Landlock unavailable (ENOSYS)
- Always-allowed minimum paths included (T-02-13)
- ABI version detection at init
- serialize_constraints returns JSON-serializable dict
"""

from __future__ import annotations

import ctypes
from typing import Any
from unittest import mock

import pytest

from cloneguard.enforcement.adapter import SandboxAdapter


class TestLandlockAdapterProtocol:
    """LandlockAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_check(self) -> None:
        """LandlockAdapter must satisfy isinstance(adapter, SandboxAdapter)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_landlock(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        assert adapter.name == "landlock"


class TestLandlockRestrictFilesystem:
    """restrict_filesystem stores writable and readable paths internally."""

    def test_stores_writable_paths(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=["/home/user/project"],
            readable=["/usr/lib"],
        )
        spec = adapter.serialize_constraints()
        assert "/home/user/project" in spec["writable"]

    def test_stores_readable_paths(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=[],
            readable=["/opt/data"],
        )
        spec = adapter.serialize_constraints()
        assert "/opt/data" in spec["readable"]

    def test_includes_always_allowed_writable(self) -> None:
        """Minimum always-allowed writable paths (T-02-13: /tmp)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        spec = adapter.serialize_constraints()
        assert "/tmp" in spec["writable"]

    def test_includes_always_allowed_readable(self) -> None:
        """Minimum always-allowed readable paths (T-02-13)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        spec = adapter.serialize_constraints()
        for path in ["/proc", "/dev/null", "/dev/urandom", "/dev/zero", "/usr/lib"]:
            assert path in spec["readable"], f"Missing always-allowed readable: {path}"


class TestLandlockRestrictNetwork:
    """restrict_network stores allowed domains for Landlock v4."""

    def test_stores_network_allow(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_network(allow=["registry.npmjs.org", "pypi.org"])
        spec = adapter.serialize_constraints()
        assert "registry.npmjs.org" in spec["network_allow"]
        assert "pypi.org" in spec["network_allow"]


class TestLandlockApplyRestrictions:
    """apply_restrictions calls Landlock syscalls via ctypes in correct order."""

    def test_calls_prctl_first(self) -> None:
        """apply_restrictions must call prctl(PR_SET_NO_NEW_PRIVS) first."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home/user"], readable=["/usr/lib"])

        call_order: list[str] = []

        def mock_syscall(*args: Any) -> int:
            syscall_num = args[0]
            if syscall_num == 157:  # SYS_prctl
                call_order.append("prctl")
            elif syscall_num == 444:
                call_order.append("create_ruleset")
            elif syscall_num == 445:
                call_order.append("add_rule")
            elif syscall_num == 446:
                call_order.append("restrict_self")
            return 3  # fake fd

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc"
        ) as mock_get_libc:
            mock_libc = mock.MagicMock()
            mock_libc.syscall.side_effect = mock_syscall
            mock_get_libc.return_value = mock_libc
            adapter.apply_restrictions()

        assert len(call_order) > 0, "No syscalls were made"
        assert call_order[0] == "prctl", f"prctl must be first, got {call_order}"

    def test_calls_create_ruleset_after_prctl(self) -> None:
        """landlock_create_ruleset must follow prctl."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home/user"], readable=["/usr/lib"])

        call_order: list[str] = []

        def mock_syscall(*args: Any) -> int:
            syscall_num = args[0]
            if syscall_num == 157:
                call_order.append("prctl")
            elif syscall_num == 444:
                call_order.append("create_ruleset")
            elif syscall_num == 445:
                call_order.append("add_rule")
            elif syscall_num == 446:
                call_order.append("restrict_self")
            return 3

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc"
        ) as mock_get_libc:
            mock_libc = mock.MagicMock()
            mock_libc.syscall.side_effect = mock_syscall
            mock_get_libc.return_value = mock_libc
            adapter.apply_restrictions()

        assert "prctl" in call_order
        assert "create_ruleset" in call_order
        prctl_idx = call_order.index("prctl")
        create_idx = call_order.index("create_ruleset")
        assert create_idx > prctl_idx

    def test_calls_add_rule_for_each_path(self) -> None:
        """landlock_add_rule must be called for each writable and readable path."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=["/home/user/project"],
            readable=["/opt/data"],
        )

        add_rule_calls: list[Any] = []

        def mock_syscall(*args: Any) -> int:
            syscall_num = args[0]
            if syscall_num == 445:  # add_rule
                add_rule_calls.append(args)
            return 3

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc"
        ) as mock_get_libc:
            mock_libc = mock.MagicMock()
            mock_libc.syscall.side_effect = mock_syscall
            mock_get_libc.return_value = mock_libc
            adapter.apply_restrictions()

        # At least the user-provided paths + always-allowed paths
        assert len(add_rule_calls) > 2, (
            f"Expected add_rule for each path, got {len(add_rule_calls)} calls"
        )

    def test_calls_restrict_self_last(self) -> None:
        """landlock_restrict_self must be the final Landlock syscall."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home/user"], readable=["/usr/lib"])

        call_order: list[str] = []

        def mock_syscall(*args: Any) -> int:
            syscall_num = args[0]
            if syscall_num == 157:
                call_order.append("prctl")
            elif syscall_num == 444:
                call_order.append("create_ruleset")
            elif syscall_num == 445:
                call_order.append("add_rule")
            elif syscall_num == 446:
                call_order.append("restrict_self")
            return 3

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc"
        ) as mock_get_libc:
            mock_libc = mock.MagicMock()
            mock_libc.syscall.side_effect = mock_syscall
            mock_get_libc.return_value = mock_libc
            adapter.apply_restrictions()

        assert call_order[-1] == "restrict_self", (
            f"restrict_self must be last, got {call_order}"
        )

    def test_graceful_degradation_enosys(self) -> None:
        """If Landlock unavailable (ENOSYS), apply_restrictions returns without error."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home/user"], readable=[])

        def mock_syscall_enosys(*args: Any) -> int:
            # Set errno to ENOSYS (38)
            ctypes.set_errno(38)
            return -1

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc"
        ) as mock_get_libc:
            mock_libc = mock.MagicMock()
            mock_libc.syscall.side_effect = mock_syscall_enosys
            mock_get_libc.return_value = mock_libc
            # Should not raise
            adapter.apply_restrictions()

    def test_graceful_degradation_no_libc(self) -> None:
        """If libc unavailable, apply_restrictions returns without error."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home/user"], readable=[])

        with mock.patch(
            "cloneguard.enforcement.landlock._get_libc",
            return_value=None,
        ):
            # Should not raise
            adapter.apply_restrictions()


class TestLandlockABIVersion:
    """LandlockAdapter detects ABI version at init time."""

    def test_detects_abi_version(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        # ABI version is an int (0 = not detected, 1-4 = detected)
        assert isinstance(adapter.abi_version, int)
        assert adapter.abi_version >= 0


class TestLandlockSerializeConstraints:
    """serialize_constraints returns JSON-serializable dict."""

    def test_returns_dict_with_adapter_name(self) -> None:
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home"], readable=["/usr"])
        spec = adapter.serialize_constraints()
        assert spec["adapter"] == "landlock"

    def test_serializable_round_trip(self) -> None:
        """The output must be JSON-serializable (for cross-process transport)."""
        import json

        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/home"], readable=["/usr"])
        adapter.restrict_network(allow=["example.com"])
        spec = adapter.serialize_constraints()
        # Must not raise
        json_str = json.dumps(spec)
        loaded = json.loads(json_str)
        assert loaded["adapter"] == "landlock"
        assert "/home" in loaded["writable"]
        assert "example.com" in loaded["network_allow"]
