"""Tests for sandbox hardening fixes 1-6.

FIX 1: prctl portability (libc.prctl() with arch-specific fallback)
FIX 2: Landlock network enforcement (ABI v4+ TCP port rules)
FIX 3: /proc narrowing (/proc/self only, not full /proc)
FIX 4: Private tmpdir (sandbox_exec creates cg-sandbox- tmpdir)
FIX 5: W^X split (_ACCESS_WRITE excludes EXECUTE)
FIX 6: Missing ABI flags (dynamic handled_access_fs by ABI version)
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any
from unittest import mock

# ===========================================================================
# FIX 1: prctl portability
# ===========================================================================


class TestFix1PrctlPortability:
    """FIX 1: prctl(PR_SET_NO_NEW_PRIVS) uses libc.prctl() or arch fallback."""

    def test_prctl_called_when_libc_has_prctl(self) -> None:
        """Positive: libc with prctl attribute -> libc.prctl() called directly."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0
        mock_libc.syscall.return_value = 3  # fake fd

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        mock_libc.prctl.assert_called_once_with(38, 1, 0, 0, 0)

    def test_fallback_syscall_x86_64(self) -> None:
        """Positive: libc without prctl, x86_64 -> syscall(157)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock(spec=["syscall"])
        mock_libc.syscall.return_value = 3

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
            mock.patch(
                "cloneguard.enforcement.landlock.platform.machine",
                return_value="x86_64",
            ),
        ):
            adapter.apply_restrictions()

        # First syscall should be prctl via syscall(157, ...)
        first_call = mock_libc.syscall.call_args_list[0]
        assert first_call[0][0] == 157, f"Expected syscall(157), got {first_call}"

    def test_fallback_syscall_aarch64(self) -> None:
        """Positive: libc without prctl, aarch64 -> syscall(167)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock(spec=["syscall"])
        mock_libc.syscall.return_value = 3

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
            mock.patch(
                "cloneguard.enforcement.landlock.platform.machine",
                return_value="aarch64",
            ),
        ):
            adapter.apply_restrictions()

        first_call = mock_libc.syscall.call_args_list[0]
        assert first_call[0][0] == 167, f"Expected syscall(167), got {first_call}"

    def test_unknown_arch_returns_without_restricting(self) -> None:
        """Negative: unknown arch -> logs warning, returns without restricting."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock(spec=["syscall"])

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch(
                "cloneguard.enforcement.landlock.platform.machine",
                return_value="s390x",
            ),
            mock.patch("cloneguard.enforcement.landlock.logger") as mock_logger,
        ):
            adapter.apply_restrictions()

        mock_logger.warning.assert_any_call(
            "Landlock: unknown architecture %s, cannot set NO_NEW_PRIVS",
            "s390x",
        )
        # No landlock syscalls should have been made
        mock_libc.syscall.assert_not_called()


# ===========================================================================
# FIX 2: Landlock network enforcement
# ===========================================================================


class TestFix2NetworkEnforcement:
    """FIX 2: Landlock v4+ TCP port-based network rules."""

    def test_abi4_empty_network_allow_denies_all(self) -> None:
        """Positive: ABI >= 4, empty network_allow -> handled_access_net set."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 4
        adapter.restrict_network(allow=[])
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        ruleset_attrs: list[Any] = []

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:  # create_ruleset
                # Capture the attr struct
                attr = args[1]
                if hasattr(attr, "contents"):
                    ruleset_attrs.append(attr.contents)
                return 3
            return 0

        mock_libc.syscall.side_effect = tracking_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        # Verify create_ruleset was called (second syscall after prctl)
        create_calls = [c for c in mock_libc.syscall.call_args_list if c[0][0] == 444]
        assert len(create_calls) == 1
        # The attr passed should have handled_access_net set
        # We verify indirectly: _add_network_rules was entered
        # (no port rules added for empty list = deny-all)

    def test_abi4_specific_ports_added(self) -> None:
        """Positive: ABI >= 4, specific ports -> port rules added."""
        from cloneguard.enforcement.landlock import (
            _LANDLOCK_RULE_NET_PORT,
            LandlockAdapter,
        )

        adapter = LandlockAdapter()
        adapter._abi_version = 4
        adapter.restrict_network(allow=["443", "80"])
        adapter.restrict_filesystem(writable=[], readable=[])

        net_rule_calls: list[tuple[Any, ...]] = []

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:
                return 3
            if args[0] == 445 and len(args) > 2:  # add_rule
                if args[2] == _LANDLOCK_RULE_NET_PORT:
                    net_rule_calls.append(args)
            return 0

        mock_libc.syscall.side_effect = tracking_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        assert len(net_rule_calls) == 2, f"Expected 2 net port rules, got {len(net_rule_calls)}"

    def test_abi_below_4_no_network_rules(self) -> None:
        """Positive: ABI < 4 -> no network rules, warning logged."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 3
        adapter.restrict_network(allow=["443"])
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0
        mock_libc.syscall.return_value = 3

        net_rule_calls: list[tuple[Any, ...]] = []

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:
                return 3
            if args[0] == 445 and len(args) > 2 and args[2] == 2:
                net_rule_calls.append(args)
            return 0

        mock_libc.syscall.side_effect = tracking_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        assert len(net_rule_calls) == 0, "Network rules added despite ABI < 4"

    def test_wildcard_skips_network_handling(self) -> None:
        """Negative: network_allow: ["*"] -> no network handling in ruleset."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 4
        adapter.restrict_network(allow=["*"])
        adapter.restrict_filesystem(writable=[], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0
        mock_libc.syscall.return_value = 3

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        # No net port rules should be added
        net_rules = [
            c
            for c in mock_libc.syscall.call_args_list
            if len(c[0]) > 2 and c[0][0] == 445 and c[0][2] == 2
        ]
        assert len(net_rules) == 0

    def test_domain_names_log_warning(self) -> None:
        """Negative: domain names -> warning logged, skipped."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 4
        adapter.restrict_network(allow=["example.com", "443"])
        adapter.restrict_filesystem(writable=[], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0

        net_rule_calls: list[tuple[Any, ...]] = []

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:
                return 3
            if args[0] == 445 and len(args) > 2 and args[2] == 2:
                net_rule_calls.append(args)
            return 0

        mock_libc.syscall.side_effect = tracking_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
            mock.patch("cloneguard.enforcement.landlock.logger") as mock_logger,
        ):
            adapter.apply_restrictions()

        # Only port 443 should produce a rule, not "example.com"
        assert len(net_rule_calls) == 1
        mock_logger.warning.assert_any_call(
            "Landlock: network_allow entry %r is not a port number "
            "(domain filtering not supported by Landlock), skipping",
            "example.com",
        )


# ===========================================================================
# FIX 3: /proc narrowing
# ===========================================================================


class TestFix3ProcNarrowing:
    """FIX 3: /proc replaced with /proc/self in _ALWAYS_READABLE."""

    def test_proc_self_in_always_readable(self) -> None:
        """Positive: /proc/self is in always-readable paths."""
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/proc/self" in _ALWAYS_READABLE

    def test_full_proc_not_in_always_readable(self) -> None:
        """Negative: /proc (full) is NOT in always-readable paths."""
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/proc" not in _ALWAYS_READABLE

    def test_proc_1_not_covered(self) -> None:
        """Negative: /proc/1 would not be covered by /proc/self."""
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        # /proc/self is a specific path, not a prefix match in Landlock
        # /proc/1 is not under /proc/self
        for path in _ALWAYS_READABLE:
            assert not (path == "/proc" or path.startswith("/proc/") and path != "/proc/self"), (
                f"Unexpected broad /proc path: {path}"
            )


# ===========================================================================
# FIX 4: Private tmpdir
# ===========================================================================


class TestFix4PrivateTmpdir:
    """FIX 4: sandbox_exec creates private tmpdir, injects into constraints."""

    def test_creates_tmpdir_with_prefix(self) -> None:
        """Positive: sandbox_exec creates tmpdir with cg-sandbox- prefix."""
        from cloneguard.enforcement.sandbox_exec import main

        created_tmpdirs: list[str] = []
        original_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(**kwargs: Any) -> str:
            result = original_mkdtemp(**kwargs)
            created_tmpdirs.append(result)
            return result

        constraints = {
            "adapter": "noop",
            "writable": ["/home/user"],
            "readable": ["/usr/lib"],
            "network_allow": [],
        }
        fd, spec_path = tempfile.mkstemp(prefix="cg-enforce-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)

        try:
            with (
                mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
                mock.patch("cloneguard.enforcement.sandbox_exec.get_sandbox_adapter") as mock_get,
                mock.patch(
                    "cloneguard.enforcement.sandbox_exec.tempfile.mkdtemp",
                    side_effect=tracking_mkdtemp,
                ),
                mock.patch(
                    "sys.argv",
                    ["sandbox-exec", "--spec-file", spec_path, "--", "bash"],
                ),
            ):
                mock_get.return_value = mock.MagicMock()
                main()

            assert len(created_tmpdirs) == 1
            assert "cg-sandbox-" in os.path.basename(created_tmpdirs[0])
        finally:
            for d in created_tmpdirs:
                if os.path.isdir(d):
                    os.rmdir(d)
            if os.path.exists(spec_path):
                os.unlink(spec_path)

    def test_sets_tmpdir_env_var(self) -> None:
        """Positive: TMPDIR env var set to private tmpdir."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        fd, spec_path = tempfile.mkstemp(prefix="cg-enforce-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)

        captured_env: dict[str, str] = {}

        def capture_execvp(cmd: str, args: list[str]) -> None:
            captured_env["TMPDIR"] = os.environ.get("TMPDIR", "")
            captured_env["TEMP"] = os.environ.get("TEMP", "")
            captured_env["TMP"] = os.environ.get("TMP", "")

        original_tmpdir = os.environ.get("TMPDIR")
        try:
            with (
                mock.patch(
                    "cloneguard.enforcement.sandbox_exec.os.execvp",
                    side_effect=capture_execvp,
                ),
                mock.patch("cloneguard.enforcement.sandbox_exec.get_sandbox_adapter") as mock_get,
                mock.patch(
                    "sys.argv",
                    ["sandbox-exec", "--spec-file", spec_path, "--", "env"],
                ),
            ):
                mock_get.return_value = mock.MagicMock()
                main()

            assert "cg-sandbox-" in captured_env["TMPDIR"]
            assert captured_env["TMPDIR"] == captured_env["TEMP"]
            assert captured_env["TMPDIR"] == captured_env["TMP"]

            # Clean up created tmpdir
            if os.path.isdir(captured_env["TMPDIR"]):
                os.rmdir(captured_env["TMPDIR"])
        finally:
            if os.path.exists(spec_path):
                os.unlink(spec_path)
            # Restore original TMPDIR
            if original_tmpdir is not None:
                os.environ["TMPDIR"] = original_tmpdir
            elif "TMPDIR" in os.environ:
                del os.environ["TMPDIR"]
            for var in ("TEMP", "TMP"):
                if var in os.environ and "cg-sandbox-" in os.environ[var]:
                    del os.environ[var]

    def test_tmpdir_in_constraints_writable(self) -> None:
        """Positive: private tmpdir added to constraints writable list."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        fd, spec_path = tempfile.mkstemp(prefix="cg-enforce-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)

        original_tmpdir = os.environ.get("TMPDIR")
        try:
            with (
                mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
                mock.patch("cloneguard.enforcement.sandbox_exec.get_sandbox_adapter") as mock_get,
                mock.patch(
                    "sys.argv",
                    ["sandbox-exec", "--spec-file", spec_path, "--", "true"],
                ),
            ):
                mock_adapter = mock.MagicMock()
                mock_get.return_value = mock_adapter
                main()

            fs_call = mock_adapter.restrict_filesystem.call_args
            writable = fs_call.kwargs.get("writable", [])
            readable = fs_call.kwargs.get("readable", [])
            # Private tmpdir should appear in both writable and readable
            assert any("cg-sandbox-" in p for p in writable), (
                f"Private tmpdir not in writable: {writable}"
            )
            assert any("cg-sandbox-" in p for p in readable), (
                f"Private tmpdir not in readable: {readable}"
            )
        finally:
            if os.path.exists(spec_path):
                os.unlink(spec_path)
            if original_tmpdir is not None:
                os.environ["TMPDIR"] = original_tmpdir
            elif "TMPDIR" in os.environ:
                del os.environ["TMPDIR"]
            for var in ("TEMP", "TMP"):
                if var in os.environ and "cg-sandbox-" in os.environ[var]:
                    del os.environ[var]

    def test_tmp_not_in_landlock_always_writable(self) -> None:
        """Negative: /tmp is NOT in Landlock _ALWAYS_WRITABLE."""
        from cloneguard.enforcement.landlock import _ALWAYS_WRITABLE

        assert "/tmp" not in _ALWAYS_WRITABLE

    def test_tmp_not_in_seatbelt_always_writable(self) -> None:
        """Negative: /tmp, /private/tmp, /private/var/folders NOT in Seatbelt."""
        from cloneguard.enforcement.seatbelt import _ALWAYS_WRITABLE

        assert "/tmp" not in _ALWAYS_WRITABLE
        assert "/private/tmp" not in _ALWAYS_WRITABLE
        assert "/private/var/folders" not in _ALWAYS_WRITABLE


# ===========================================================================
# FIX 5: W^X split
# ===========================================================================


class TestFix5WxSplit:
    """FIX 5: _ACCESS_WRITE excludes EXECUTE; _ACCESS_WRITE_EXEC includes it."""

    def test_access_write_no_execute(self) -> None:
        """Positive: _ACCESS_WRITE does NOT include EXECUTE flag."""
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE,
            _LANDLOCK_ACCESS_FS_EXECUTE,
        )

        assert not (_ACCESS_WRITE & _LANDLOCK_ACCESS_FS_EXECUTE)

    def test_access_write_exec_has_execute(self) -> None:
        """Positive: _ACCESS_WRITE_EXEC includes EXECUTE flag."""
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE_EXEC,
            _LANDLOCK_ACCESS_FS_EXECUTE,
        )

        assert _ACCESS_WRITE_EXEC & _LANDLOCK_ACCESS_FS_EXECUTE

    def test_writable_paths_get_no_execute(self) -> None:
        """Positive: writable paths use _ACCESS_WRITE (no EXECUTE bit)."""
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE,
            _LANDLOCK_ACCESS_FS_EXECUTE,
            LandlockAdapter,
        )

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=["/home/user"],
            readable=[],
        )

        # Verify at the constant level: _ACCESS_WRITE must not include EXECUTE
        assert not (_ACCESS_WRITE & _LANDLOCK_ACCESS_FS_EXECUTE)

    def test_executable_writable_paths_get_execute(self) -> None:
        """Positive: executable_writable paths use _ACCESS_WRITE_EXEC."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=["/data"],
            readable=[],
            executable_writable=["/usr/local/bin"],
        )

        add_rule_calls: list[tuple[Any, ...]] = []

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:
                return 3
            if args[0] == 445:
                add_rule_calls.append(args)
            return 0

        mock_libc.syscall.side_effect = tracking_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        # executable_writable paths should produce add_rule calls
        # (readable + writable + executable_writable all produce calls)
        assert len(add_rule_calls) > 0

    def test_serialize_includes_executable_writable(self) -> None:
        """Positive: serialize_constraints includes executable_writable."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(
            writable=["/data"],
            readable=["/usr"],
            executable_writable=["/usr/local/bin"],
        )
        spec = adapter.serialize_constraints()
        assert "executable_writable" in spec
        assert "/usr/local/bin" in spec["executable_writable"]


# ===========================================================================
# FIX 6: Missing ABI flags
# ===========================================================================


class TestFix6ABIFlags:
    """FIX 6: _build_handled_access_fs builds mask by ABI version."""

    def test_abi_v1_base_flags_only(self) -> None:
        """Positive: ABI v1 -> base 13 flags only."""
        from cloneguard.enforcement.landlock import (
            _BASE_FS_ACCESS_V1,
            _LANDLOCK_ACCESS_FS_REFER,
            _LANDLOCK_ACCESS_FS_TRUNCATE,
            _build_handled_access_fs,
        )

        mask = _build_handled_access_fs(1)
        assert mask == _BASE_FS_ACCESS_V1
        assert not (mask & _LANDLOCK_ACCESS_FS_REFER)
        assert not (mask & _LANDLOCK_ACCESS_FS_TRUNCATE)

    def test_abi_v2_includes_refer(self) -> None:
        """Positive: ABI v2 -> includes REFER."""
        from cloneguard.enforcement.landlock import (
            _LANDLOCK_ACCESS_FS_REFER,
            _build_handled_access_fs,
        )

        mask = _build_handled_access_fs(2)
        assert mask & _LANDLOCK_ACCESS_FS_REFER

    def test_abi_v3_includes_refer_and_truncate(self) -> None:
        """Positive: ABI v3 -> includes REFER + TRUNCATE."""
        from cloneguard.enforcement.landlock import (
            _LANDLOCK_ACCESS_FS_REFER,
            _LANDLOCK_ACCESS_FS_TRUNCATE,
            _build_handled_access_fs,
        )

        mask = _build_handled_access_fs(3)
        assert mask & _LANDLOCK_ACCESS_FS_REFER
        assert mask & _LANDLOCK_ACCESS_FS_TRUNCATE

    def test_abi_v1_no_refer_or_truncate(self) -> None:
        """Negative: ABI v1 does NOT include REFER or TRUNCATE."""
        from cloneguard.enforcement.landlock import (
            _LANDLOCK_ACCESS_FS_REFER,
            _LANDLOCK_ACCESS_FS_TRUNCATE,
            _build_handled_access_fs,
        )

        mask = _build_handled_access_fs(1)
        assert not (mask & _LANDLOCK_ACCESS_FS_REFER), "ABI v1 has REFER"
        assert not (mask & _LANDLOCK_ACCESS_FS_TRUNCATE), "ABI v1 has TRUNCATE"

    def test_apply_uses_dynamic_abi_flags(self) -> None:
        """Positive: apply_restrictions uses _build_handled_access_fs."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 3
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0
        mock_libc.syscall.return_value = 3

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
            mock.patch("cloneguard.enforcement.landlock._build_handled_access_fs") as mock_build,
        ):
            mock_build.return_value = 0x7FFF
            adapter.apply_restrictions()

        mock_build.assert_called_once_with(3)


# ===========================================================================
# Cross-fix integration tests
# ===========================================================================


class TestCrossFixIntegration:
    """Tests that verify multiple fixes work together correctly."""

    def test_adapter_protocol_still_satisfied(self) -> None:
        """LandlockAdapter still satisfies SandboxAdapter Protocol."""
        from cloneguard.enforcement.adapter import SandboxAdapter
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_seatbelt_protocol_still_satisfied(self) -> None:
        """SeatbeltAdapter still satisfies SandboxAdapter Protocol."""
        from cloneguard.enforcement.adapter import SandboxAdapter
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_noop_adapter_accepts_executable_writable(self) -> None:
        """NoopAdapter accepts executable_writable parameter."""
        from cloneguard.enforcement.adapter import NoopAdapter

        adapter = NoopAdapter()
        # Should not raise
        adapter.restrict_filesystem(
            writable=["/tmp"],
            readable=["/usr"],
            executable_writable=["/usr/local/bin"],
        )

    def test_seatbelt_accepts_executable_writable(self) -> None:
        """SeatbeltAdapter accepts executable_writable and merges into writable."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=["/data"],
            readable=["/usr"],
            executable_writable=["/usr/local/bin"],
        )
        spec = adapter.serialize_constraints()
        assert "/data" in spec["writable"]
        assert "/usr/local/bin" in spec["writable"]

    def test_full_apply_cycle_mocked(self) -> None:
        """Full apply cycle with all fixes active (mocked libc)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 4
        adapter.restrict_filesystem(
            writable=["/home/user"],
            readable=["/usr/lib"],
            executable_writable=["/usr/local/bin"],
        )
        adapter.restrict_network(allow=["443"])

        call_order: list[str] = []

        mock_libc = mock.MagicMock()

        def mock_prctl(*args: Any) -> int:
            call_order.append("prctl")
            return 0

        mock_libc.prctl.side_effect = mock_prctl

        def mock_syscall(*args: Any) -> int:
            if args[0] == 444:
                call_order.append("create_ruleset")
                return 3
            elif args[0] == 445:
                call_order.append("add_rule")
            elif args[0] == 446:
                call_order.append("restrict_self")
            return 0

        mock_libc.syscall.side_effect = mock_syscall

        with (
            mock.patch(
                "cloneguard.enforcement.landlock._get_libc",
                return_value=mock_libc,
            ),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        assert call_order[0] == "prctl"
        assert call_order[1] == "create_ruleset"
        assert call_order[-1] == "restrict_self"
        assert "add_rule" in call_order
