"""Sandbox breakout test cases for CloneGuard Seatbelt and Landlock adapters.

These tests verify that the sandbox BLOCKS escape attempts. Tests are designed
to run on CI with mocked adapters (unit tests) and optionally on real systems
with real sandbox enforcement (integration tests).

Test naming: test_breakout_{category}_{number}_{description}
Markers:
  - @pytest.mark.sandbox_breakout: all breakout tests
  - @pytest.mark.seatbelt: Seatbelt-specific
  - @pytest.mark.landlock: Landlock-specific
  - @pytest.mark.integration: requires real OS sandbox (not mocked)

Reference: docs/sub-agents/sandbox-breakout-research.md
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from typing import Any
from unittest import mock

import pytest

IS_LINUX = sys.platform == "linux"
IS_MACOS = sys.platform == "darwin"

pytestmark = pytest.mark.sandbox_breakout


# ===========================================================================
# A. Path Traversal / Symlink Attacks
# ===========================================================================


class TestBreakoutSymlinkEscape:
    """A-01/A-02: Symlink from allowed path to restricted path."""

    def test_breakout_a01_symlink_tmp_to_etc_passwd_landlock(self) -> None:
        """Landlock: symlink in /tmp -> /etc/passwd should be readable
        because /etc is in _ALWAYS_READABLE (needed for DNS resolution).
        """
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/etc" in _ALWAYS_READABLE, (
            "/etc removed from always-readable -- DNS resolution may break"
        )

    def test_breakout_a01_symlink_tmp_to_home_landlock(self) -> None:
        """Landlock: symlink in /tmp -> /home/user/.ssh should be DENIED
        because /home is NOT in always-readable.
        """
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/home" not in _ALWAYS_READABLE

    def test_breakout_a02_seatbelt_profile_uses_subpath(self) -> None:
        """Seatbelt: verify profile uses 'subpath' not 'literal' for path rules.
        subpath means kernel-resolved paths are checked, blocking symlink escape.
        """
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/usr/lib"])
        profile = adapter._generate_profile()
        # All file rules should use 'subpath' which resolves symlinks
        assert "(subpath" in profile
        # No 'literal' path rules (which don't resolve symlinks)
        file_rules = [
            line for line in profile.split("\n") if "file-read" in line or "file-write" in line
        ]
        for rule in file_rules:
            assert "literal" not in rule, f"Rule uses 'literal' instead of 'subpath': {rule}"


# ===========================================================================
# B. /proc and /sys Abuse (Linux)
# ===========================================================================


class TestBreakoutProcAbuse:
    """B-01/B-02: /proc/self/environ and /proc/self/fd access."""

    def test_breakout_b01_proc_narrowed_to_proc_self_landlock(self) -> None:
        """Landlock: /proc narrowed to /proc/self only (FIX 3)."""
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/proc" not in _ALWAYS_READABLE, "/proc still fully readable"
        assert "/proc/self" in _ALWAYS_READABLE, "/proc/self missing from readable"

    def test_breakout_b04_sys_not_readable_landlock(self) -> None:
        """Landlock: /sys should NOT be in always-readable."""
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/sys" not in _ALWAYS_READABLE, "/sys is always-readable -- B-04 is vulnerable"


# ===========================================================================
# C. File Descriptor Inheritance
# ===========================================================================


class TestBreakoutFDInheritance:
    """C-01: Verify FD cleanup in sandbox wrapper."""

    def test_breakout_c01_ruleset_fd_closed_landlock(self) -> None:
        """Landlock: ruleset FD must be closed after restrict_self."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/usr/lib"])

        closed_fds: list[int] = []

        def mock_syscall(*args: Any) -> int:
            if args[0] == 444:  # create_ruleset
                return 42  # fake ruleset fd
            return 0

        mock_libc = mock.MagicMock()
        mock_libc.syscall.side_effect = mock_syscall

        def tracking_close(fd: int) -> None:
            closed_fds.append(fd)

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch(
                "cloneguard.enforcement.landlock.os.close",
                side_effect=tracking_close,
            ),
        ):
            adapter.apply_restrictions()

        # The ruleset fd (42) must appear in closed FDs
        assert 42 in closed_fds, f"Ruleset FD 42 not closed. Closed FDs: {closed_fds}"

    def test_breakout_c01_spec_file_closed_before_target_runs(self) -> None:
        """sandbox wrapper: spec file FD must be closed before target runs."""
        from cloneguard.enforcement.sandbox_exec import _load_constraints_from_file

        # Create a temp spec file
        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        fd, path = tempfile.mkstemp(prefix="cg-test-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)

        result = _load_constraints_from_file(path)
        assert result is not None
        # File should be deleted
        assert not os.path.exists(path), "Spec file should be deleted after read"

    def test_breakout_c01_landlock_path_fds_use_cloexec(self) -> None:
        """Landlock: path FDs opened with O_CLOEXEC to prevent inheritance."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        open_flags: list[int] = []

        def tracking_open(path: str, flags: int) -> int:
            open_flags.append(flags)
            return 10

        mock_libc = mock.MagicMock()
        mock_libc.syscall.return_value = 3  # fake fd

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", side_effect=tracking_open),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        # O_CLOEXEC = 0x80000 on Linux
        o_cloexec = getattr(os, "O_CLOEXEC", 0x80000)
        for flags in open_flags:
            assert flags & o_cloexec, f"Path FD opened without O_CLOEXEC: flags={flags:#x}"


# ===========================================================================
# D. /tmp-Based Escape Vectors
# ===========================================================================


class TestBreakoutTmpEscape:
    """D-01/D-02: /tmp as staging area and IPC channel."""

    def test_breakout_d01_tmp_not_always_writable_both(self) -> None:
        """Both: /tmp removed from always-writable (FIX 4, private tmpdir)."""
        from cloneguard.enforcement.landlock import _ALWAYS_WRITABLE as LL_WRITABLE
        from cloneguard.enforcement.seatbelt import _ALWAYS_WRITABLE as SB_WRITABLE

        assert "/tmp" not in LL_WRITABLE, "/tmp still always-writable in Landlock"
        assert "/tmp" not in SB_WRITABLE, "/tmp still always-writable in Seatbelt"

    def test_breakout_d02_landlock_no_make_sock_in_write(self) -> None:
        """Landlock: _ACCESS_WRITE should NOT include MAKE_SOCK.
        This prevents Unix socket creation in writable paths.
        """
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE,
            _LANDLOCK_ACCESS_FS_MAKE_SOCK,
        )

        has_make_sock = _ACCESS_WRITE & _LANDLOCK_ACCESS_FS_MAKE_SOCK
        assert not has_make_sock, "_ACCESS_WRITE includes MAKE_SOCK -- D-02 socket IPC is possible"

    def test_breakout_d03_spec_file_uses_mkstemp(self) -> None:
        """sandbox wrapper: write_constraint_spec uses mkstemp (unique, 0600)."""
        from cloneguard.enforcement.sandbox_exec import write_constraint_spec

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        path = write_constraint_spec(constraints)
        try:
            st = os.stat(path)
            # Check permissions: should be 0600 (owner read/write only)
            mode = stat.S_IMODE(st.st_mode)
            assert mode == 0o600, f"Spec file mode is {oct(mode)}, expected 0o600"
        finally:
            os.unlink(path)


# ===========================================================================
# E. Signal-Based Attacks
# ===========================================================================


class TestBreakoutSignalAttack:
    """E-01/E-02: Signal sending from sandboxed process."""

    def test_breakout_e01_seatbelt_denies_signal_by_default(self) -> None:
        """Seatbelt: (deny default) should block signal sending.
        Verify profile does not explicitly allow signal.
        """
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()
        # Profile should not contain explicit (allow signal)
        signal_allows = [
            line for line in profile.split("\n") if "allow" in line and "signal" in line
        ]
        assert len(signal_allows) == 0, f"Profile explicitly allows signal: {signal_allows}"

    def test_breakout_e02_landlock_no_signal_restriction(self) -> None:
        """Landlock: document that Landlock does NOT restrict signals.
        This is a known limitation -- signals require seccomp-bpf.
        """
        from cloneguard.enforcement.landlock import _SYS_LANDLOCK_CREATE_RULESET

        # Landlock only handles filesystem (and v4+ network) -- no signal control
        assert _SYS_LANDLOCK_CREATE_RULESET == 444
        # No signal-related constants exist in the module
        import cloneguard.enforcement.landlock as ll_mod

        signal_attrs = [a for a in dir(ll_mod) if "signal" in a.lower()]
        assert len(signal_attrs) == 0, (
            "Signal-related attributes found -- check if signal restriction was added"
        )


# ===========================================================================
# F. Network Exfiltration
# ===========================================================================


class TestBreakoutNetworkExfil:
    """F-01/F-02: DNS and network exfiltration."""

    def test_breakout_f01_seatbelt_no_network_when_empty(self) -> None:
        """Seatbelt: empty network_allow should produce NO network-outbound rule."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        adapter.restrict_network(allow=[])
        profile = adapter._generate_profile()

        network_allows = [
            line.strip()
            for line in profile.split("\n")
            if "network-outbound" in line and "allow" in line
        ]
        assert len(network_allows) == 0, (
            f"Network allowed when it should be denied: {network_allows}"
        )

    def test_breakout_f01_seatbelt_bsd_sb_may_allow_dns(self) -> None:
        """Seatbelt: bsd.sb import may allow DNS via Mach IPC.
        Document that mDNSResponder lookup is not explicitly denied.
        """
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        adapter.restrict_network(allow=[])
        profile = adapter._generate_profile()

        # Check if mDNSResponder is explicitly denied
        has_mdns_deny = "mDNSResponder" in profile and "deny" in profile
        if not has_mdns_deny:
            assert '(import "bsd.sb")' in profile, (
                "bsd.sb import removed -- F-01 DNS exfil risk may be different"
            )

    def test_breakout_f02_landlock_network_enforcement_abi4(self) -> None:
        """Landlock: FIX 2 adds network enforcement for ABI v4+.
        With ABI < 4, network rules are not added (graceful degradation).
        """
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter._abi_version = 4  # Simulate ABI v4
        adapter.restrict_network(allow=["443", "80"])
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        mock_libc = mock.MagicMock()
        mock_libc.prctl.return_value = 0
        mock_libc.syscall.return_value = 3  # fake fd

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        # With ABI v4 and port-based allow, network rules should be added
        add_rule_calls = [
            c
            for c in mock_libc.syscall.call_args_list
            if len(c[0]) > 2 and c[0][0] == 445  # SYS_LANDLOCK_ADD_RULE
        ]
        assert len(add_rule_calls) > 0, "No add_rule calls were made"

    def test_breakout_f03_seatbelt_network_all_or_nothing(self) -> None:
        """Seatbelt: non-empty network_allow grants ALL network, not per-domain."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        adapter.restrict_network(allow=["registry.npmjs.org"])
        profile = adapter._generate_profile()

        # The profile has (allow network-outbound) with no filter
        assert "(allow network-outbound)" in profile
        # The specific domain does NOT appear as a filter in the SBPL
        profile_no_comments = "\n".join(
            line for line in profile.split("\n") if not line.strip().startswith(";;")
        )
        assert "registry.npmjs.org" not in profile_no_comments, (
            "Per-domain network filtering found (update this test)"
        )


# ===========================================================================
# G. Hardlink Attacks
# ===========================================================================


class TestBreakoutHardlink:
    """G-01: Hardlink-based escape attempts."""

    def test_breakout_g01_landlock_make_sym_not_in_write(self) -> None:
        """Landlock: _ACCESS_WRITE should NOT include MAKE_SYM.
        Prevents creating symlinks in writable paths for traversal attacks.
        """
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE,
            _LANDLOCK_ACCESS_FS_MAKE_SYM,
        )

        has_make_sym = _ACCESS_WRITE & _LANDLOCK_ACCESS_FS_MAKE_SYM
        assert not has_make_sym, "_ACCESS_WRITE includes MAKE_SYM -- symlink creation allowed"


# ===========================================================================
# H. Mount Namespace Tricks
# ===========================================================================


class TestBreakoutMountNamespace:
    """H-01: Mount namespace escape via PR_SET_NO_NEW_PRIVS."""

    def test_breakout_h01_landlock_sets_no_new_privs(self) -> None:
        """Landlock: PR_SET_NO_NEW_PRIVS must be set before restrict_self.
        This prevents capability escalation via mount namespaces.
        FIX 1: now uses libc.prctl() when available.
        """
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        call_order: list[str] = []

        def mock_syscall(*args: Any) -> int:
            if args[0] == 444:
                call_order.append("create_ruleset")
                return 3
            elif args[0] == 446:
                call_order.append("restrict_self")
            return 0

        mock_libc = mock.MagicMock()
        mock_libc.syscall.side_effect = mock_syscall
        # FIX 1: libc has prctl attribute -> direct call
        mock_libc.prctl.return_value = 0

        def track_prctl(*args: Any) -> int:
            call_order.append("no_new_privs")
            return 0

        mock_libc.prctl.side_effect = track_prctl

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        assert "no_new_privs" in call_order, "PR_SET_NO_NEW_PRIVS not called"
        assert call_order.index("no_new_privs") < call_order.index("restrict_self"), (
            "PR_SET_NO_NEW_PRIVS must come before restrict_self"
        )


# ===========================================================================
# I. Environment Variable Exfiltration
# ===========================================================================


class TestBreakoutEnvLeak:
    """I-01/I-02: Environment variable exposure."""

    def test_breakout_i01_proc_environ_mitigated_landlock(self) -> None:
        """Landlock: /proc narrowed to /proc/self (FIX 3).
        Other processes' /proc/[pid]/environ is no longer readable.
        /proc/self/environ is still accessible (own process only).
        """
        from cloneguard.enforcement.landlock import _ALWAYS_READABLE

        assert "/proc" not in _ALWAYS_READABLE, "/proc still fully readable"
        assert "/proc/self" in _ALWAYS_READABLE

    def test_breakout_i02_env_vars_not_stripped_by_wrapper(self) -> None:
        """sandbox wrapper: verify that env vars are passed through to child.
        This documents that os.execvp inherits the full environment.
        """
        from cloneguard.enforcement.sandbox_exec import main

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp") as mock_execvp,
            mock.patch("sys.argv", ["sandbox-wrapper", "--", "env"]),
        ):
            main()

        mock_execvp.assert_called_once()
        call_args = mock_execvp.call_args
        assert len(call_args[0]) == 2, "Called with extra args (env filtering may have been added)"


# ===========================================================================
# J. Escape via Always-Allowed Paths
# ===========================================================================


class TestBreakoutAlwaysAllowedPaths:
    """J-01/J-02/J-03: Abuse of always-allowed paths."""

    def test_breakout_j01_tmp_covert_channel_mitigated(self) -> None:
        """Both: /tmp removed from always-writable (FIX 4, private tmpdir)."""
        from cloneguard.enforcement.landlock import _ALWAYS_WRITABLE as LL_W
        from cloneguard.enforcement.seatbelt import _ALWAYS_WRITABLE as SB_W

        assert "/tmp" not in LL_W, "/tmp still always-writable in Landlock"
        assert "/tmp" not in SB_W, "/tmp still always-writable in Seatbelt"

    def test_breakout_j02_dev_shm_not_allowed_landlock(self) -> None:
        """Landlock: /dev/shm should NOT be in always-allowed paths."""
        from cloneguard.enforcement.landlock import (
            _ALWAYS_READABLE,
            _ALWAYS_WRITABLE,
        )

        assert "/dev/shm" not in _ALWAYS_READABLE
        assert "/dev/shm" not in _ALWAYS_WRITABLE
        # Only specific /dev files are allowed
        assert "/dev/null" in _ALWAYS_READABLE
        assert "/dev/urandom" in _ALWAYS_READABLE

    def test_breakout_j03_seatbelt_bsd_sb_mach_services(self) -> None:
        """Seatbelt: bsd.sb import allows Mach service lookups.
        Document which services could be abused.
        """
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()

        assert '(import "bsd.sb")' in profile, "bsd.sb removed -- Mach IPC attack surface reduced"


# ===========================================================================
# K. TOCTOU on Spec File
# ===========================================================================


class TestBreakoutSpecFileTOCTOU:
    """K-01/K-02: Race conditions on constraint spec file."""

    def test_breakout_k01_spec_file_deleted_after_read(self) -> None:
        """Spec file is deleted immediately after reading."""
        from cloneguard.enforcement.sandbox_exec import _load_constraints_from_file

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        fd, path = tempfile.mkstemp(prefix="cg-test-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)

        assert os.path.exists(path)
        _load_constraints_from_file(path)
        assert not os.path.exists(path), "Spec file not deleted after read"

    def test_breakout_k01_spec_file_has_restricted_permissions(self) -> None:
        """Spec file created with 0600 permissions (owner only)."""
        from cloneguard.enforcement.sandbox_exec import write_constraint_spec

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        path = write_constraint_spec(constraints)
        try:
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            assert mode == 0o600, f"Spec file mode {oct(mode)}, expected 0600"
        finally:
            os.unlink(path)

    def test_breakout_k02_spec_file_deleted_even_on_invalid_json(self) -> None:
        """Spec file is deleted even if JSON parsing fails."""
        from cloneguard.enforcement.sandbox_exec import _load_constraints_from_file

        fd, path = tempfile.mkstemp(prefix="cg-test-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("NOT VALID JSON {{{")

        result = _load_constraints_from_file(path)
        assert result is None
        assert not os.path.exists(path), "Spec file not deleted after failed parse"


# ===========================================================================
# L. Python-Specific Escapes
# ===========================================================================


class TestBreakoutPythonSpecific:
    """L-01 through L-04: Python-level escape techniques."""

    def test_breakout_l01_ctypes_available_in_sandbox(self) -> None:
        """Both: ctypes is available in sandboxed Python (documents the risk)."""
        import ctypes

        assert hasattr(ctypes, "CDLL")
        assert hasattr(ctypes, "c_int")

    def test_breakout_l03_import_from_tmp(self) -> None:
        """Both: Python can import modules from /tmp (always-writable)."""
        import importlib.util

        module_path = "/tmp/cg_breakout_test_module.py"
        try:
            with open(module_path, "w") as f:
                f.write("BREAKOUT_VALUE = 42\n")

            spec = importlib.util.spec_from_file_location(
                "cg_breakout_test_module",
                module_path,
            )
            assert spec is not None, "Could not create module spec from /tmp"
            mod = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            assert mod.BREAKOUT_VALUE == 42  # type: ignore[attr-defined]
        finally:
            if os.path.exists(module_path):
                os.unlink(module_path)

    def test_breakout_l05_landlock_write_excludes_execute(self) -> None:
        """Landlock: _ACCESS_WRITE does NOT include EXECUTE (FIX 5 W^X).
        _ACCESS_WRITE_EXEC exists for paths that genuinely need both.
        """
        from cloneguard.enforcement.landlock import (
            _ACCESS_WRITE,
            _ACCESS_WRITE_EXEC,
            _LANDLOCK_ACCESS_FS_EXECUTE,
        )

        assert not (_ACCESS_WRITE & _LANDLOCK_ACCESS_FS_EXECUTE), (
            "_ACCESS_WRITE still includes EXECUTE -- W^X not enforced"
        )
        assert _ACCESS_WRITE_EXEC & _LANDLOCK_ACCESS_FS_EXECUTE, (
            "_ACCESS_WRITE_EXEC missing EXECUTE flag"
        )


# ===========================================================================
# Implementation Correctness Tests
# ===========================================================================


class TestImplementationCorrectness:
    """Cross-examination of implementation against known best practices."""

    def test_impl_landlock_prctl_before_restrict_self(self) -> None:
        """CRITICAL: prctl(PR_SET_NO_NEW_PRIVS) MUST precede restrict_self.
        Kernel returns EPERM if this ordering is violated.
        FIX 1: now uses libc.prctl() when available.
        """
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        call_order: list[str] = []

        def tracking_syscall(*args: Any) -> int:
            if args[0] == 444:
                call_order.append("create_ruleset")
                return 3
            elif args[0] == 446:
                call_order.append("restrict_self")
            return 0

        mock_libc = mock.MagicMock()
        mock_libc.syscall.side_effect = tracking_syscall

        def track_prctl(*args: Any) -> int:
            call_order.append("prctl")
            return 0

        mock_libc.prctl.side_effect = track_prctl

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch("cloneguard.enforcement.landlock.os.close"),
        ):
            adapter.apply_restrictions()

        assert "prctl" in call_order
        assert "restrict_self" in call_order
        assert call_order.index("prctl") < call_order.index("restrict_self")

    def test_impl_landlock_prctl_portable(self) -> None:
        """FIX 1: prctl uses libc.prctl() directly or arch-specific fallback.
        No more hardcoded x86_64-only SYS_prctl constant.
        """
        from cloneguard.enforcement.landlock import _PRCTL_SYSCALL_BY_ARCH

        assert "x86_64" in _PRCTL_SYSCALL_BY_ARCH
        assert "aarch64" in _PRCTL_SYSCALL_BY_ARCH
        assert _PRCTL_SYSCALL_BY_ARCH["x86_64"] == 157
        assert _PRCTL_SYSCALL_BY_ARCH["aarch64"] == 167

    def test_impl_landlock_abi_aware_fs_access(self) -> None:
        """FIX 6: handled_access_fs built dynamically based on ABI version."""
        from cloneguard.enforcement.landlock import (
            _LANDLOCK_ACCESS_FS_REFER,
            _LANDLOCK_ACCESS_FS_TRUNCATE,
            _build_handled_access_fs,
        )

        v1 = _build_handled_access_fs(1)
        v2 = _build_handled_access_fs(2)
        v3 = _build_handled_access_fs(3)
        assert not (v1 & _LANDLOCK_ACCESS_FS_REFER), "ABI v1 should not have REFER"
        assert not (v1 & _LANDLOCK_ACCESS_FS_TRUNCATE), "ABI v1 should not have TRUNCATE"
        assert v2 & _LANDLOCK_ACCESS_FS_REFER, "ABI v2 should have REFER"
        assert v3 & _LANDLOCK_ACCESS_FS_TRUNCATE, "ABI v3 should have TRUNCATE"

    def test_impl_seatbelt_profile_deny_default_first(self) -> None:
        """Seatbelt: (deny default) must appear before any (allow) rules."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/usr/lib"])
        profile = adapter._generate_profile()

        lines = [line.strip() for line in profile.split("\n") if line.strip()]
        deny_idx = next(i for i, line in enumerate(lines) if "(deny default)" in line)
        first_allow_idx = next(i for i, line in enumerate(lines) if "(allow" in line)
        assert deny_idx < first_allow_idx, "(deny default) must come before first (allow) rule"

    def test_impl_seatbelt_sbpl_injection_escaping(self) -> None:
        """T-02-15: Path escaping prevents SBPL injection."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        # Malicious path attempting SBPL injection
        malicious_path = '/tmp/evil") (allow file-read* (subpath "/etc/shadow'
        adapter.restrict_filesystem(writable=[malicious_path], readable=[])
        profile = adapter._generate_profile()

        # The injected SBPL should be escaped, not interpreted as code
        shadow_as_subpath = [
            line for line in profile.split("\n") if '(subpath "/etc/shadow")' in line
        ]
        assert len(shadow_as_subpath) == 0, (
            f"SBPL injection succeeded -- /etc/shadow allowed: {shadow_as_subpath}"
        )

    def test_impl_seatbelt_version_header(self) -> None:
        """Seatbelt: profile must start with (version 1)."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()
        assert profile.startswith("(version 1)")

    def test_impl_landlock_syscall_numbers_correct(self) -> None:
        """Landlock: syscall numbers match kernel headers for x86_64/aarch64."""
        from cloneguard.enforcement.landlock import (
            _SYS_LANDLOCK_ADD_RULE,
            _SYS_LANDLOCK_CREATE_RULESET,
            _SYS_LANDLOCK_RESTRICT_SELF,
        )

        # These are the same on x86_64 and aarch64
        assert _SYS_LANDLOCK_CREATE_RULESET == 444
        assert _SYS_LANDLOCK_ADD_RULE == 445
        assert _SYS_LANDLOCK_RESTRICT_SELF == 446

    def test_impl_landlock_ruleset_fd_always_closed(self) -> None:
        """Landlock: ruleset FD is closed in finally block (no leak on error)."""
        from cloneguard.enforcement.landlock import LandlockAdapter

        adapter = LandlockAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=[])

        closed_fds: list[int] = []

        def mock_syscall(*args: Any) -> int:
            if args[0] == 444:
                return 42  # ruleset fd
            if args[0] == 445:  # add_rule
                raise RuntimeError("Simulated add_rule failure")
            return 0

        mock_libc = mock.MagicMock()
        mock_libc.syscall.side_effect = mock_syscall

        def tracking_close(fd: int) -> None:
            closed_fds.append(fd)

        with (
            mock.patch("cloneguard.enforcement.landlock._get_libc", return_value=mock_libc),
            mock.patch("cloneguard.enforcement.landlock.os.open", return_value=10),
            mock.patch(
                "cloneguard.enforcement.landlock.os.close",
                side_effect=tracking_close,
            ),
        ):
            # Should not raise despite add_rule failure
            adapter.apply_restrictions()

        # Ruleset fd 42 must be closed even on error
        assert 42 in closed_fds, f"Ruleset FD not closed on error. Closed: {closed_fds}"
