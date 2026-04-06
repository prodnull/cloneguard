"""Linux Landlock LSM sandbox adapter.

Applies filesystem and network restrictions via Landlock LSM syscalls
(Linux 5.13+). Uses ctypes for direct syscall invocation -- no external
dependencies.

Architecture: apply_restrictions() is called ONLY from within the
cloneguard-sandbox-exec wrapper process. The hook handler process
never calls it -- it only serializes constraints via serialize_constraints()
for cross-process transport. Since apply_restrictions() applies Landlock
to the CURRENT process (and exec preserves Landlock restrictions),
the restrictions persist into the target command.

Graceful degradation: if Landlock is unavailable (pre-5.13 kernel,
container without CAP_SYS_ADMIN, or non-Linux), apply_restrictions()
returns silently. Better to run unconfined than to crash the tool.

Reference: https://docs.kernel.org/userspace-api/landlock.html
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import platform
from typing import Any

logger = logging.getLogger(__name__)

# Landlock syscall numbers (same on x86_64 and aarch64)
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

# prctl constants -- prefer libc.prctl() when available (FIX 1)
_PR_SET_NO_NEW_PRIVS = 38
# Architecture-specific SYS_prctl numbers for fallback via libc.syscall()
_PRCTL_SYSCALL_BY_ARCH: dict[str, int] = {"x86_64": 157, "aarch64": 167}

# Landlock rule types
_LANDLOCK_RULE_PATH_BENEATH = 0x01
_LANDLOCK_RULE_NET_PORT = 0x02  # ABI v4+

# Filesystem access flags (Landlock ABI v1+)
_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12

# ABI v2+ filesystem flags
_LANDLOCK_ACCESS_FS_REFER = 1 << 13  # ABI v2+
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14  # ABI v3+

# Network access flags (Landlock ABI v4+)
_LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
_LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

# Composite access masks -- W^X split (FIX 5)
_ACCESS_READ = _LANDLOCK_ACCESS_FS_READ_FILE | _LANDLOCK_ACCESS_FS_READ_DIR
_ACCESS_WRITE = (
    _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
)
_ACCESS_WRITE_EXEC = _ACCESS_WRITE | _LANDLOCK_ACCESS_FS_EXECUTE

# Base filesystem access flags (ABI v1)
_BASE_FS_ACCESS_V1 = (
    _LANDLOCK_ACCESS_FS_EXECUTE
    | _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_READ_FILE
    | _LANDLOCK_ACCESS_FS_READ_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
)


def _build_handled_access_fs(abi_version: int) -> int:
    """Build handled_access_fs bitmask dynamically based on ABI version (FIX 6).

    ABI v1: base 13 flags. ABI v2: +REFER. ABI v3: +TRUNCATE.
    """
    mask = _BASE_FS_ACCESS_V1
    if abi_version >= 2:
        mask |= _LANDLOCK_ACCESS_FS_REFER
    if abi_version >= 3:
        mask |= _LANDLOCK_ACCESS_FS_TRUNCATE
    return mask


# Minimum always-allowed paths (T-02-13 / Pitfall 2 from research)
# FIX 3: /proc narrowed to /proc/self only (blocks /proc/[pid]/environ)
# FIX 4: /tmp removed -- private tmpdir injected by sandbox_exec
_ALWAYS_WRITABLE: tuple[str, ...] = ()
_ALWAYS_READABLE = (
    "/proc/self",  # glibc needs /proc/self/auxv, /proc/self/status, etc.
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/usr/lib",
    "/usr/local/lib",
    "/lib",
    "/lib64",
    "/etc",  # DNS resolution, user lookup
)

# ENOSYS errno value
_ENOSYS = 38


class _LandlockRulesetAttr(ctypes.Structure):
    """struct landlock_ruleset_attr -- ABI v4+ with network field."""

    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    """struct landlock_path_beneath_attr."""

    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _LandlockNetPortAttr(ctypes.Structure):
    """struct landlock_net_port_attr (ABI v4+)."""

    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


def _get_libc() -> Any | None:
    """Load libc for syscall invocation. Returns None if unavailable."""
    try:
        lib_name = ctypes.util.find_library("c")
        if lib_name is None:
            return None
        return ctypes.CDLL(lib_name, use_errno=True)
    except OSError:
        logger.debug("Failed to load libc", exc_info=True)
        return None


class LandlockAdapter:
    """Linux Landlock LSM sandbox adapter.

    Restricts filesystem and (optionally, v4+) network access via Landlock
    syscalls. apply_restrictions() applies restrictions to the CURRENT
    process -- called only from cloneguard-sandbox-exec, never from the
    hook handler.
    """

    def __init__(self) -> None:
        self._writable: list[str] = []
        self._readable: list[str] = []
        self._executable_writable: list[str] = []
        self._network_allow: list[str] = []
        self._abi_version: int = 0
        self._detect_abi_version()

    @property
    def name(self) -> str:
        """Adapter name for audit events and logging."""
        return "landlock"

    @property
    def abi_version(self) -> int:
        """Detected Landlock ABI version (0 = not available)."""
        return self._abi_version

    def _detect_abi_version(self) -> None:
        """Probe Landlock ABI version via create_ruleset(NULL, 0, flags=version).

        ABI version detection: syscall(444, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        Returns the ABI version number on success, -1 on failure.
        """
        try:
            libc = _get_libc()
            if libc is None:
                return
            # LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
            version = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, None, 0, 1)
            if version > 0:
                self._abi_version = version
                logger.debug("Landlock ABI version: %d", version)
            else:
                errno = ctypes.get_errno()
                if errno == _ENOSYS:
                    logger.debug("Landlock not available (ENOSYS)")
                else:
                    logger.debug("Landlock ABI probe returned %d, errno=%d", version, errno)
        except Exception:
            logger.debug("Landlock ABI detection failed", exc_info=True)

    def restrict_filesystem(
        self,
        writable: list[str],
        readable: list[str],
        executable_writable: list[str] | None = None,
    ) -> None:
        """Store filesystem restrictions for later application.

        Always includes minimum always-allowed paths (T-02-13).
        executable_writable: paths that need both write AND execute (FIX 5 W^X).
        """
        self._writable = list(set(list(writable) + list(_ALWAYS_WRITABLE)))
        self._readable = list(set(list(readable) + list(_ALWAYS_READABLE)))
        self._executable_writable = list(executable_writable or [])

    def restrict_network(
        self,
        allow: list[str],
    ) -> None:
        """Store network restrictions. Network enforcement requires Landlock v4+."""
        self._network_allow = list(allow)

    def apply_restrictions(self) -> None:
        """Apply Landlock restrictions to the CURRENT process.

        Called ONLY from cloneguard-sandbox-exec wrapper, never from hook handler.
        On failure, returns silently (graceful degradation).

        Steps:
        1. prctl(PR_SET_NO_NEW_PRIVS) -- required before landlock_restrict_self
        2. landlock_create_ruleset with handled_access_fs bitmask
        3. landlock_add_rule for each readable and writable path
        4. landlock_restrict_self -- finalize enforcement
        5. Close ruleset fd
        """
        libc = _get_libc()
        if libc is None:
            logger.warning("Landlock: libc unavailable, running unrestricted")
            return

        try:
            self._apply_with_libc(libc)
        except Exception:
            logger.warning(
                "Landlock: apply_restrictions failed, running unrestricted",
                exc_info=True,
            )

    def _set_no_new_privs(self, libc: Any) -> bool:
        """Set PR_SET_NO_NEW_PRIVS via libc.prctl() or fallback syscall (FIX 1).

        Returns True on success, False on failure.
        """
        if hasattr(libc, "prctl"):
            ret = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        else:
            prctl_nr = _PRCTL_SYSCALL_BY_ARCH.get(platform.machine())
            if prctl_nr is None:
                logger.warning(
                    "Landlock: unknown architecture %s, cannot set NO_NEW_PRIVS",
                    platform.machine(),
                )
                return False
            ret = libc.syscall(prctl_nr, _PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if ret == -1:
            errno = ctypes.get_errno()
            logger.warning("Landlock: prctl failed, errno=%d", errno)
            return False
        return True

    def _apply_with_libc(self, libc: Any) -> None:
        """Internal: apply restrictions using the provided libc handle."""
        # Step 1: prctl(PR_SET_NO_NEW_PRIVS) -- FIX 1 portable
        if not self._set_no_new_privs(libc):
            return

        # Step 2: landlock_create_ruleset -- FIX 6 dynamic ABI flags
        abi = max(self._abi_version, 1)
        handled_fs = _build_handled_access_fs(abi)

        # FIX 2: network enforcement for ABI v4+
        handled_net: int = 0
        if self._abi_version >= 4 and self._network_allow != ["*"]:
            handled_net = _LANDLOCK_ACCESS_NET_CONNECT_TCP

        attr = _LandlockRulesetAttr(
            handled_access_fs=handled_fs,
            handled_access_net=handled_net,
        )
        ruleset_fd = libc.syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.byref(attr),
            ctypes.sizeof(attr),
            0,
        )
        if ruleset_fd < 0:
            errno = ctypes.get_errno()
            if errno == _ENOSYS:
                logger.debug("Landlock: not available (ENOSYS)")
            else:
                logger.warning("Landlock: create_ruleset failed, errno=%d", errno)
            return

        try:
            # Step 3a: Add filesystem rules for each path
            for path in self._readable:
                self._add_path_rule(libc, ruleset_fd, path, _ACCESS_READ)
            for path in self._writable:
                self._add_path_rule(libc, ruleset_fd, path, _ACCESS_WRITE)
            # FIX 5: W^X -- executable_writable paths get write+execute
            for path in self._executable_writable:
                self._add_path_rule(libc, ruleset_fd, path, _ACCESS_WRITE_EXEC)

            # Step 3b: Add network rules (FIX 2)
            if handled_net and self._abi_version >= 4:
                self._add_network_rules(libc, ruleset_fd)

            # Step 4: landlock_restrict_self
            ret = libc.syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
            if ret == -1:
                errno = ctypes.get_errno()
                logger.warning("Landlock: restrict_self failed, errno=%d", errno)
        finally:
            # Step 5: Close ruleset fd
            os.close(ruleset_fd)

    def _add_network_rules(self, libc: Any, ruleset_fd: int) -> None:
        """Add Landlock v4+ TCP port allow rules (FIX 2).

        When network_allow is empty, handled_access_net catches all TCP connect
        but no allow rules are added -- effectively deny-all.
        """
        if self._abi_version < 4:
            logger.warning("Landlock: network enforcement requires ABI v4+")
            return

        for entry in self._network_allow:
            if entry == "*":
                continue  # Wildcard handled by not adding handled_access_net
            # Only accept numeric port strings
            if not entry.isdigit():
                logger.warning(
                    "Landlock: network_allow entry %r is not a port number "
                    "(domain filtering not supported by Landlock), skipping",
                    entry,
                )
                continue
            port = int(entry)
            rule_attr = _LandlockNetPortAttr(
                allowed_access=_LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port=port,
            )
            ret = libc.syscall(
                _SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                _LANDLOCK_RULE_NET_PORT,
                ctypes.byref(rule_attr),
                0,
            )
            if ret == -1:
                errno = ctypes.get_errno()
                logger.debug(
                    "Landlock: add_rule (net port %d) failed, errno=%d",
                    port,
                    errno,
                )

    def _add_path_rule(
        self,
        libc: Any,
        ruleset_fd: int,
        path: str,
        access_mask: int,
    ) -> None:
        """Add a Landlock path rule for a single path."""
        # O_PATH (0x200000) is Linux-only; O_CLOEXEC (0x80000) is Linux-only
        o_path = getattr(os, "O_PATH", 0x200000)
        o_cloexec = getattr(os, "O_CLOEXEC", 0x80000)
        try:
            path_fd = os.open(path, o_path | o_cloexec)
        except OSError:
            logger.debug("Landlock: cannot open path %s, skipping", path)
            return

        try:
            rule_attr = _LandlockPathBeneathAttr(
                allowed_access=access_mask,
                parent_fd=path_fd,
            )
            ret = libc.syscall(
                _SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                _LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(rule_attr),
                0,
            )
            if ret == -1:
                errno = ctypes.get_errno()
                logger.debug("Landlock: add_rule failed for %s, errno=%d", path, errno)
        finally:
            os.close(path_fd)

    def serialize_constraints(self) -> dict[str, Any]:
        """Serialize constraints for cross-process transport.

        Returns a JSON-serializable dict suitable for writing to a spec file
        that cloneguard-sandbox-exec reads.
        """
        return {
            "adapter": self.name,
            "writable": list(self._writable),
            "readable": list(self._readable),
            "executable_writable": list(self._executable_writable),
            "network_allow": list(self._network_allow),
        }

    def snapshot(self) -> dict[str, bytes]:
        """Capture file contents for writable paths before MELON execution.

        Returns dict mapping absolute path -> file bytes for each writable
        file that exists. Landlock restrictions are irrevocable; this captures
        the file state to enable content rollback, not restriction rollback.
        """
        from pathlib import Path

        captured: dict[str, bytes] = {}
        for path_str in self._writable:
            p = Path(path_str).resolve()
            if p.is_file():
                try:
                    captured[str(p)] = p.read_bytes()
                except OSError:
                    logger.warning("snapshot: could not read %s", p)
        return captured

    def rollback(self, snapshot: dict[str, bytes]) -> None:  # type: ignore[override]
        """Restore file contents to pre-execution state.

        Writes back the byte content captured by snapshot(). Does not
        undo Landlock restrictions (irrevocable by kernel design).
        """
        from pathlib import Path

        if not snapshot:
            return
        for path_str, content in snapshot.items():
            p = Path(path_str)
            try:
                p.write_bytes(content)
            except OSError:
                logger.warning("rollback: could not restore %s", p)

    def restrict_syscalls(self, allowed: list[str]) -> None:
        """Apply syscall filter. Deferred to Phase 5."""

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Retrieve sandbox audit trail. Deferred to Phase 5."""
        return []
