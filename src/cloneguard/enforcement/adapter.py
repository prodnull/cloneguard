"""Sandbox adapter interface and implementations.

SandboxAdapter Protocol (PEP 544 structural subtyping) defines the contract
for OS-level sandbox enforcement. Adapters restrict filesystem and network
access for tool call subprocesses -- never for the CloneGuard process itself.

Auto-selection probes available capabilities at startup and returns the
strongest adapter. Operator can override via policy config. Fallback is
always NoopAdapter -- CloneGuard never fails to start due to missing sandbox.

Phase 2 core methods (D-04): restrict_filesystem, restrict_network
Deferred methods (D-05): snapshot, rollback, restrict_syscalls, get_audit_log
"""

from __future__ import annotations

import importlib
import logging
import sys
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class SandboxAdapter(Protocol):
    """Protocol for OS-level sandbox enforcement (D-04).

    Phase 2 core methods:
        restrict_filesystem: Apply filesystem read/write restrictions
        restrict_network: Apply network access restrictions

    Deferred methods (D-05, default no-op):
        snapshot: Capture pre-execution state (Phase 4 MELON)
        rollback: Revert to snapshot (Phase 4 MELON)
        restrict_syscalls: Syscall filtering (Phase 5 gVisor/Firecracker)
        get_audit_log: Retrieve sandbox audit trail (Phase 5)
    """

    @property
    def name(self) -> str:
        """Adapter name for audit events and logging."""
        ...

    def restrict_filesystem(
        self,
        writable: list[str],
        readable: list[str],
    ) -> None:
        """Apply filesystem restrictions to tool call subprocess.

        writable: paths the subprocess can read AND write
        readable: paths the subprocess can read only
        Must NEVER restrict the CloneGuard process itself.
        """
        ...

    def restrict_network(
        self,
        allow: list[str],
    ) -> None:
        """Apply network restrictions to tool call subprocess.

        allow: list of allowed domains/CIDRs
        Empty list = deny all network. Must NEVER restrict CloneGuard.
        """
        ...

    # Deferred methods (D-05) -- default implementations provided
    def snapshot(self) -> Any:
        """Capture pre-execution state. Deferred to Phase 4."""
        return None

    def rollback(self, snapshot: Any) -> None:
        """Revert to snapshot state. Deferred to Phase 4."""

    def restrict_syscalls(self, allowed: list[str]) -> None:
        """Apply syscall filter. Deferred to Phase 5."""

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Retrieve sandbox audit trail. Deferred to Phase 5."""
        return []


class NoopAdapter:
    """No-operation adapter -- preserves v0.5.0 detection-only behavior (D-07).

    All methods are no-ops. Default adapter and fallback when no OS-level
    sandbox is available or configured. Detection still runs; enforcement
    is bypassed.
    """

    @property
    def name(self) -> str:
        return "noop"

    def restrict_filesystem(
        self,
        writable: list[str],
        readable: list[str],
    ) -> None:
        pass  # Detection-only mode: no sandbox enforcement

    def restrict_network(
        self,
        allow: list[str],
    ) -> None:
        pass  # Detection-only mode: no sandbox enforcement

    def snapshot(self) -> Any:
        return None

    def rollback(self, snapshot: Any) -> None:
        pass

    def restrict_syscalls(self, allowed: list[str]) -> None:
        pass

    def get_audit_log(self) -> list[dict[str, Any]]:
        return []


def _probe_landlock() -> bool:
    """Check if Landlock LSM is available (Linux 5.13+)."""
    if sys.platform != "linux":
        return False
    try:
        import ctypes
        import ctypes.util

        lib_name = ctypes.util.find_library("c")
        if lib_name is None:
            return False
        libc = ctypes.CDLL(lib_name, use_errno=True)

        # Probe: create a minimal ruleset. If syscall exists, Landlock is available.
        # SYS_landlock_create_ruleset = 444 (x86_64 and aarch64)
        # Pass invalid args to just test if the syscall number is recognized.
        # Returns -1 with ENOSYS if not available, -1 with EINVAL if available.
        class _Attr(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]

        attr = _Attr(handled_access_fs=0)
        fd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if fd >= 0:
            import os

            os.close(fd)
            return True
        # ENOSYS = 38 (not available), EINVAL = 22 (available but invalid args)
        errno = ctypes.get_errno()
        return errno != 38  # Any error other than ENOSYS means Landlock exists
    except Exception:
        return False


def _probe_seatbelt() -> bool:
    """Check if Seatbelt (sandbox-exec) is available (macOS)."""
    if sys.platform != "darwin":
        return False
    try:
        import ctypes

        libsystem = ctypes.CDLL("libSystem.dylib")
        # Check if sandbox_init_with_parameters symbol exists
        _ = libsystem.sandbox_init_with_parameters
        return True
    except (OSError, AttributeError):
        return False


# Adapter registry: name -> (probe_fn, lazy_import_path)
# Ordered by strength: strongest first
_ADAPTER_REGISTRY: list[tuple[str, Any, str]] = [
    ("landlock", _probe_landlock, "cloneguard.enforcement.landlock"),
    ("seatbelt", _probe_seatbelt, "cloneguard.enforcement.seatbelt"),
]


def get_sandbox_adapter(preferred: str = "auto") -> SandboxAdapter:
    """Return the sandbox adapter to use for enforcement (D-06).

    Auto-selection: probe available capabilities, select strongest.
    Operator override: preferred="landlock"|"seatbelt"|"noop".
    Fallback: always NoopAdapter. Never fails.
    """
    if preferred == "noop":
        return NoopAdapter()

    if preferred == "auto":
        # Probe in order of strength
        for name, probe_fn, module_path in _ADAPTER_REGISTRY:
            try:
                if probe_fn():
                    return _load_adapter(name, module_path)
            except Exception:
                logger.debug("Probe failed for %s", name, exc_info=True)
                continue
        return NoopAdapter()

    # Specific adapter requested
    for name, probe_fn, module_path in _ADAPTER_REGISTRY:
        if name == preferred:
            try:
                if probe_fn():
                    return _load_adapter(name, module_path)
            except Exception:
                logger.warning(
                    "Requested adapter %s unavailable, falling back to noop",
                    preferred,
                )
            return NoopAdapter()

    logger.warning("Unknown adapter %s, falling back to noop", preferred)
    return NoopAdapter()


def _load_adapter(name: str, module_path: str) -> SandboxAdapter:
    """Lazy-import and instantiate an adapter by module path."""
    try:
        mod = importlib.import_module(module_path)
        # Convention: each adapter module exports a class named {Name}Adapter
        class_name = name.capitalize() + "Adapter"
        adapter_class = getattr(mod, class_name)
        return adapter_class()  # type: ignore[no-any-return]
    except Exception:
        logger.warning("Failed to load %s adapter", name, exc_info=True)
        return NoopAdapter()
