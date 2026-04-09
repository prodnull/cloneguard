"""macOS Seatbelt sandbox adapter.

Applies filesystem and network restrictions via Apple's Seatbelt (sandbox-exec)
framework using ctypes calls to libSystem.dylib's sandbox_init_with_parameters.

Architecture: apply_restrictions() generates an SBPL (Scheme-based Policy
Language) profile and applies it via sandbox_init_with_parameters to the
CURRENT process. Called ONLY from cloneguard-sandbox-exec wrapper -- never
from the hook handler. Since sandbox_init applies to the calling process
and exec preserves Seatbelt restrictions, the target command inherits them.

SBPL profiles use deny-default baseline with selective allows for:
- Always-allowed system paths (temp dirs, system libraries, executables)
- User-specified writable paths (file-read* + file-write*)
- User-specified readable paths (file-read* only)
- Network (network-outbound if explicitly allowed)

Note: sandbox-exec is deprecated by Apple but remains functional on all
current macOS versions. sandbox_init_with_parameters is the programmatic
equivalent.

Graceful degradation: if libSystem.dylib is unavailable or sandbox_init
fails, apply_restrictions() returns silently.
"""

from __future__ import annotations

import ctypes
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Always-allowed system paths for macOS (T-02-13)
# FIX 4: /tmp, /private/tmp, /private/var/folders removed from writable --
# private tmpdir injected by sandbox_exec
_ALWAYS_WRITABLE: tuple[str, ...] = ()
_ALWAYS_READABLE = (
    "/usr/lib",
    "/usr/local/lib",
    "/Library/Frameworks",
    "/System/Library",
    "/bin",
    "/usr/bin",
    "/usr/sbin",
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
)


def _escape_sbpl_path(path: str) -> str:
    """Escape a path for safe embedding in SBPL profile strings.

    T-02-15: Prevents SBPL injection via crafted path strings.
    Doubles backslashes and escapes double-quotes.
    """
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _get_libsystem() -> Any | None:
    """Load libSystem.dylib for sandbox_init_with_parameters. Returns None if unavailable."""
    try:
        return ctypes.CDLL("libSystem.dylib")
    except OSError:
        logger.debug("Failed to load libSystem.dylib", exc_info=True)
        return None


class SeatbeltAdapter:
    """macOS Seatbelt sandbox adapter.

    Generates deny-default SBPL profiles and applies them via
    sandbox_init_with_parameters from libSystem.dylib.
    apply_restrictions() applies sandbox to the CURRENT process --
    called only from cloneguard-sandbox-exec, never from the hook handler.
    """

    def __init__(self) -> None:
        self._writable: list[str] = []
        self._readable: list[str] = []
        self._network_allow: list[str] = []

    @property
    def name(self) -> str:
        """Adapter name for audit events and logging."""
        return "seatbelt"

    def restrict_filesystem(
        self,
        writable: list[str],
        readable: list[str],
        executable_writable: list[str] | None = None,
    ) -> None:
        """Store filesystem restrictions for profile generation.

        executable_writable is accepted for Protocol compatibility but
        Seatbelt does not distinguish W^X at the profile level.
        """
        self._writable = list(writable) + list(executable_writable or [])
        self._readable = list(readable)

    def restrict_network(
        self,
        allow: list[str],
    ) -> None:
        """Store network restrictions for profile generation."""
        self._network_allow = list(allow)

    def _generate_profile(self) -> str:
        """Generate an SBPL profile string with deny-default baseline.

        Structure:
        1. (version 1) header
        2. (deny default) baseline
        3. (import "bsd.sb") standard BSD operations
        4. Always-allowed process execution paths
        5. Always-allowed system library paths
        6. Always-allowed temp paths
        7. User-specified readable paths (file-read*)
        8. User-specified writable paths (file-read* + file-write*)
        9. Network rules (if network_allow non-empty)
        """
        lines: list[str] = [
            "(version 1)",
            "(deny default)",
            '(import "bsd.sb")',
            "",
            ";; Process execution (always allowed)",
            '(allow process-exec (subpath "/bin"))',
            '(allow process-exec (subpath "/usr/bin"))',
            '(allow process-exec (subpath "/usr/sbin"))',
            "",
            ";; System libraries (always allowed)",
        ]

        for path in _ALWAYS_READABLE:
            escaped = _escape_sbpl_path(path)
            lines.append(f'(allow file-read* (subpath "{escaped}"))')

        # FIX 4: system temp paths removed; private tmpdir injected via writable
        if _ALWAYS_WRITABLE:
            lines.append("")
            lines.append(";; Temp paths (always writable)")
            for path in _ALWAYS_WRITABLE:
                escaped = _escape_sbpl_path(path)
                lines.append(f'(allow file-read* file-write* (subpath "{escaped}"))')

        # User-specified readable paths
        if self._readable:
            lines.append("")
            lines.append(";; User-specified readable paths")
            for path in self._readable:
                escaped = _escape_sbpl_path(path)
                lines.append(f'(allow file-read* (subpath "{escaped}"))')

        # User-specified writable paths
        if self._writable:
            lines.append("")
            lines.append(";; User-specified writable paths")
            for path in self._writable:
                escaped = _escape_sbpl_path(path)
                lines.append(f'(allow file-read* file-write* (subpath "{escaped}"))')

        # Network rules
        if self._network_allow:
            lines.append("")
            lines.append(";; Network rules")
            lines.append("(allow network-outbound)")

        return "\n".join(lines) + "\n"

    def apply_restrictions(self) -> None:
        """Apply Seatbelt sandbox to the CURRENT process.

        Called ONLY from cloneguard-sandbox-exec wrapper, never from hook handler.
        On failure, returns silently (graceful degradation).
        """
        libsystem = _get_libsystem()
        if libsystem is None:
            logger.warning("Seatbelt: libSystem unavailable, running unrestricted")
            return

        try:
            profile = self._generate_profile()
            profile_bytes = profile.encode("utf-8")

            # sandbox_init_with_parameters(profile, flags, params, errorbuf)
            # flags=0 for custom profile, params=NULL, errorbuf=pointer to char*
            errorbuf = ctypes.c_char_p()
            ret = libsystem.sandbox_init_with_parameters(
                profile_bytes,
                0,
                None,
                ctypes.byref(errorbuf),
            )
            if ret != 0:
                error_msg = errorbuf.value.decode("utf-8") if errorbuf.value else "unknown"
                logger.warning("Seatbelt: sandbox_init failed: %s", error_msg)
        except Exception:
            logger.warning(
                "Seatbelt: apply_restrictions failed, running unrestricted",
                exc_info=True,
            )

    def serialize_constraints(self) -> dict[str, Any]:
        """Serialize constraints for cross-process transport.

        Returns a JSON-serializable dict suitable for writing to a spec file
        that cloneguard-sandbox-exec reads.
        """
        return {
            "adapter": self.name,
            "writable": list(self._writable),
            "readable": list(self._readable),
            "network_allow": list(self._network_allow),
        }

    def snapshot(self) -> dict[str, bytes]:
        """Capture file contents for writable paths before MELON execution.

        Returns dict mapping absolute path -> file bytes for each writable
        file that exists. Seatbelt restrictions are irrevocable; this captures
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

    def rollback(self, snapshot: dict[str, bytes]) -> None:
        """Restore file contents to pre-execution state.

        Writes back the byte content captured by snapshot(). Does not
        undo Seatbelt restrictions (irrevocable by kernel design).
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
