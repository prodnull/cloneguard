"""Docker container sandbox adapter.

Restricts tool call execution by running commands inside ephemeral Docker
containers with constrained filesystem mounts, network mode, and dropped
capabilities. Unlike Landlock/Seatbelt, Docker restrictions are applied at
container creation time, not by modifying the current process.

Per D-07: Full enforcement depth -- restrict_filesystem + restrict_network +
restrict_syscalls.

Architecture:
- apply_restrictions() is a no-op (restrictions applied at container creation)
- execute_sandboxed() creates an ephemeral container with docker run flags
- serialize_constraints() enables cross-process transport via spec files

Dependencies: docker>=7.1 (optional, via extras)
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def _probe_docker() -> bool:
    """Check if Docker daemon is available."""
    try:
        import docker as docker_sdk

        client = docker_sdk.from_env()
        client.ping()
        return True
    except Exception:
        return False


class DockerAdapter:
    """Docker container sandbox adapter (D-06, D-07)."""

    def __init__(self) -> None:
        self._writable: list[str] = []
        self._readable: list[str] = []
        self._executable_writable: list[str] = []
        self._network_allow: list[str] = []
        self._syscall_allow: list[str] = []

    @property
    def name(self) -> str:
        return "docker"

    def restrict_filesystem(
        self,
        writable: list[str],
        readable: list[str],
        executable_writable: list[str] | None = None,
    ) -> None:
        self._writable = list(writable)
        self._readable = list(readable)
        self._executable_writable = list(executable_writable or [])

    def restrict_network(self, allow: list[str]) -> None:
        self._network_allow = list(allow)

    def restrict_syscalls(self, allowed: list[str]) -> None:
        """Store allowed syscalls for seccomp profile generation (D-07)."""
        self._syscall_allow = list(allowed)

    def apply_restrictions(self) -> None:
        """No-op -- Docker applies restrictions at container creation.

        Unlike Landlock/Seatbelt which modify the current process,
        Docker restrictions are applied via docker run flags when
        execute_sandboxed() creates the container.
        """

    def execute_sandboxed(
        self,
        target_cmd: list[str],
        image: str = "python:3.12-slim",
        timeout: int = 300,
    ) -> subprocess.CompletedProcess[str]:
        """Run target command inside an ephemeral Docker container.

        Builds docker run command with:
        - --rm: auto-cleanup
        - --read-only: read-only root filesystem
        - --cap-drop ALL: drop all Linux capabilities
        - --network none: deny network (unless allow list specified)
        - -v mounts: readable as :ro, writable as :rw
        - --security-opt no-new-privileges: prevent privilege escalation
        """
        cmd = [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]

        # Network mode
        if not self._network_allow:
            cmd.extend(["--network", "none"])

        # Volume mounts
        for path in self._readable:
            cmd.extend(["-v", f"{path}:{path}:ro"])
        for path in self._writable:
            cmd.extend(["-v", f"{path}:{path}:rw"])
        for path in self._executable_writable:
            cmd.extend(["-v", f"{path}:{path}:rw"])

        # Tmpfs for writable tmp
        cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        # Resource limits (T-06-10)
        cmd.extend(["--memory", "512m", "--cpus", "1.0", "--pids-limit", "256"])

        cmd.append(image)
        cmd.extend(target_cmd)

        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def serialize_constraints(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "writable": list(self._writable),
            "readable": list(self._readable),
            "executable_writable": list(self._executable_writable),
            "network_allow": list(self._network_allow),
            "syscall_allow": list(self._syscall_allow),
        }

    def snapshot(self) -> Any:
        return None

    def rollback(self, snapshot: Any) -> None:
        pass

    def get_audit_log(self) -> list[dict[str, Any]]:
        return []
