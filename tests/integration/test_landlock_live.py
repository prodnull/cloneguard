"""Live Linux Landlock sandbox integration tests.

Run directly on a Linux host with kernel 5.13+ and Landlock LSM enabled.
Intended for CI (ubuntu-latest) -- LinuxKit (Docker Desktop on macOS) does NOT
include Landlock.

Skip on non-Linux or kernels without Landlock.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import subprocess
import tempfile

import pytest

# Skip on non-Linux
if platform.system() != "Linux":
    pytestmark = pytest.mark.skip(reason="Landlock tests require Linux")
else:
    _LANDLOCK_AVAILABLE = os.path.isfile("/sys/kernel/security/landlock/abi_version")
    pytestmark = pytest.mark.skipif(
        not _LANDLOCK_AVAILABLE,
        reason="Landlock LSM not available",
    )


def _find_sandbox_binary() -> list[str]:
    """Find cloneguard-sandbox-exec binary."""
    binary = shutil.which("cloneguard-sandbox-exec")
    if binary:
        return [binary]
    venv_bin = os.path.join(os.environ.get("VIRTUAL_ENV", ""), "bin", "cloneguard-sandbox-exec")
    if os.path.isfile(venv_bin):
        return [venv_bin]
    import sys

    return [sys.executable, "-m", "cloneguard.enforcement.sandbox_exec"]


@pytest.fixture
def sandbox_cmd() -> list[str]:
    """Command to invoke cloneguard-sandbox-exec."""
    return _find_sandbox_binary()


@pytest.fixture
def project_dir(tmp_path: object) -> str:
    """Temporary project directory for writable scope."""
    d = str(tmp_path)
    with open(os.path.join(d, "allowed.txt"), "w") as f:
        f.write("allowed content")
    return d


def _encode_policy(constraints: dict[str, object]) -> str:
    return base64.b64encode(json.dumps(constraints).encode()).decode()


class TestLandlockKernelSupport:
    """Verify Landlock is available and functional."""

    def test_landlock_abi_version(self) -> None:
        """Kernel reports Landlock ABI version >= 1."""
        with open("/sys/kernel/security/landlock/abi_version") as f:
            version = int(f.read().strip())
        assert version >= 1, f"Landlock ABI v{version} too old"


class TestLandlockFilesystemRestriction:
    """Verify Landlock restricts filesystem for sandboxed subprocess."""

    def test_can_write_to_allowed_path(self, sandbox_cmd: list[str], project_dir: str) -> None:
        """Subprocess can write to paths in the writable list."""
        policy = _encode_policy(
            {
                "adapter": "landlock",
                "writable": [project_dir],
                "readable": [project_dir],
                "network_allow": [],
            }
        )
        outfile = os.path.join(project_dir, "output.txt")
        shell_cmd = f'echo "sandboxed write" > {outfile}'
        result = subprocess.run(
            [*sandbox_cmd, "--policy", policy, "--", "bash", "-c", shell_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert os.path.exists(outfile)
        with open(outfile) as f:
            assert "sandboxed write" in f.read()

    def test_cannot_write_outside_allowed_path(
        self, sandbox_cmd: list[str], project_dir: str
    ) -> None:
        """Subprocess CANNOT write outside allowed paths."""
        policy = _encode_policy(
            {
                "adapter": "landlock",
                "writable": [project_dir],
                "readable": [project_dir],
                "network_allow": [],
            }
        )
        forbidden = "/var/tmp/cg-landlock-test-forbidden.txt"
        shell_cmd = f'echo "should fail" > {forbidden}'
        result = subprocess.run(
            [*sandbox_cmd, "--policy", policy, "--", "bash", "-c", shell_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0 or not os.path.exists(forbidden)
        if os.path.exists(forbidden):
            os.unlink(forbidden)

    def test_cannot_read_outside_allowed_path(
        self, sandbox_cmd: list[str], project_dir: str
    ) -> None:
        """Subprocess CANNOT read files outside allowed paths."""
        policy = _encode_policy(
            {
                "adapter": "landlock",
                "writable": [project_dir],
                "readable": [project_dir],
                "network_allow": [],
            }
        )
        fd, secret_path = tempfile.mkstemp(prefix="cg-secret-", dir="/var/tmp")
        with os.fdopen(fd, "w") as f:
            f.write("top secret data")
        try:
            result = subprocess.run(
                [*sandbox_cmd, "--policy", policy, "--", "cat", secret_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode != 0, "Read outside sandbox succeeded"
            assert "top secret" not in result.stdout, "Secret data leaked"
        finally:
            os.unlink(secret_path)

    def test_can_read_system_paths(self, sandbox_cmd: list[str], project_dir: str) -> None:
        """Subprocess can read system paths (always-allowed)."""
        policy = _encode_policy(
            {
                "adapter": "landlock",
                "writable": [project_dir],
                "readable": [project_dir],
                "network_allow": [],
            }
        )
        result = subprocess.run(
            [*sandbox_cmd, "--policy", policy, "--", "ls", "/usr/bin/true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "/usr/bin/true" in result.stdout

    def test_spec_file_mode(self, sandbox_cmd: list[str], project_dir: str) -> None:
        """Test --spec-file mode (production path)."""
        constraints = {
            "adapter": "landlock",
            "writable": [project_dir],
            "readable": [project_dir],
            "network_allow": [],
        }
        fd, spec_path = tempfile.mkstemp(prefix="cg-test-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)
        outfile = os.path.join(project_dir, "spec-output.txt")
        shell_cmd = f'echo "spec mode" > {outfile}'
        result = subprocess.run(
            [*sandbox_cmd, "--spec-file", spec_path, "--", "bash", "-c", shell_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert os.path.exists(outfile)
        assert not os.path.exists(spec_path), "Spec file should be deleted"


class TestLandlockNoConstraints:
    """Verify no-constraint mode preserves full access."""

    def test_no_policy_runs_unrestricted(
        self,
        sandbox_cmd: list[str],
    ) -> None:
        """Without constraints, subprocess has full access."""
        result = subprocess.run(
            [*sandbox_cmd, "--", "echo", "unrestricted"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "unrestricted" in result.stdout
