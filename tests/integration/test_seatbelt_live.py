"""Live macOS Seatbelt sandbox integration tests.

These tests invoke cloneguard-sandbox-exec with real Seatbelt restrictions
on a subprocess. The subprocess is sandboxed — the test runner is NOT.

Skip on non-macOS platforms.
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

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="Seatbelt tests require macOS",
)


def _find_sandbox_exec() -> list[str]:
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
def sandbox_exec_cmd() -> list[str]:
    """Command to invoke cloneguard-sandbox-exec."""
    return _find_sandbox_exec()


@pytest.fixture
def project_dir(tmp_path: object) -> str:
    """Temporary project directory for writable scope."""
    d = str(tmp_path)
    with open(os.path.join(d, "allowed.txt"), "w") as f:
        f.write("allowed content")
    return d


def _make_policy(constraints: dict[str, object]) -> str:
    return base64.b64encode(json.dumps(constraints).encode()).decode()


class TestSeatbeltFilesystemRestriction:
    """Verify Seatbelt restricts filesystem access for sandboxed subprocess."""

    def test_can_write_to_allowed_path(self, sandbox_exec_cmd: list[str], project_dir: str) -> None:
        """Subprocess can write to paths in the writable list."""
        policy = _make_policy(
            {
                "adapter": "seatbelt",
                "writable": [project_dir],
                "readable": [],
                "network_allow": [],
            }
        )
        outfile = os.path.join(project_dir, "output.txt")
        cmd = " ".join(["echo", '"sandboxed write"', ">", outfile])
        result = subprocess.run(
            [*sandbox_exec_cmd, "--policy", policy, "--", "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert os.path.exists(outfile)
        with open(outfile) as f:
            assert "sandboxed write" in f.read()

    def test_cannot_write_outside_allowed_path(
        self, sandbox_exec_cmd: list[str], project_dir: str
    ) -> None:
        """Subprocess CANNOT write outside the allowed writable paths."""
        policy = _make_policy(
            {
                "adapter": "seatbelt",
                "writable": [project_dir],
                "readable": [],
                "network_allow": [],
            }
        )
        forbidden = os.path.expanduser("~/cg-seatbelt-test-forbidden.txt")
        cmd = " ".join(["echo", '"should fail"', ">", forbidden])
        result = subprocess.run(
            [*sandbox_exec_cmd, "--policy", policy, "--", "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0 or not os.path.exists(forbidden)
        if os.path.exists(forbidden):
            os.unlink(forbidden)

    def test_cannot_read_outside_allowed_path(
        self, sandbox_exec_cmd: list[str], project_dir: str
    ) -> None:
        """Subprocess CANNOT read arbitrary user files."""
        policy = _make_policy(
            {
                "adapter": "seatbelt",
                "writable": [project_dir],
                "readable": [project_dir],
                "network_allow": [],
            }
        )
        target = os.path.expanduser("~/.zshrc")
        if not os.path.exists(target):
            target = os.path.expanduser("~/.bashrc")
        if not os.path.exists(target):
            pytest.skip("No shell rc file to test read restriction")
        result = subprocess.run(
            [*sandbox_exec_cmd, "--policy", policy, "--", "cat", target],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0, f"Expected cat {target} to fail under sandbox"

    def test_can_read_system_paths(self, sandbox_exec_cmd: list[str], project_dir: str) -> None:
        """Subprocess can read system paths (always-allowed)."""
        policy = _make_policy(
            {
                "adapter": "seatbelt",
                "writable": [project_dir],
                "readable": [],
                "network_allow": [],
            }
        )
        result = subprocess.run(
            [*sandbox_exec_cmd, "--policy", policy, "--", "ls", "/usr/bin/true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "/usr/bin/true" in result.stdout

    def test_spec_file_mode(self, sandbox_exec_cmd: list[str], project_dir: str) -> None:
        """Test --spec-file mode (production path)."""
        constraints = {
            "adapter": "seatbelt",
            "writable": [project_dir],
            "readable": [],
            "network_allow": [],
        }
        fd, spec_path = tempfile.mkstemp(prefix="cg-test-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(constraints, f)
        outfile = os.path.join(project_dir, "spec-output.txt")
        cmd = " ".join(["echo", '"spec mode"', ">", outfile])
        result = subprocess.run(
            [*sandbox_exec_cmd, "--spec-file", spec_path, "--", "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert os.path.exists(outfile)
        assert not os.path.exists(spec_path), "Spec file should be deleted"


class TestSeatbeltNoConstraints:
    """Verify no-constraint mode preserves full access."""

    def test_no_policy_runs_unrestricted(
        self,
        sandbox_exec_cmd: list[str],
    ) -> None:
        """Without --policy or --spec-file, subprocess runs unrestricted."""
        result = subprocess.run(
            [*sandbox_exec_cmd, "--", "echo", "unrestricted"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "unrestricted" in result.stdout
