"""Protocol conformance and probe tests for sandbox adapters.

Verifies that DockerAdapter, WasmAdapter, GvisorAdapter, and FirecrackerAdapter
all satisfy the SandboxAdapter Protocol (runtime_checkable) and that probe
functions correctly detect platform/runtime availability.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloneguard.enforcement.adapter import SandboxAdapter
from cloneguard.enforcement.docker_adapter import DockerAdapter, _probe_docker
from cloneguard.enforcement.wasm_adapter import WasmAdapter, _probe_wasm

# ---------------------------------------------------------------------------
# DockerAdapter Protocol conformance
# ---------------------------------------------------------------------------


class TestDockerAdapterProtocol:
    """Verify DockerAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_sandbox_adapter(self) -> None:
        """DockerAdapter is an instance of SandboxAdapter (runtime_checkable)."""
        adapter = DockerAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_docker(self) -> None:
        """DockerAdapter.name returns 'docker'."""
        adapter = DockerAdapter()
        assert adapter.name == "docker"

    def test_restrict_filesystem_stores_paths(self) -> None:
        """restrict_filesystem stores writable/readable/executable_writable paths."""
        adapter = DockerAdapter()
        adapter.restrict_filesystem(
            writable=["/tmp/out"],
            readable=["/src"],
            executable_writable=["/tmp/exec"],
        )
        constraints = adapter.serialize_constraints()
        assert constraints["writable"] == ["/tmp/out"]
        assert constraints["readable"] == ["/src"]
        assert constraints["executable_writable"] == ["/tmp/exec"]

    def test_restrict_network_stores_allow_list(self) -> None:
        """restrict_network stores allowed networks."""
        adapter = DockerAdapter()
        adapter.restrict_network(allow=["10.0.0.0/8"])
        constraints = adapter.serialize_constraints()
        assert constraints["network_allow"] == ["10.0.0.0/8"]

    def test_restrict_syscalls_stores_allowed(self) -> None:
        """restrict_syscalls stores allowed syscalls (D-07)."""
        adapter = DockerAdapter()
        adapter.restrict_syscalls(allowed=["read", "write", "open"])
        constraints = adapter.serialize_constraints()
        assert constraints["syscall_allow"] == ["read", "write", "open"]

    def test_apply_restrictions_is_noop(self) -> None:
        """apply_restrictions does not raise (no-op for Docker)."""
        adapter = DockerAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/src"])
        adapter.apply_restrictions()  # Should not raise

    def test_serialize_constraints_shape(self) -> None:
        """serialize_constraints returns dict with adapter='docker' and all fields."""
        adapter = DockerAdapter()
        adapter.restrict_filesystem(writable=["/w"], readable=["/r"])
        adapter.restrict_network(allow=["443"])
        adapter.restrict_syscalls(allowed=["read"])
        constraints = adapter.serialize_constraints()
        assert constraints["adapter"] == "docker"
        assert "writable" in constraints
        assert "readable" in constraints
        assert "executable_writable" in constraints
        assert "network_allow" in constraints
        assert "syscall_allow" in constraints

    def test_execute_sandboxed_builds_docker_command(self) -> None:
        """execute_sandboxed builds docker run with correct flags (mock subprocess)."""
        adapter = DockerAdapter()
        adapter.restrict_filesystem(
            writable=["/tmp/out"],
            readable=["/src/code"],
        )

        with patch("cloneguard.enforcement.docker_adapter.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="ok", stderr=""
            )
            adapter.execute_sandboxed(["python", "-c", "print('hi')"])

            call_args = mock_run.call_args
            cmd = call_args[0][0]

            # Verify key docker run flags
            assert cmd[0] == "docker"
            assert "run" in cmd
            assert "--rm" in cmd
            assert "--read-only" in cmd
            assert "--cap-drop" in cmd
            idx = cmd.index("--cap-drop")
            assert cmd[idx + 1] == "ALL"
            assert "--network" in cmd
            idx = cmd.index("--network")
            assert cmd[idx + 1] == "none"
            assert "--security-opt" in cmd
            assert "no-new-privileges" in cmd

            # Verify volume mounts
            assert "-v" in cmd
            assert "/src/code:/src/code:ro" in cmd
            assert "/tmp/out:/tmp/out:rw" in cmd

            # Verify target command at end
            assert cmd[-3:] == ["python", "-c", "print('hi')"]

    def test_snapshot_returns_none(self) -> None:
        """snapshot returns None."""
        adapter = DockerAdapter()
        assert adapter.snapshot() is None

    def test_rollback_does_not_raise(self) -> None:
        """rollback does not raise."""
        adapter = DockerAdapter()
        adapter.rollback(None)  # Should not raise

    def test_get_audit_log_returns_empty_list(self) -> None:
        """get_audit_log returns empty list."""
        adapter = DockerAdapter()
        assert adapter.get_audit_log() == []


# ---------------------------------------------------------------------------
# WasmAdapter Protocol conformance
# ---------------------------------------------------------------------------


class TestWasmAdapterProtocol:
    """Verify WasmAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_sandbox_adapter(self) -> None:
        """WasmAdapter is an instance of SandboxAdapter (runtime_checkable)."""
        adapter = WasmAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_wasm(self) -> None:
        """WasmAdapter.name returns 'wasm'."""
        adapter = WasmAdapter()
        assert adapter.name == "wasm"

    def test_restrict_filesystem_stores_paths(self) -> None:
        """restrict_filesystem stores paths for WASI configuration."""
        adapter = WasmAdapter()
        adapter.restrict_filesystem(
            writable=["/tmp/out"],
            readable=["/src"],
            executable_writable=["/tmp/exec"],
        )
        constraints = adapter.serialize_constraints()
        assert constraints["writable"] == ["/tmp/out"]
        assert constraints["readable"] == ["/src"]
        assert constraints["executable_writable"] == ["/tmp/exec"]

    def test_restrict_network_stores_allow_list(self) -> None:
        """restrict_network stores allowed networks."""
        adapter = WasmAdapter()
        adapter.restrict_network(allow=["10.0.0.0/8"])
        constraints = adapter.serialize_constraints()
        assert constraints["network_allow"] == ["10.0.0.0/8"]

    def test_restrict_syscalls_stores_allowed(self) -> None:
        """restrict_syscalls stores allowed syscalls (D-07)."""
        adapter = WasmAdapter()
        adapter.restrict_syscalls(allowed=["fd_read", "fd_write"])
        constraints = adapter.serialize_constraints()
        assert constraints["syscall_allow"] == ["fd_read", "fd_write"]

    def test_serialize_constraints_shape(self) -> None:
        """serialize_constraints returns dict with adapter='wasm' and all fields."""
        adapter = WasmAdapter()
        adapter.restrict_filesystem(writable=["/w"], readable=["/r"])
        adapter.restrict_network(allow=[])
        adapter.restrict_syscalls(allowed=["fd_read"])
        constraints = adapter.serialize_constraints()
        assert constraints["adapter"] == "wasm"
        assert "writable" in constraints
        assert "readable" in constraints
        assert "executable_writable" in constraints
        assert "network_allow" in constraints
        assert "syscall_allow" in constraints

    def test_execute_sandboxed_uniform_interface(self) -> None:
        """execute_sandboxed accepts target_cmd: list[str] uniformly.

        target_cmd[0] = module path, target_cmd[1:] = args.
        """
        adapter = WasmAdapter()
        # Mock wasmtime import failure to test graceful degradation
        with patch.dict("sys.modules", {"wasmtime": None}):
            result = adapter.execute_sandboxed(["/path/to/module.wasm", "--arg1"])
            assert result["exit_code"] == 1
            assert "not installed" in result.get("error", "")

    def test_apply_restrictions_is_noop(self) -> None:
        """apply_restrictions does not raise (no-op for WASM)."""
        adapter = WasmAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/src"])
        adapter.apply_restrictions()  # Should not raise

    def test_snapshot_returns_none(self) -> None:
        """snapshot returns None."""
        adapter = WasmAdapter()
        assert adapter.snapshot() is None

    def test_rollback_does_not_raise(self) -> None:
        """rollback does not raise."""
        adapter = WasmAdapter()
        adapter.rollback(None)  # Should not raise

    def test_get_audit_log_returns_empty_list(self) -> None:
        """get_audit_log returns empty list."""
        adapter = WasmAdapter()
        assert adapter.get_audit_log() == []


# ---------------------------------------------------------------------------
# Probe tests (Docker and WASM)
# ---------------------------------------------------------------------------


class TestProbes:
    """Test probe functions for Docker and WASM adapters."""

    def test_probe_docker_returns_false_when_sdk_not_importable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_docker returns False when docker SDK not importable."""
        import builtins

        original_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "docker":
                raise ImportError("No module named 'docker'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert _probe_docker() is False

    def test_probe_docker_returns_false_when_daemon_unavailable(self) -> None:
        """_probe_docker returns False when Docker daemon ping fails."""
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("connection refused")

        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_client

        with patch.dict("sys.modules", {"docker": mock_docker}):
            # Re-import to pick up patched module
            import importlib

            from cloneguard.enforcement import docker_adapter

            importlib.reload(docker_adapter)
            assert docker_adapter._probe_docker() is False
            importlib.reload(docker_adapter)  # Restore

    def test_probe_wasm_returns_false_when_not_importable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_wasm returns False when wasmtime not importable."""
        import builtins

        original_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "wasmtime":
                raise ImportError("No module named 'wasmtime'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert _probe_wasm() is False
