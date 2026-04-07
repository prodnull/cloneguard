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
from cloneguard.enforcement.firecracker_adapter import (
    FirecrackerAdapter,
    _probe_firecracker,
)
from cloneguard.enforcement.gvisor_adapter import GvisorAdapter, _probe_gvisor
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
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
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
# GvisorAdapter Protocol conformance
# ---------------------------------------------------------------------------


class TestGvisorAdapterProtocol:
    """Verify GvisorAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_sandbox_adapter(self) -> None:
        """GvisorAdapter is an instance of SandboxAdapter (runtime_checkable)."""
        adapter = GvisorAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_gvisor(self) -> None:
        """GvisorAdapter.name returns 'gvisor'."""
        adapter = GvisorAdapter()
        assert adapter.name == "gvisor"

    def test_restrict_filesystem_stores_paths(self) -> None:
        """restrict_filesystem stores writable/readable/executable_writable paths."""
        adapter = GvisorAdapter()
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
        adapter = GvisorAdapter()
        adapter.restrict_network(allow=["10.0.0.0/8"])
        constraints = adapter.serialize_constraints()
        assert constraints["network_allow"] == ["10.0.0.0/8"]

    def test_restrict_syscalls_stores_allowed(self) -> None:
        """restrict_syscalls stores allowed syscalls (D-07)."""
        adapter = GvisorAdapter()
        adapter.restrict_syscalls(allowed=["read", "write", "mmap"])
        constraints = adapter.serialize_constraints()
        assert constraints["syscall_allow"] == ["read", "write", "mmap"]

    def test_apply_restrictions_is_noop(self) -> None:
        """apply_restrictions does not raise (no-op for gVisor)."""
        adapter = GvisorAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/src"])
        adapter.apply_restrictions()  # Should not raise

    def test_serialize_constraints_shape(self) -> None:
        """serialize_constraints returns dict with adapter='gvisor' and all fields."""
        adapter = GvisorAdapter()
        adapter.restrict_filesystem(writable=["/w"], readable=["/r"])
        adapter.restrict_network(allow=["443"])
        adapter.restrict_syscalls(allowed=["read"])
        constraints = adapter.serialize_constraints()
        assert constraints["adapter"] == "gvisor"
        assert "writable" in constraints
        assert "readable" in constraints
        assert "executable_writable" in constraints
        assert "network_allow" in constraints
        assert "syscall_allow" in constraints

    def test_execute_sandboxed_builds_runsc_command(self) -> None:
        """execute_sandboxed builds docker run --runtime=runsc command (mock subprocess)."""
        adapter = GvisorAdapter()
        adapter.restrict_filesystem(
            writable=["/tmp/out"],
            readable=["/src/code"],
        )

        with patch("cloneguard.enforcement.gvisor_adapter.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
            adapter.execute_sandboxed(["python", "-c", "print('hi')"])

            call_args = mock_run.call_args
            cmd = call_args[0][0]

            # Verify gVisor-specific runtime flag
            assert "--runtime" in cmd
            idx = cmd.index("--runtime")
            assert cmd[idx + 1] == "runsc"

            # Verify standard Docker security flags still present
            assert "--cap-drop" in cmd
            assert "--read-only" in cmd
            assert "--network" in cmd

    def test_snapshot_returns_none(self) -> None:
        """snapshot returns None."""
        adapter = GvisorAdapter()
        assert adapter.snapshot() is None

    def test_rollback_does_not_raise(self) -> None:
        """rollback does not raise."""
        adapter = GvisorAdapter()
        adapter.rollback(None)  # Should not raise

    def test_get_audit_log_returns_empty_list(self) -> None:
        """get_audit_log returns empty list."""
        adapter = GvisorAdapter()
        assert adapter.get_audit_log() == []


# ---------------------------------------------------------------------------
# FirecrackerAdapter Protocol conformance
# ---------------------------------------------------------------------------


class TestFirecrackerAdapterProtocol:
    """Verify FirecrackerAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_sandbox_adapter(self) -> None:
        """FirecrackerAdapter is an instance of SandboxAdapter (runtime_checkable)."""
        adapter = FirecrackerAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_firecracker(self) -> None:
        """FirecrackerAdapter.name returns 'firecracker'."""
        adapter = FirecrackerAdapter()
        assert adapter.name == "firecracker"

    def test_restrict_filesystem_stores_paths(self) -> None:
        """restrict_filesystem stores writable/readable/executable_writable paths."""
        adapter = FirecrackerAdapter()
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
        adapter = FirecrackerAdapter()
        adapter.restrict_network(allow=["10.0.0.0/8"])
        constraints = adapter.serialize_constraints()
        assert constraints["network_allow"] == ["10.0.0.0/8"]

    def test_restrict_syscalls_stores_allowed(self) -> None:
        """restrict_syscalls stores allowed syscalls (D-07)."""
        adapter = FirecrackerAdapter()
        adapter.restrict_syscalls(allowed=["read", "write", "ioctl"])
        constraints = adapter.serialize_constraints()
        assert constraints["syscall_allow"] == ["read", "write", "ioctl"]

    def test_apply_restrictions_is_noop(self) -> None:
        """apply_restrictions does not raise (no-op for Firecracker)."""
        adapter = FirecrackerAdapter()
        adapter.restrict_filesystem(writable=["/tmp"], readable=["/src"])
        adapter.apply_restrictions()  # Should not raise

    def test_serialize_constraints_shape(self) -> None:
        """serialize_constraints returns dict with adapter='firecracker' and all fields."""
        adapter = FirecrackerAdapter()
        adapter.restrict_filesystem(writable=["/w"], readable=["/r"])
        adapter.restrict_network(allow=[])
        adapter.restrict_syscalls(allowed=["read"])
        constraints = adapter.serialize_constraints()
        assert constraints["adapter"] == "firecracker"
        assert "writable" in constraints
        assert "readable" in constraints
        assert "executable_writable" in constraints
        assert "network_allow" in constraints
        assert "syscall_allow" in constraints

    def test_execute_sandboxed_calls_api(self) -> None:
        """execute_sandboxed sends REST API calls to Firecracker socket (mock)."""
        adapter = FirecrackerAdapter(socket_path="/tmp/test.socket")

        with patch(
            "cloneguard.enforcement.firecracker_adapter._UnixHTTPConnection"
        ) as mock_conn_cls:
            mock_conn = MagicMock()
            mock_response = MagicMock()
            mock_response.read.return_value = b"{}"
            mock_conn.getresponse.return_value = mock_response
            mock_conn_cls.return_value = mock_conn

            result = adapter.execute_sandboxed(["echo", "hello"])

            assert result["exit_code"] == 0

            # Verify API calls were made (boot-source, machine-config,
            # drives/rootfs, actions)
            calls = mock_conn.request.call_args_list
            assert len(calls) == 4

            # Boot source
            assert calls[0][0][0] == "PUT"
            assert calls[0][0][1] == "/boot-source"

            # Machine config
            assert calls[1][0][0] == "PUT"
            assert calls[1][0][1] == "/machine-config"

            # Root drive
            assert calls[2][0][0] == "PUT"
            assert calls[2][0][1] == "/drives/rootfs"

            # Instance start
            assert calls[3][0][0] == "PUT"
            assert calls[3][0][1] == "/actions"

    def test_execute_sandboxed_handles_failure(self) -> None:
        """execute_sandboxed returns error dict on connection failure."""
        adapter = FirecrackerAdapter(socket_path="/nonexistent.socket")

        result = adapter.execute_sandboxed(["echo", "hello"])
        assert result["exit_code"] == 1
        assert "error" in result

    def test_snapshot_returns_none(self) -> None:
        """snapshot returns None."""
        adapter = FirecrackerAdapter()
        assert adapter.snapshot() is None

    def test_rollback_does_not_raise(self) -> None:
        """rollback does not raise."""
        adapter = FirecrackerAdapter()
        adapter.rollback(None)  # Should not raise

    def test_get_audit_log_returns_empty_list(self) -> None:
        """get_audit_log returns empty list."""
        adapter = FirecrackerAdapter()
        assert adapter.get_audit_log() == []


# ---------------------------------------------------------------------------
# Probe tests
# ---------------------------------------------------------------------------


class TestProbes:
    """Test probe functions for all adapters."""

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

    def test_probe_gvisor_returns_false_on_non_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_probe_gvisor returns False on non-Linux (sys.platform != 'linux')."""
        monkeypatch.setattr("cloneguard.enforcement.gvisor_adapter.sys.platform", "darwin")
        assert _probe_gvisor() is False

    def test_probe_gvisor_returns_false_when_runsc_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_gvisor returns False when runsc binary not found."""
        monkeypatch.setattr("cloneguard.enforcement.gvisor_adapter.sys.platform", "linux")
        monkeypatch.setattr(
            "cloneguard.enforcement.gvisor_adapter.shutil.which",
            lambda x: None,
        )
        assert _probe_gvisor() is False

    def test_probe_firecracker_returns_false_on_non_linux(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_firecracker returns False on non-Linux."""
        monkeypatch.setattr("cloneguard.enforcement.firecracker_adapter.sys.platform", "darwin")
        assert _probe_firecracker() is False

    def test_probe_firecracker_returns_false_when_kvm_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_firecracker returns False when /dev/kvm does not exist."""
        monkeypatch.setattr("cloneguard.enforcement.firecracker_adapter.sys.platform", "linux")
        monkeypatch.setattr(
            "cloneguard.enforcement.firecracker_adapter.os.path.exists",
            lambda x: False,
        )
        assert _probe_firecracker() is False

    def test_probe_firecracker_returns_false_when_binary_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_probe_firecracker returns False when firecracker binary not found."""
        monkeypatch.setattr("cloneguard.enforcement.firecracker_adapter.sys.platform", "linux")
        monkeypatch.setattr(
            "cloneguard.enforcement.firecracker_adapter.os.path.exists",
            lambda x: x == "/dev/kvm",
        )
        monkeypatch.setattr(
            "cloneguard.enforcement.firecracker_adapter.shutil.which",
            lambda x: None,
        )
        assert _probe_firecracker() is False


# ---------------------------------------------------------------------------
# Auto-selection tests (D-08 strength order)
# ---------------------------------------------------------------------------


class TestAutoSelection:
    """Test adapter auto-selection by strength order (D-08)."""

    def test_registry_strength_order(self) -> None:
        """Registry ordered: firecracker > gvisor > docker > wasm > landlock > seatbelt."""
        from cloneguard.enforcement.adapter import _ADAPTER_REGISTRY

        names = [name for name, _, _ in _ADAPTER_REGISTRY]
        assert names == ["firecracker", "gvisor", "docker", "wasm", "landlock", "seatbelt"]

    def test_auto_select_falls_through_to_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When all probes return False, get_sandbox_adapter returns NoopAdapter."""
        from cloneguard.enforcement import adapter as adapter_mod

        patched = [(name, lambda: False, path) for name, _, path in adapter_mod._ADAPTER_REGISTRY]
        monkeypatch.setattr(adapter_mod, "_ADAPTER_REGISTRY", patched)
        adapter = adapter_mod.get_sandbox_adapter("auto")
        assert adapter.name == "noop"

    def test_auto_select_picks_strongest_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Auto-selection picks the first probe that returns True."""
        from cloneguard.enforcement import adapter as adapter_mod

        def make_probe(target_name: str):
            def probe() -> bool:
                return target_name == "docker"

            return probe

        patched = [
            (name, make_probe(name), path) for name, _, path in adapter_mod._ADAPTER_REGISTRY
        ]
        monkeypatch.setattr(adapter_mod, "_ADAPTER_REGISTRY", patched)
        mock_adapter = MagicMock()
        mock_adapter.name = "docker"
        monkeypatch.setattr(adapter_mod, "_load_adapter", lambda n, p: mock_adapter)
        result = adapter_mod.get_sandbox_adapter("auto")
        assert result.name == "docker"

    def test_preferred_override(self) -> None:
        """Operator can request specific adapter via preferred parameter."""
        from cloneguard.enforcement.adapter import get_sandbox_adapter

        adapter = get_sandbox_adapter("noop")
        assert adapter.name == "noop"


# ---------------------------------------------------------------------------
# Sandbox exec dispatch tests
# ---------------------------------------------------------------------------


class TestSandboxExecDispatch:
    """Test sandbox_exec.py dispatch to adapter-specific execution models."""

    def test_external_exec_adapters_set(self) -> None:
        """_EXTERNAL_EXEC_ADAPTERS contains docker, gvisor, firecracker, wasm."""
        from cloneguard.enforcement.sandbox_exec import _EXTERNAL_EXEC_ADAPTERS

        assert _EXTERNAL_EXEC_ADAPTERS == frozenset({"docker", "gvisor", "firecracker", "wasm"})

    def test_self_restrict_adapters_set(self) -> None:
        """_SELF_RESTRICT_ADAPTERS contains landlock, seatbelt, noop, auto."""
        from cloneguard.enforcement.sandbox_exec import _SELF_RESTRICT_ADAPTERS

        assert _SELF_RESTRICT_ADAPTERS == frozenset({"landlock", "seatbelt", "noop", "auto"})
