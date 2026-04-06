"""Tests for SandboxAdapter Protocol, NoopAdapter, and auto-selection.

Covers:
- SandboxAdapter is a runtime_checkable Protocol
- NoopAdapter satisfies isinstance check against SandboxAdapter
- NoopAdapter methods are all no-ops
- get_sandbox_adapter() auto-selection logic with platform fallbacks
"""

from __future__ import annotations

from unittest import mock

from cloneguard.enforcement.adapter import (
    NoopAdapter,
    SandboxAdapter,
    get_sandbox_adapter,
)


class TestSandboxAdapterProtocol:
    """SandboxAdapter Protocol structural subtyping checks."""

    def test_protocol_is_runtime_checkable(self) -> None:
        """SandboxAdapter must be decorated with @runtime_checkable."""
        assert hasattr(SandboxAdapter, "__protocol_attrs__") or isinstance(SandboxAdapter, type)
        # The real test: isinstance works at runtime
        noop = NoopAdapter()
        assert isinstance(noop, SandboxAdapter)

    def test_protocol_has_restrict_filesystem(self) -> None:
        assert hasattr(SandboxAdapter, "restrict_filesystem")

    def test_protocol_has_restrict_network(self) -> None:
        assert hasattr(SandboxAdapter, "restrict_network")

    def test_protocol_has_deferred_methods(self) -> None:
        """D-05: snapshot, rollback, restrict_syscalls, get_audit_log."""
        assert hasattr(SandboxAdapter, "snapshot")
        assert hasattr(SandboxAdapter, "rollback")
        assert hasattr(SandboxAdapter, "restrict_syscalls")
        assert hasattr(SandboxAdapter, "get_audit_log")


class TestNoopAdapter:
    """NoopAdapter implements all methods as no-ops."""

    def test_name_returns_noop(self) -> None:
        adapter = NoopAdapter()
        assert adapter.name == "noop"

    def test_restrict_filesystem_is_noop(self) -> None:
        adapter = NoopAdapter()
        result = adapter.restrict_filesystem(writable=["/tmp"], readable=["/home"])
        assert result is None

    def test_restrict_network_is_noop(self) -> None:
        adapter = NoopAdapter()
        result = adapter.restrict_network(allow=["example.com"])
        assert result is None

    def test_snapshot_returns_none(self) -> None:
        adapter = NoopAdapter()
        assert adapter.snapshot() is None

    def test_rollback_is_noop(self) -> None:
        adapter = NoopAdapter()
        result = adapter.rollback(snapshot=None)
        assert result is None

    def test_restrict_syscalls_is_noop(self) -> None:
        adapter = NoopAdapter()
        result = adapter.restrict_syscalls(allowed=["read", "write"])
        assert result is None

    def test_get_audit_log_returns_empty(self) -> None:
        adapter = NoopAdapter()
        assert adapter.get_audit_log() == []

    def test_satisfies_protocol(self) -> None:
        """NoopAdapter must pass isinstance check against SandboxAdapter."""
        adapter = NoopAdapter()
        assert isinstance(adapter, SandboxAdapter)


class TestGetSandboxAdapter:
    """Auto-selection logic for sandbox adapters."""

    def test_default_returns_noop_or_platform_adapter(self) -> None:
        """Default auto-selection returns an adapter that satisfies the protocol."""
        adapter = get_sandbox_adapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_preferred_noop_returns_noop(self) -> None:
        adapter = get_sandbox_adapter(preferred="noop")
        assert isinstance(adapter, NoopAdapter)
        assert adapter.name == "noop"

    def test_preferred_landlock_on_non_linux_returns_noop(self) -> None:
        """Landlock is Linux-only; on non-Linux, fallback to NoopAdapter."""
        with mock.patch("cloneguard.enforcement.adapter.sys") as mock_sys:
            mock_sys.platform = "darwin"
            adapter = get_sandbox_adapter(preferred="landlock")
            assert isinstance(adapter, NoopAdapter)

    def test_preferred_seatbelt_on_non_macos_returns_noop(self) -> None:
        """Seatbelt is macOS-only; on non-macOS, fallback to NoopAdapter."""
        with mock.patch("cloneguard.enforcement.adapter.sys") as mock_sys:
            mock_sys.platform = "linux"
            adapter = get_sandbox_adapter(preferred="seatbelt")
            assert isinstance(adapter, NoopAdapter)

    def test_unknown_adapter_returns_noop(self) -> None:
        """Unknown adapter name falls back to NoopAdapter."""
        adapter = get_sandbox_adapter(preferred="nonexistent")
        assert isinstance(adapter, NoopAdapter)

    def test_auto_returns_adapter_satisfying_protocol(self) -> None:
        """Auto mode returns an adapter satisfying SandboxAdapter protocol."""
        adapter = get_sandbox_adapter(preferred="auto")
        assert isinstance(adapter, SandboxAdapter)

    def test_probe_failure_returns_noop(self) -> None:
        """If all probes fail/raise, auto returns NoopAdapter."""
        with (
            mock.patch(
                "cloneguard.enforcement.adapter._probe_landlock", side_effect=Exception("fail")
            ),
            mock.patch(
                "cloneguard.enforcement.adapter._probe_seatbelt", side_effect=Exception("fail")
            ),
        ):
            adapter = get_sandbox_adapter(preferred="auto")
            assert isinstance(adapter, NoopAdapter)
