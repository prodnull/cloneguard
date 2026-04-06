"""Tests for SPIFFE identity module (GOVN-06).

Validates graceful degradation: missing SPIFFE_ENDPOINT_SOCKET, unavailable
SPIRE agent, and successful identity fetch all produce correct AgentIdentity.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

import cloneguard.identity.spiffe as spiffe_mod
from cloneguard.identity.types import AgentIdentity


@pytest.fixture(autouse=True)
def _reset_cached_identity() -> None:
    """Reset module-level cached identity before each test."""
    spiffe_mod._cached_identity = None


class TestAgentIdentity:
    """Test AgentIdentity dataclass."""

    def test_default_identity_unavailable(self) -> None:
        """AgentIdentity with no SPIFFE has available=False and spiffe_id=''."""
        identity = AgentIdentity()
        assert identity.available is False
        assert identity.spiffe_id == ""
        assert identity.trust_domain == ""

    def test_identity_with_spiffe(self) -> None:
        """AgentIdentity can hold a SPIFFE URI."""
        identity = AgentIdentity(
            spiffe_id="spiffe://example.org/agent/claude-code-01",
            trust_domain="example.org",
            available=True,
        )
        assert identity.available is True
        assert identity.spiffe_id == "spiffe://example.org/agent/claude-code-01"
        assert identity.trust_domain == "example.org"

    def test_identity_is_frozen(self) -> None:
        """AgentIdentity is immutable."""
        identity = AgentIdentity()
        with pytest.raises(AttributeError):
            identity.spiffe_id = "changed"  # type: ignore[misc]


class TestGetAgentIdentity:
    """Test get_agent_identity() function."""

    def test_no_socket_returns_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_agent_identity() returns AgentIdentity(available=False) when
        SPIFFE_ENDPOINT_SOCKET not set."""
        monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
        identity = spiffe_mod.get_agent_identity()
        assert identity.available is False
        assert identity.spiffe_id == ""

    def test_spiffe_available_returns_identity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_agent_identity() returns AgentIdentity(available=True, spiffe_id='spiffe://...')
        when mock SPIFFE is available."""
        monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")

        mock_svid = MagicMock()
        mock_svid.spiffe_id = MagicMock()
        mock_svid.spiffe_id.__str__ = lambda self: "spiffe://example.org/agent/claude-code-01"
        mock_svid.spiffe_id.trust_domain = MagicMock()
        mock_svid.spiffe_id.trust_domain.__str__ = lambda self: "example.org"

        mock_client = MagicMock()
        mock_client.fetch_x509_svid.return_value = mock_svid
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch.dict("sys.modules", {"spiffe": MagicMock()}):
            with patch("cloneguard.identity.spiffe.WorkloadApiClient", create=True) as mock_cls:
                # Patch the import inside the function
                mock_wac = MagicMock()
                mock_wac.return_value = mock_client

                # We need to patch the actual import path
                import importlib

                # Create a mock spiffe module
                mock_spiffe_module = MagicMock()
                mock_spiffe_module.WorkloadApiClient = mock_wac

                with patch.dict("sys.modules", {"spiffe": mock_spiffe_module}):
                    # Force re-import
                    identity = spiffe_mod.get_agent_identity()

        assert identity.available is True
        assert identity.spiffe_id == "spiffe://example.org/agent/claude-code-01"
        assert identity.trust_domain == "example.org"

    def test_exception_returns_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_agent_identity() returns AgentIdentity(available=False) on any exception
        (never raises)."""
        monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")

        mock_spiffe_module = MagicMock()
        mock_spiffe_module.WorkloadApiClient.side_effect = RuntimeError("SPIRE agent not running")

        with patch.dict("sys.modules", {"spiffe": mock_spiffe_module}):
            identity = spiffe_mod.get_agent_identity()

        assert identity.available is False
        assert identity.spiffe_id == ""

    def test_caching_returns_same_identity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_agent_identity() caches result -- second call returns same object."""
        monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
        first = spiffe_mod.get_agent_identity()
        second = spiffe_mod.get_agent_identity()
        assert first is second

    def test_completes_within_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_agent_identity() completes within 2 seconds (timeout guard)."""
        monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)
        start = time.monotonic()
        spiffe_mod.get_agent_identity()
        elapsed = time.monotonic() - start
        assert elapsed < 2.0


class TestAuditEventAgentIdentity:
    """Test AuditEvent agent_identity field."""

    def test_audit_event_accepts_agent_identity(self) -> None:
        """AuditEvent accepts agent_identity string field."""
        from cloneguard.audit.types import AuditEvent, EventType

        event = AuditEvent(
            session_id="test-session",
            event_type=EventType.PRE_TOOL_USE,
            tool_name="Write",
            tool_input_hash="abc123",
            verdict="clean",
            cloneguard_version="0.5.0",
            agent_identity="spiffe://example.org/agent/claude-code-01",
        )
        assert event.agent_identity == "spiffe://example.org/agent/claude-code-01"

    def test_audit_event_ndjson_includes_agent_identity(self) -> None:
        """AuditEvent.to_ndjson() includes agent_identity in output when non-empty."""
        from cloneguard.audit.types import AuditEvent, EventType

        event = AuditEvent(
            session_id="test-session",
            event_type=EventType.PRE_TOOL_USE,
            tool_name="Write",
            tool_input_hash="abc123",
            verdict="clean",
            cloneguard_version="0.5.0",
            agent_identity="spiffe://example.org/agent/test",
        )
        ndjson = event.to_ndjson()
        parsed = json.loads(ndjson)
        assert parsed["agent_identity"] == "spiffe://example.org/agent/test"

    def test_audit_event_default_empty_identity(self) -> None:
        """AuditEvent defaults to empty agent_identity."""
        from cloneguard.audit.types import AuditEvent, EventType

        event = AuditEvent(
            session_id="test-session",
            event_type=EventType.PRE_TOOL_USE,
            tool_name="Write",
            tool_input_hash="abc123",
            verdict="clean",
            cloneguard_version="0.5.0",
        )
        assert event.agent_identity == ""
