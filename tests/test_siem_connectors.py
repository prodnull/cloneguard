"""Tests for SIEM connectors (GOVN-04).

Validates Splunk HEC, Microsoft Sentinel, and Chronicle UDM connectors
against mock endpoints. All connectors must satisfy SIEMConnector Protocol,
read credentials from env vars only, and handle failures gracefully.
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest

from cloneguard.audit.types import AuditEvent, EventType


def _make_audit_event(**overrides: object) -> AuditEvent:
    """Create a valid AuditEvent with known test values."""
    defaults: dict[str, object] = {
        "session_id": "test-session-001",
        "agent_type": "claude-code",
        "agent_identity": "spiffe://example.org/agent/test",
        "event_type": EventType.PRE_TOOL_USE,
        "tool_name": "Write",
        "tool_input_hash": "abc123def456",
        "verdict": "detected",
        "confidence": 0.95,
        "enforcement_action": "BLOCK",
        "cloneguard_version": "0.5.0",
        "source_path": "src/main.py",
        "timestamp": datetime.datetime(2026, 4, 6, 12, 0, 0, tzinfo=datetime.UTC),
    }
    defaults.update(overrides)
    return AuditEvent(**defaults)  # type: ignore[arg-type]


class TestSIEMConnectorProtocol:
    """Test that all connectors satisfy the runtime_checkable SIEMConnector Protocol."""

    def test_splunk_satisfies_protocol(self) -> None:
        """SplunkHECConnector satisfies SIEMConnector Protocol."""
        from cloneguard.audit.connectors import SIEMConnector
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
        )
        assert isinstance(connector, SIEMConnector)

    def test_sentinel_satisfies_protocol(self) -> None:
        """SentinelConnector satisfies SIEMConnector Protocol."""
        from cloneguard.audit.connectors import SIEMConnector
        from cloneguard.audit.connectors.sentinel import SentinelConnector

        connector = SentinelConnector(
            endpoint_env="TEST_SENTINEL_ENDPOINT",
            rule_id_env="TEST_SENTINEL_RULE_ID",
        )
        assert isinstance(connector, SIEMConnector)

    def test_chronicle_satisfies_protocol(self) -> None:
        """ChronicleConnector satisfies SIEMConnector Protocol."""
        from cloneguard.audit.connectors import SIEMConnector
        from cloneguard.audit.connectors.chronicle import ChronicleConnector

        connector = ChronicleConnector(config={})
        assert isinstance(connector, SIEMConnector)


class TestSplunkHECConnector:
    """Test Splunk HEC connector transform and send."""

    def test_transform_hec_envelope(self) -> None:
        """SplunkHECConnector.transform(event) returns dict with HEC envelope keys."""
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
        )
        event = _make_audit_event()
        result = connector.transform(event)

        assert "time" in result
        assert "sourcetype" in result
        assert "source" in result
        assert "host" in result
        assert "event" in result
        assert result["sourcetype"] == "cloneguard"
        assert result["source"] == "cloneguard:hooks"

    def test_transform_includes_all_event_fields(self) -> None:
        """SplunkHECConnector.transform(event)['event'] contains AuditEvent fields
        including agent_identity."""
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
        )
        event = _make_audit_event()
        result = connector.transform(event)

        inner = result["event"]
        assert inner["agent_identity"] == "spiffe://example.org/agent/test"
        assert inner["verdict"] == "detected"
        assert inner["confidence"] == 0.95
        assert inner["tool_name"] == "Write"

    def test_send_posts_with_hec_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SplunkHECConnector.send(events) POSTs to /services/collector
        with HEC token header."""
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        monkeypatch.setenv("TEST_SPLUNK_TOKEN", "test-token-123")

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
            verify_ssl=False,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        with patch("cloneguard.audit.connectors.splunk.requests") as mock_requests:
            mock_session = MagicMock()
            mock_session.post.return_value = mock_response
            mock_requests.Session.return_value = mock_session

            events = [_make_audit_event()]
            result = connector.send(events)

        assert result is True
        mock_session.post.assert_called_once()
        call_kwargs = mock_session.post.call_args
        assert "Splunk test-token-123" in str(call_kwargs)

    def test_token_from_env_not_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SplunkHECConnector reads token from env var, never from config value directly."""
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        monkeypatch.setenv("TEST_SPLUNK_TOKEN", "env-token-value")

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
        )

        # Verify the connector stores env var NAME, not the token value
        assert not hasattr(connector, "_token") or getattr(connector, "_token", None) is None
        assert connector._token_env == "TEST_SPLUNK_TOKEN"

    def test_send_failure_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SplunkHECConnector.send() returns False on failure, never raises."""
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        monkeypatch.setenv("TEST_SPLUNK_TOKEN", "test-token")

        connector = SplunkHECConnector(
            endpoint="https://splunk.example.com:8088/services/collector",
            token_env="TEST_SPLUNK_TOKEN",
        )

        with patch("cloneguard.audit.connectors.splunk.requests") as mock_requests:
            mock_session = MagicMock()
            mock_session.post.side_effect = ConnectionError("SIEM down")
            mock_requests.Session.return_value = mock_session

            result = connector.send([_make_audit_event()])

        assert result is False


class TestSentinelConnector:
    """Test Microsoft Sentinel DCR connector transform and send."""

    def test_transform_dcr_format(self) -> None:
        """SentinelConnector.transform(event) returns dict with DCR-compatible field names."""
        from cloneguard.audit.connectors.sentinel import SentinelConnector

        connector = SentinelConnector(
            endpoint_env="TEST_SENTINEL_ENDPOINT",
            rule_id_env="TEST_SENTINEL_RULE_ID",
        )
        event = _make_audit_event()
        result = connector.transform(event)

        assert "TimeGenerated" in result
        assert "Verdict" in result or "verdict" in result
        assert "AgentIdentity" in result or "agent_identity" in result

    def test_send_calls_upload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SentinelConnector.send(events) calls LogsIngestionClient.upload
        with correct stream name."""
        from cloneguard.audit.connectors.sentinel import SentinelConnector

        monkeypatch.setenv("TEST_SENTINEL_ENDPOINT", "https://sentinel.example.com")
        monkeypatch.setenv("TEST_SENTINEL_RULE_ID", "dcr-abc123")

        connector = SentinelConnector(
            endpoint_env="TEST_SENTINEL_ENDPOINT",
            rule_id_env="TEST_SENTINEL_RULE_ID",
            stream_name="Custom-CloneGuard_CL",
        )

        mock_client = MagicMock()
        mock_credential = MagicMock()

        with patch(
            "cloneguard.audit.connectors.sentinel.LogsIngestionClient",
            create=True,
        ) as mock_lic:
            mock_lic.return_value = mock_client
            with patch(
                "cloneguard.audit.connectors.sentinel.DefaultAzureCredential",
                create=True,
            ) as mock_dac:
                mock_dac.return_value = mock_credential
                result = connector.send([_make_audit_event()])

        assert result is True
        mock_client.upload.assert_called_once()
        call_args = mock_client.upload.call_args
        assert call_args[0][0] == "dcr-abc123"  # rule_id
        assert call_args[0][1] == "Custom-CloneGuard_CL"  # stream_name

    def test_send_failure_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SentinelConnector.send() returns False on failure, never raises."""
        from cloneguard.audit.connectors.sentinel import SentinelConnector

        monkeypatch.setenv("TEST_SENTINEL_ENDPOINT", "https://sentinel.example.com")
        monkeypatch.setenv("TEST_SENTINEL_RULE_ID", "dcr-abc123")

        connector = SentinelConnector(
            endpoint_env="TEST_SENTINEL_ENDPOINT",
            rule_id_env="TEST_SENTINEL_RULE_ID",
        )

        with patch(
            "cloneguard.audit.connectors.sentinel.DefaultAzureCredential",
            create=True,
            side_effect=RuntimeError("No Azure credential"),
        ):
            result = connector.send([_make_audit_event()])

        assert result is False


class TestChronicleConnector:
    """Test Chronicle UDM connector transform and send."""

    def test_transform_udm_structure(self) -> None:
        """ChronicleConnector.transform(event) returns dict with UDM event structure."""
        from cloneguard.audit.connectors.chronicle import ChronicleConnector

        connector = ChronicleConnector(config={})
        event = _make_audit_event()
        result = connector.transform(event)

        assert "metadata" in result
        assert "securityResult" in result or "security_result" in result

    def test_send_posts_udm_events(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ChronicleConnector.send(events) calls the UDM ingestion endpoint."""
        from cloneguard.audit.connectors.chronicle import ChronicleConnector

        monkeypatch.setenv("CLONEGUARD_CHRONICLE_CUSTOMER_ID", "cust-123")

        connector = ChronicleConnector(
            config={
                "customer_id_env": "CLONEGUARD_CHRONICLE_CUSTOMER_ID",
                "region": "us",
            }
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        with patch("cloneguard.audit.connectors.chronicle.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            result = connector.send([_make_audit_event()])

        assert result is True

    def test_send_failure_returns_false(self) -> None:
        """ChronicleConnector.send() returns False on failure, never raises."""
        from cloneguard.audit.connectors.chronicle import ChronicleConnector

        connector = ChronicleConnector(config={})

        with patch("cloneguard.audit.connectors.chronicle.requests") as mock_requests:
            mock_requests.post.side_effect = ConnectionError("Chronicle unreachable")
            result = connector.send([_make_audit_event()])

        assert result is False


class TestGetConnector:
    """Test connector factory function."""

    def test_get_splunk_connector(self) -> None:
        """get_connector('splunk_hec') returns SplunkHECConnector."""
        from cloneguard.audit.connectors import get_connector

        connector = get_connector(
            "splunk_hec",
            {
                "endpoint": "https://splunk.example.com:8088/services/collector",
                "token_env": "TEST_TOKEN",
            },
        )
        assert connector.name == "splunk_hec"

    def test_get_sentinel_connector(self) -> None:
        """get_connector('sentinel_dcr') returns SentinelConnector."""
        from cloneguard.audit.connectors import get_connector

        connector = get_connector(
            "sentinel_dcr",
            {"endpoint_env": "TEST_EP", "rule_id_env": "TEST_RULE"},
        )
        assert connector.name == "sentinel_dcr"

    def test_get_chronicle_connector(self) -> None:
        """get_connector('chronicle_udm') returns ChronicleConnector."""
        from cloneguard.audit.connectors import get_connector

        connector = get_connector("chronicle_udm", {})
        assert connector.name == "chronicle_udm"

    def test_unknown_connector_raises(self) -> None:
        """get_connector() raises ValueError for unknown connector name."""
        from cloneguard.audit.connectors import get_connector

        with pytest.raises(ValueError, match="Unknown"):
            get_connector("unknown_siem")

    def test_splunk_alias(self) -> None:
        """get_connector('splunk') works as alias for 'splunk_hec'."""
        from cloneguard.audit.connectors import get_connector

        connector = get_connector(
            "splunk",
            {
                "endpoint": "https://splunk.example.com:8088/services/collector",
                "token_env": "TEST_TOKEN",
            },
        )
        assert connector.name == "splunk_hec"
