"""SIEM connector protocols and registry (D-03, D-04, GOVN-04).

Connectors transform NDJSON AuditEvents to SIEM-native formats and deliver
them asynchronously. Connectors NEVER block hook responses -- they consume
NDJSON from file/stderr output, not from the hook's synchronous path.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)


@runtime_checkable
class SIEMConnector(Protocol):
    """Protocol for SIEM connectors that transform and deliver AuditEvents."""

    @property
    def name(self) -> str: ...

    def transform(self, event: AuditEvent) -> dict[str, Any]:
        """Transform AuditEvent to SIEM-native format."""
        ...

    def send(self, events: list[AuditEvent]) -> bool:
        """Batch-send events to SIEM. Returns True on success, False on failure.

        Never raises.
        """
        ...


def get_connector(name: str, config: dict[str, Any] | None = None) -> SIEMConnector:
    """Factory for SIEM connectors.

    Supported names:
        - "splunk_hec" or "splunk" -> SplunkHECConnector
        - "sentinel_dcr" or "sentinel" -> SentinelConnector
        - "chronicle_udm" or "chronicle" -> ChronicleConnector

    Raises ValueError for unknown connector names.
    """
    cfg = config or {}

    if name in ("splunk_hec", "splunk"):
        from cloneguard.audit.connectors.splunk import SplunkHECConnector

        return SplunkHECConnector(
            endpoint=cfg.get("endpoint", ""),
            token_env=cfg.get("token_env", "CLONEGUARD_SPLUNK_HEC_TOKEN"),
            sourcetype=cfg.get("sourcetype", "cloneguard"),
            source=cfg.get("source", "cloneguard:hooks"),
            index=cfg.get("index", "security"),
            verify_ssl=cfg.get("verify_ssl", True),
            batch_size=cfg.get("batch_size", 10),
        )

    if name in ("sentinel_dcr", "sentinel"):
        from cloneguard.audit.connectors.sentinel import SentinelConnector

        return SentinelConnector(
            endpoint_env=cfg.get("endpoint_env", "CLONEGUARD_SENTINEL_ENDPOINT"),
            rule_id_env=cfg.get("rule_id_env", "CLONEGUARD_SENTINEL_RULE_ID"),
            stream_name=cfg.get("stream_name", "Custom-CloneGuard_CL"),
            batch_size=cfg.get("batch_size", 50),
        )

    if name in ("chronicle_udm", "chronicle"):
        from cloneguard.audit.connectors.chronicle import ChronicleConnector

        return ChronicleConnector(config=cfg)

    msg = f"Unknown SIEM connector: {name!r}"
    raise ValueError(msg)


def load_connector_config(config_path: Path) -> dict[str, Any]:
    """Load and validate SIEM connector config from a YAML file.

    Raises ValueError if the config file is missing the required 'connector' field.
    """
    import yaml

    text = config_path.read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "connector" not in data:
        msg = f"Config file {config_path} must contain a 'connector' field"
        raise ValueError(msg)
    return data


def from_config(config_path: Path) -> SIEMConnector:
    """Create a SIEM connector from a YAML config file.

    Reads the config, extracts the connector name, and instantiates via get_connector().
    """
    cfg = load_connector_config(config_path)
    connector_name = cfg.pop("connector")
    return get_connector(connector_name, cfg)


__all__ = ["SIEMConnector", "get_connector", "load_connector_config", "from_config"]
