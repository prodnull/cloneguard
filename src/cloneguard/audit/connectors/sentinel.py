"""Microsoft Sentinel DCR connector -- transforms AuditEvents for Logs Ingestion API.

Reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview

Auth via DefaultAzureCredential (managed identity, CLI credential, or service principal).
Endpoint and rule ID are read from environment variables (T-05-07).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)

# Lazy imports for azure SDK -- optional dependency
try:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient
except ImportError:
    DefaultAzureCredential = None  # type: ignore[assignment,misc]
    LogsIngestionClient = None  # type: ignore[assignment,misc]


class SentinelConnector:
    """Microsoft Sentinel DCR connector implementing SIEMConnector Protocol.

    Transforms AuditEvents to DCR-compatible column names and uploads
    via the Logs Ingestion API using DefaultAzureCredential.
    """

    def __init__(
        self,
        endpoint_env: str,
        rule_id_env: str,
        stream_name: str = "Custom-CloneGuard_CL",
        batch_size: int = 50,
    ) -> None:
        self._endpoint_env = endpoint_env
        self._rule_id_env = rule_id_env
        self._stream_name = stream_name
        self._batch_size = batch_size

    @property
    def name(self) -> str:
        """Connector name for audit and logging."""
        return "sentinel_dcr"

    def transform(self, event: AuditEvent) -> dict[str, Any]:
        """Transform AuditEvent to DCR-compatible column format.

        Maps AuditEvent fields to Sentinel custom table column names.
        Uses TimeGenerated for timestamp (required by Sentinel).
        """
        return {
            "TimeGenerated": event.timestamp.isoformat(),
            "SchemaVersion": event.schema_version,
            "SessionId": event.session_id,
            "AgentType": event.agent_type,
            "AgentIdentity": event.agent_identity,
            "EventType": str(event.event_type),
            "ToolName": event.tool_name,
            "ToolInputHash": event.tool_input_hash,
            "Verdict": event.verdict,
            "Confidence": event.confidence,
            "EnforcementAction": event.enforcement_action,
            "SandboxAdapter": event.sandbox_adapter,
            "Outcome": event.outcome,
            "PolicyVersion": event.policy_version,
            "CloneGuardVersion": event.cloneguard_version,
            "SourcePath": event.source_path,
            "Tier0Matches": event.signals.tier0_matches,
            "Tier15Verdict": event.signals.tier15_verdict,
            "Tier15Confidence": event.signals.tier15_confidence,
        }

    def send(self, events: list[AuditEvent]) -> bool:
        """Upload events to Sentinel via Logs Ingestion API.

        Uses DefaultAzureCredential for authentication. Returns False
        on any error. NEVER raises.
        """
        endpoint = os.environ.get(self._endpoint_env, "")
        rule_id = os.environ.get(self._rule_id_env, "")

        if not endpoint or not rule_id:
            logger.warning(
                "Sentinel endpoint/rule_id env vars not set (%s, %s)",
                self._endpoint_env,
                self._rule_id_env,
            )
            return False

        try:
            credential = DefaultAzureCredential()
            client = LogsIngestionClient(endpoint=endpoint, credential=credential)
            logs = [self.transform(e) for e in events]
            client.upload(rule_id, self._stream_name, logs)
            return True
        except Exception:
            logger.debug("Sentinel DCR send failed", exc_info=True)
            return False
