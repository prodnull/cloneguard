"""Chronicle (Google SecOps) UDM connector -- transforms AuditEvents to UDM event format.

Reference: https://cloud.google.com/chronicle/docs/reference/ingestion-api

Auth via GOOGLE_APPLICATION_CREDENTIALS (Application Default Credentials).
Uses requests for direct API calls. Falls back gracefully if secops library
is unavailable.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)


class ChronicleConnector:
    """Chronicle UDM connector implementing SIEMConnector Protocol.

    Transforms AuditEvents to UDM event structure with metadata,
    principal, target, and securityResult fields. Uses direct HTTP
    to Chronicle Ingestion API.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._customer_id_env = config.get("customer_id_env", "CLONEGUARD_CHRONICLE_CUSTOMER_ID")
        self._region = config.get("region", "us")
        self._log_type = config.get("log_type", "CLONEGUARD")
        self._batch_size = config.get("batch_size", 100)

    @property
    def name(self) -> str:
        """Connector name for audit and logging."""
        return "chronicle_udm"

    def _get_base_url(self) -> str:
        """Build Chronicle Ingestion API base URL for the configured region."""
        region = self._region
        if region == "us":
            return "https://malachiteingestion-pa.googleapis.com"
        if region == "eu":
            return "https://europe-malachiteingestion-pa.googleapis.com"
        return f"https://{region}-malachiteingestion-pa.googleapis.com"

    def transform(self, event: AuditEvent) -> dict[str, Any]:
        """Transform AuditEvent to UDM event structure.

        Maps to UDM fields: metadata (event type, timestamps),
        principal (agent identity), and securityResult (detection verdict).
        """
        return {
            "metadata": {
                "event_timestamp": event.timestamp.isoformat(),
                "event_type": "SCAN_UNCATEGORIZED",
                "product_name": "CloneGuard",
                "product_version": event.cloneguard_version,
                "vendor_name": "CloneGuard",
                "description": f"{event.event_type.value}: {event.verdict}",
                "log_type": self._log_type,
            },
            "principal": {
                "hostname": event.agent_type,
                "labels": [
                    {"key": "session_id", "value": event.session_id},
                    {"key": "agent_identity", "value": event.agent_identity},
                ],
            },
            "target": {
                "file": {
                    "full_path": event.source_path,
                    "sha256": event.tool_input_hash,
                },
            },
            "securityResult": [
                {
                    "action": "BLOCK" if event.enforcement_action == "BLOCK" else "ALLOW",
                    "severity": "HIGH" if event.verdict == "detected" else "LOW",
                    "confidence_details": {
                        "percentage": int(event.confidence * 100),
                    },
                    "detection_fields": [
                        {"key": "tool_name", "value": event.tool_name},
                        {"key": "sandbox_adapter", "value": event.sandbox_adapter},
                        {"key": "tier0_matches", "value": str(event.signals.tier0_matches)},
                    ],
                    "rule_name": event.signals.sequence_rule or "pattern_detection",
                    "summary": f"CloneGuard {event.verdict} (confidence: {event.confidence:.2f})",
                },
            ],
        }

    def send(self, events: list[AuditEvent]) -> bool:
        """Send events to Chronicle via UDM Ingestion API.

        Uses direct HTTP POST. Auth via google-auth Application Default
        Credentials if available. Returns False on any error. NEVER raises.
        """
        customer_id = os.environ.get(self._customer_id_env, "")

        try:
            base_url = self._get_base_url()
            url = f"{base_url}/v2/unstructuredlogentries:batchCreate"

            # Transform events to UDM format
            udm_events = [self.transform(e) for e in events]

            payload = {
                "customer_id": customer_id,
                "log_type": self._log_type,
                "entries": [{"log_text": str(udm_event)} for udm_event in udm_events],
            }

            # Attempt to get Google auth token
            headers: dict[str, str] = {"Content-Type": "application/json"}
            try:
                import google.auth
                import google.auth.transport.requests

                credentials, _ = google.auth.default()
                auth_req = google.auth.transport.requests.Request()
                credentials.refresh(auth_req)
                headers["Authorization"] = f"Bearer {credentials.token}"
            except Exception:
                logger.debug("Google auth unavailable, sending without auth")

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception:
            logger.debug("Chronicle UDM send failed", exc_info=True)
            return False
