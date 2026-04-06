"""Splunk HEC connector -- transforms AuditEvents to HEC JSON envelope format.

Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector

Token is ALWAYS read from an environment variable at send time (T-05-06).
Config files reference the env var NAME, never the token value itself.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from typing import Any

import requests

from cloneguard.audit.types import AuditEvent

logger = logging.getLogger(__name__)


class SplunkHECConnector:
    """Splunk HEC connector implementing SIEMConnector Protocol.

    Wraps AuditEvent in HEC JSON envelope and POSTs to /services/collector.
    Multiple events are concatenated without separator (Splunk HEC format).
    Token is read from env var at send time -- never stored in instance.
    """

    def __init__(
        self,
        endpoint: str,
        token_env: str,
        sourcetype: str = "cloneguard",
        source: str = "cloneguard:hooks",
        index: str = "security",
        verify_ssl: bool = True,
        batch_size: int = 10,
    ) -> None:
        self._endpoint = endpoint
        self._token_env = token_env
        self._sourcetype = sourcetype
        self._source = source
        self._index = index
        self._verify_ssl = verify_ssl
        self._batch_size = batch_size

    @property
    def name(self) -> str:
        """Connector name for audit and logging."""
        return "splunk_hec"

    def transform(self, event: AuditEvent) -> dict[str, Any]:
        """Transform AuditEvent to HEC JSON envelope.

        HEC envelope format:
            {"time": epoch, "sourcetype": ..., "source": ..., "host": ..., "event": {...}}
        """
        return {
            "time": int(event.timestamp.timestamp()),
            "sourcetype": self._sourcetype,
            "source": self._source,
            "index": self._index,
            "host": socket.gethostname(),
            "event": json.loads(event.model_dump_json(exclude_none=True)),
        }

    def send(self, events: list[AuditEvent]) -> bool:
        """Batch-send events to Splunk HEC endpoint.

        POSTs concatenated JSON objects (NO array wrapper, NO separator --
        Splunk HEC format) with Authorization: Splunk {token} header.
        Returns False on any error. NEVER raises.
        """
        token = os.environ.get(self._token_env, "")
        if not token:
            logger.warning("Splunk HEC token env var %s not set", self._token_env)
            return False

        try:
            session = requests.Session()
            # Concatenate transformed events (Splunk HEC format: no separator)
            payload = "".join(
                json.dumps(self.transform(event)) for event in events
            )

            response = session.post(
                self._endpoint,
                data=payload,
                headers={
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json",
                },
                verify=self._verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception:
            logger.debug("Splunk HEC send failed", exc_info=True)
            return False
