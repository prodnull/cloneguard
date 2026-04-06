"""Microsoft AGT ToolCallInterceptor plugin for CloneGuard (D-06).

Exposes CloneGuard as a semantic sensor within Microsoft AGT governance
pipelines. Wraps DetectionEngine.scan() and maps three-verdict results
to AGT-compatible decisions (DENY / CONSTRAIN / ALLOW).

Direct Python API -- does NOT use hook stdin/stdout protocol (D-08).
Optional dependency: agent-os-kernel (D-07). Module importable without it.

Threat model:
    T-03-06: Exhaustive verdict mapping. detected->DENY, suspicious->CONSTRAIN,
             clean->ALLOW. MALICIOUS must NEVER map to ALLOW.
    T-03-07: Audit events use tool_input_hash (SHA-256), never raw tool_input.
    T-03-11: All external calls wrapped in try/except. If AGT SDK or
             DetectionEngine fails, returns ALLOW (fail open, logged).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from cloneguard.detection.engine import get_detection_engine
from cloneguard.detection.types import ToolCallEvent

logger = logging.getLogger(__name__)

# Import guard: agent-os-kernel is optional (D-07)
try:
    from agent_os import PolicyEngine as AGTPolicyEngine  # noqa: F401

    _AGT_AVAILABLE = True
except ImportError:
    _AGT_AVAILABLE = False


def _extract_content(tool_input: dict[str, Any]) -> str:
    """Join all string values from tool_input dict for scanning.

    Recursively extracts strings from nested dicts. Non-string values
    (int, bool, list) are skipped.
    """
    parts: list[str] = []
    for value in tool_input.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            nested = _extract_content(value)
            if nested:
                parts.append(nested)
    return " ".join(parts)


def _tool_input_hash(tool_input: dict[str, Any]) -> str:
    """SHA-256 hash of tool_input for audit trail (T-03-07)."""
    import json

    serialized = json.dumps(tool_input, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _verdict_to_decision(verdict: str, confidence: float, message: str) -> dict[str, Any]:
    """Map DetectionEngine verdict to AGT decision dict (T-03-06).

    Mapping:
        "detected" (MALICIOUS) -> DENY
        "suspicious"           -> CONSTRAIN
        "clean" (SAFE)         -> ALLOW
    """
    if verdict == "detected":
        return {
            "decision": "DENY",
            "reason": message,
            "confidence": confidence,
        }
    if verdict == "suspicious":
        return {
            "decision": "CONSTRAIN",
            "reason": message,
            "confidence": confidence,
        }
    return {
        "decision": "ALLOW",
        "reason": "",
        "confidence": confidence,
    }


class CloneGuardInterceptor:
    """CloneGuard semantic sensor for Microsoft AGT governance pipeline (D-06).

    Direct Python API -- does NOT use hook protocol (D-08).
    Wraps DetectionEngine.scan() and maps results to AGT-compatible decisions.

    Usage::

        interceptor = CloneGuardInterceptor()
        decision = interceptor.before_tool_call(
            agent_id="agent-1",
            tool_name="shell",
            tool_input={"command": "ls -la"},
        )
        # decision = {"decision": "ALLOW", "reason": "", "confidence": 1.0, ...}
    """

    @property
    def available(self) -> bool:
        """Whether the AGT SDK (agent-os-kernel) is installed."""
        return _AGT_AVAILABLE

    def before_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Scan tool call before execution and return AGT decision.

        Creates a ToolCallEvent, runs DetectionEngine.scan(), and maps the
        verdict to DENY/CONSTRAIN/ALLOW. On any internal error, returns
        ALLOW (fail open per T-03-11).
        """
        try:
            content = _extract_content(tool_input)

            event = ToolCallEvent(
                event_type="PreToolUse",
                tool_name=tool_name,
                tool_input=tool_input,
                content=content,
                session_id=agent_id,
                raw_data={"agent_id": agent_id, **kwargs},
            )

            result = get_detection_engine().scan(event)

            decision = _verdict_to_decision(result.verdict, result.confidence, result.message)
            decision["agent_type"] = "agt"
            decision["tool_input_hash"] = _tool_input_hash(tool_input)
            return decision

        except Exception:
            logger.exception("CloneGuard AGT interceptor error in before_tool_call")
            return {
                "decision": "ALLOW",
                "reason": "CloneGuard internal error (fail open)",
                "confidence": 0.0,
                "agent_type": "agt",
            }

    def after_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_output: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Scan tool output after execution and return AGT decision.

        Mirrors PostToolUse scanning: extracts text from tool_output,
        runs detection, maps verdict to DENY/CONSTRAIN/ALLOW.
        """
        try:
            content = _extract_content(tool_output)

            event = ToolCallEvent(
                event_type="PostToolUse",
                tool_name=tool_name,
                tool_input=tool_output,
                content=content,
                session_id=agent_id,
                raw_data={"agent_id": agent_id, **kwargs},
            )

            result = get_detection_engine().scan(event)

            decision = _verdict_to_decision(result.verdict, result.confidence, result.message)
            decision["agent_type"] = "agt"
            decision["tool_input_hash"] = _tool_input_hash(tool_output)
            return decision

        except Exception:
            logger.exception("CloneGuard AGT interceptor error in after_tool_call")
            return {
                "decision": "ALLOW",
                "reason": "CloneGuard internal error (fail open)",
                "confidence": 0.0,
                "agent_type": "agt",
            }
