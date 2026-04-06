"""CI/CD adapter normalizing GitHub Actions webhook events to ToolCallEvent (D-15).

Translates GitHub Actions pull_request webhook payloads into the normalized
ToolCallEvent dataclass for scanning. All CI scans are pre-merge (PreToolUse)
regardless of webhook action type.

The composite action (.github/actions/cloneguard-scan/action.yml) invokes the
CLI directly via ``cloneguard scan --sarif``. This adapter enables future
programmatic CI integrations (GitLab CI, Jenkins, etc.) and testing.

Threat model:
    T-03-16: Webhook payloads carry PR content which may contain injections.
             Content is the TARGET of scanning, not a bypass vector. Malformed
             webhooks produce empty ToolCallEvent (fail safe).
"""

from __future__ import annotations

from typing import Any

from cloneguard.adapters import register_adapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent


@register_adapter("cicd")
class CICDAdapter:
    """Normalize GitHub Actions webhook events into ToolCallEvent for scanning."""

    @property
    def agent_type(self) -> str:
        """Agent platform identifier."""
        return "cicd"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Convert a GitHub Actions webhook payload to a normalized ToolCallEvent.

        Extracts PR metadata and changed file patches. Returns safe defaults
        for empty or malformed payloads (T-03-16: fail safe, never crash).
        """
        pr: dict[str, Any] = raw_event.get("pull_request", {})
        action: str = raw_event.get("action", "")
        changed_files: list[dict[str, Any]] = raw_event.get("changed_files", [])

        # Concatenate all file patches/content
        patches: list[str] = []
        filenames: list[str] = []
        for f in changed_files:
            filename = f.get("filename", "")
            patch = f.get("patch", "") or f.get("content", "")
            if filename:
                filenames.append(filename)
            if patch:
                patches.append(patch)

        content = "\n".join(patches)
        if len(filenames) > 1:
            source_path = ", ".join(filenames)
        elif filenames:
            source_path = filenames[0]
        else:
            source_path = ""

        return ToolCallEvent(
            event_type="PreToolUse",
            tool_name="pr-scan",
            tool_input={"pr_number": pr.get("number", 0), "action": action},
            content=content,
            source_path=source_path,
            session_id=str(pr.get("number", "")),
        )

    def format_response(
        self, result: DetectionResult, raw_event: dict[str, Any]
    ) -> dict[str, Any]:
        """Format a DetectionResult into CI/CD-compatible response.

        Exit code 0 means clean (not blocked). Any non-zero exit code
        means blocked with a reason string.
        """
        if result.exit_code == 0:
            return {"blocked": False, "sarif_generated": True}
        return {
            "blocked": True,
            "reason": result.message,
            "sarif_generated": True,
        }
