"""SARIF 2.1.0 emitter using sarif-pydantic (D-08, D-09, D-10).

Converts CloneGuard scan results to SARIF 2.1.0 format for consumption by
GitHub Advanced Security, VS Code, and SonarQube. Uses sarif-pydantic for
schema-correct serialization instead of manual JSON construction.

Verdict-to-level mapping (D-09):
    DETECTED + CRITICAL/HIGH -> Level.ERROR
    DETECTED + MEDIUM        -> Level.WARNING
    DETECTED + LOW           -> Level.NOTE
    SUSPICIOUS               -> Level.WARNING
    CLEAN                    -> Not emitted

Threat mitigations:
    T-03-02: Results contain file paths and matched pattern text, not full content.
    T-03-03: Results capped at _MAX_RESULTS (5,000) per GitHub limits.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sarif_pydantic import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    Sarif,
    Tool,
    ToolDriver,
)

from cloneguard import __version__

logger = logging.getLogger(__name__)

_MAX_RESULTS = 5000  # GitHub Advanced Security limit per run

_VERDICT_SEVERITY_TO_LEVEL: dict[str, Level] = {
    "detected_critical": Level.ERROR,
    "detected_high": Level.ERROR,
    "detected_medium": Level.WARNING,
    "detected_low": Level.NOTE,
    "suspicious": Level.WARNING,
}


def _compute_fingerprint(rule_id: str, file_path: str, matched_text: str) -> str:
    """SHA-256 fingerprint for deduplication across runs."""
    return hashlib.sha256(f"{rule_id}:{file_path}:{matched_text}".encode()).hexdigest()


def _build_rules_from_patterns(pattern_engine: Any) -> list[ReportingDescriptor]:
    """Convert all loaded pattern rules to SARIF reportingDescriptors.

    Enumerates the PatternEngine's compiled rules and creates a
    ReportingDescriptor for each unique rule ID.
    """
    seen: set[str] = set()
    descriptors: list[ReportingDescriptor] = []

    for rule in pattern_engine.rules:
        rule_id = rule.get("id", "")
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        descriptors.append(
            ReportingDescriptor(
                id=rule_id,
                short_description=Message(text=rule.get("description", rule_id)),
            )
        )

    return descriptors


def build_sarif(
    scan_results: list[dict[str, Any]],
    rules: list[ReportingDescriptor],
) -> Sarif:
    """Build a SARIF 2.1.0 document from scan results (D-08, D-09).

    Args:
        scan_results: List of dicts with keys: verdict, severity, rule_id,
            file_path, line_number, matched_text, message.
        rules: List of SARIF ReportingDescriptor rules (from _build_rules_from_patterns
            or manually constructed).

    Returns:
        A sarif-pydantic Sarif object ready for JSON serialization.
    """
    results: list[Result] = []
    truncated = False

    for sr in scan_results:
        verdict = sr.get("verdict", "clean")
        if verdict == "clean":
            continue

        if len(results) >= _MAX_RESULTS:
            truncated = True
            break

        severity = sr.get("severity", "")
        level_key = f"{verdict}_{severity}" if severity else verdict
        level = _VERDICT_SEVERITY_TO_LEVEL.get(level_key, Level.WARNING)

        rule_id = sr.get("rule_id", "SEMANTIC")
        file_path = sr.get("file_path", "")
        matched_text = sr.get("matched_text", "")

        results.append(
            Result(
                rule_id=rule_id,
                level=level,
                message=Message(text=sr.get("message", "Detection finding")),
                locations=[
                    Location(
                        physical_location=PhysicalLocation(
                            artifact_location=ArtifactLocation(uri=file_path),
                            region=Region(start_line=sr.get("line_number", 1)),
                        )
                    )
                ],
                partial_fingerprints={
                    "primaryLocationLineHash": _compute_fingerprint(
                        rule_id, file_path, matched_text
                    )
                },
            )
        )

    if truncated:
        logger.warning(
            "SARIF output truncated to %d results (GitHub Advanced Security limit)",
            _MAX_RESULTS,
        )

    return Sarif(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolDriver(
                        name="cloneguard",
                        version=__version__,
                        information_uri="https://github.com/prodnull/cloneguard",
                        rules=rules,
                    )
                ),
                results=results,
            )
        ],
    )


class SARIFEmitter:
    """High-level SARIF output for CLI integration.

    Wraps build_sarif() with pattern engine rule extraction and
    JSON serialization.
    """

    def __init__(self) -> None:
        self._rules: list[ReportingDescriptor] | None = None

    def _get_rules(self) -> list[ReportingDescriptor]:
        """Lazy-load rules from PatternEngine."""
        if self._rules is None:
            try:
                from cloneguard.detection.patterns import PatternEngine

                engine = PatternEngine()
                self._rules = _build_rules_from_patterns(engine)
            except Exception:
                logger.debug("Could not load PatternEngine for SARIF rules", exc_info=True)
                self._rules = []
        return self._rules

    def emit_json(
        self,
        scan_results: list[dict[str, Any]],
        rules: list[ReportingDescriptor] | None = None,
    ) -> str:
        """Convert scan results to SARIF JSON string.

        Args:
            scan_results: List of result dicts (verdict, severity, rule_id, etc.).
            rules: Optional explicit rules list. If None, loads from PatternEngine.

        Returns:
            SARIF 2.1.0 JSON string.
        """
        if rules is None:
            rules = self._get_rules()
        sarif = build_sarif(scan_results, rules)
        result: str = sarif.model_dump_json(by_alias=True, exclude_none=True, indent=2)
        return result
