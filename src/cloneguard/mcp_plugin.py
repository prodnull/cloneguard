# mypy: ignore-errors
"""CloneGuard guardrail plugin for MCP Gateway.

Integrates CloneGuard's multi-tier detection engine into the MCP Gateway
plugin system. Scans tool inputs for prompt injection before forwarding,
and scans tool outputs for injection patterns before returning.

Detection tiers:
  - Tier 0: PatternEngine regex (191 patterns, <50ms)
  - Tier 1.5: MiniSemanticClassifier ONNX (~16ms/sample, optional)

Severity mapping:
  - CRITICAL/HIGH -> block (return None from process_request)
  - MEDIUM -> log warning, allow
  - LOW -> pass silently
"""

from __future__ import annotations

import logging
import time
from typing import Any

from cloneguard.patterns import PatternEngine, Severity, Verdict

logger = logging.getLogger(__name__)

# Guard mcp_gateway imports — the plugin file must be importable even when
# mcp-gateway is not installed (e.g., during unit tests or standalone use).
try:
    from mcp import types
    from mcp_gateway.plugins.base import GuardrailPlugin, PluginContext
    from mcp_gateway.plugins.manager import register_plugin

    _MCP_GATEWAY_AVAILABLE = True
except ImportError:
    _MCP_GATEWAY_AVAILABLE = False

    # Provide stub base class so the module can still be imported and tested.
    class GuardrailPlugin:  # type: ignore[no-redef]
        plugin_type = "guardrail"

        def load(self, config: dict[str, Any] | None = None) -> None: ...
        def process_request(self, context: Any) -> dict[str, Any] | None: ...
        def process_response(self, context: Any) -> Any: ...

    class PluginContext:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def register_plugin(cls: type) -> type:  # type: ignore[no-redef]
        return cls

    types = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Severity threshold — CRITICAL and HIGH trigger blocking
# ---------------------------------------------------------------------------
_BLOCK_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})


_MAX_EXTRACT_DEPTH = 10


def _extract_text_values(obj: Any, *, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a dict/list structure.

    Limits recursion to _MAX_EXTRACT_DEPTH levels to avoid pathological inputs.
    """
    if depth > _MAX_EXTRACT_DEPTH:
        logger.warning(
            "Extraction depth limit (%d) reached — deeply nested content will not be scanned. "
            "This could indicate a nesting-based evasion attempt.",
            _MAX_EXTRACT_DEPTH,
        )
        return []
    texts: list[str] = []
    if isinstance(obj, str):
        texts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            texts.extend(_extract_text_values(v, depth=depth + 1))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            texts.extend(_extract_text_values(item, depth=depth + 1))
    return texts


@register_plugin
class CloneGuardPlugin(GuardrailPlugin):
    """MCP Gateway guardrail that detects prompt injection via CloneGuard.

    Configuration keys (passed to ``load(config)``):
        enable_semantic (bool): Enable Tier 1.5 ONNX classifier. Default True.
    """

    plugin_name = "cloneguard"

    def __init__(self) -> None:
        self._pattern_engine: PatternEngine | None = None
        self._semantic: Any | None = None  # MiniSemanticClassifier, if available
        self._semantic_available: bool = False

    def load(self, config: dict[str, Any] | None = None) -> None:
        """Initialize detection engines.

        Always loads Tier 0 (PatternEngine). Optionally loads Tier 1.5
        (MiniSemanticClassifier) — degrades gracefully if ONNX/model missing.
        """
        config = config or {}

        # Tier 0: regex patterns — always available
        self._pattern_engine = PatternEngine()
        rule_count = len(self._pattern_engine.rules)
        logger.info("CloneGuard: Tier 0 loaded (%d patterns)", rule_count)

        # Tier 1.5: ONNX semantic classifier — optional
        if config.get("enable_semantic", True):
            try:
                from cloneguard.mini_semantic import MiniSemanticClassifier

                classifier = MiniSemanticClassifier()
                if classifier.available:
                    self._semantic = classifier
                    self._semantic_available = True
                    logger.info("CloneGuard: Tier 1.5 ONNX classifier loaded")
                else:
                    logger.info(
                        "CloneGuard: Tier 1.5 unavailable (model not found), running Tier 0 only"
                    )
            except Exception as exc:
                logger.warning(
                    "CloneGuard: Tier 1.5 init failed (%s), running Tier 0 only",
                    exc,
                )
        else:
            logger.info("CloneGuard: Tier 1.5 disabled by config")

    # ------------------------------------------------------------------
    # Request scanning
    # ------------------------------------------------------------------

    def process_request(self, context: PluginContext) -> dict[str, Any] | None:
        """Scan tool input arguments for prompt injection.

        Each extracted text value is scanned independently to prevent
        truncation-based evasion where benign text in early arguments pushes
        malicious content past the Tier 1.5 classifier's 256-token window.

        Returns:
            The original arguments dict if clean/low-risk, or None to block.
        """
        if not context.arguments or self._pattern_engine is None:
            return context.arguments

        texts = _extract_text_values(context.arguments)
        if not texts:
            return context.arguments

        source = f"{context.server_name}/{context.capability_name}"

        # --- Scan each text value independently ---
        total_regex_ms = 0.0
        total_onnx_ms = 0.0
        worst_regex_result = None
        worst_semantic: str | None = None
        total_matches = 0

        for text in texts:
            # Tier 0: regex scan (no token limit)
            t0 = time.perf_counter()
            result = self._pattern_engine.scan(text, source)
            total_regex_ms += (time.perf_counter() - t0) * 1000
            total_matches += len(result.matches)

            is_worse = worst_regex_result is None or (
                result.verdict.value > worst_regex_result.verdict.value
            )
            if is_worse:
                worst_regex_result = result

            # Tier 1.5: semantic scan per value (avoids truncation evasion)
            if self._semantic_available and self._semantic is not None:
                t1 = time.perf_counter()
                classification = self._semantic.classify(text)
                total_onnx_ms += (time.perf_counter() - t1) * 1000
                if worst_semantic is None or (
                    classification.verdict == "MALICIOUS"
                    or (classification.verdict == "SUSPICIOUS" and worst_semantic == "SAFE")
                ):
                    worst_semantic = classification.verdict

        assert worst_regex_result is not None  # texts is non-empty
        total_ms = total_regex_ms + total_onnx_ms

        # --- Decide verdict ---
        if worst_regex_result.verdict == Verdict.DETECTED or worst_semantic == "MALICIOUS":
            logger.warning(
                "CloneGuard: BLOCKED request %s — scanned in %.1fms "
                "(regex=%.1fms, onnx=%.1fms), verdict: BLOCKED, "
                "matches=%d, max_severity=%s, semantic=%s",
                source,
                total_ms,
                total_regex_ms,
                total_onnx_ms,
                total_matches,
                worst_regex_result.max_severity.value
                if worst_regex_result.max_severity
                else "none",
                worst_semantic or "n/a",
            )
            return None  # Block

        if worst_regex_result.verdict == Verdict.SUSPICIOUS:
            logger.warning(
                "CloneGuard: scanned request %s in %.1fms, verdict: SUSPICIOUS "
                "(allowed), matches=%d, max_severity=%s, semantic=%s",
                source,
                total_ms,
                total_regex_ms,
                total_matches,
                worst_regex_result.max_severity.value
                if worst_regex_result.max_severity
                else "none",
                worst_semantic or "n/a",
            )
            return context.arguments  # Warn but allow

        logger.debug(
            "CloneGuard: scanned request %s in %.1fms, verdict: CLEAN",
            source,
            total_ms,
        )
        return context.arguments

    # ------------------------------------------------------------------
    # Response scanning
    # ------------------------------------------------------------------

    def process_response(self, context: PluginContext) -> Any:
        """Scan tool response text for injection patterns.

        Does not block responses (would break tool output), but logs warnings
        for detected patterns so operators can investigate.
        """
        response = context.response
        if self._pattern_engine is None:
            return response

        # Only handle CallToolResult with text content
        if (
            types is not None
            and isinstance(response, types.CallToolResult)
            and hasattr(response, "content")
            and response.content
        ):
            return self._scan_call_tool_result(context, response)

        return response

    def _scan_call_tool_result(self, context: PluginContext, response: Any) -> Any:
        """Scan each TextContent item in a CallToolResult."""
        source = f"{context.server_name}/{context.capability_name}"

        for item in response.content:
            if not isinstance(item, types.TextContent):
                continue

            text = item.text
            if not text:
                continue

            # --- Tier 0 ---
            t0 = time.perf_counter()
            result = self._pattern_engine.scan(text, source)
            regex_ms = (time.perf_counter() - t0) * 1000

            # --- Tier 1.5 ---
            onnx_ms = 0.0
            semantic_verdict: str | None = None
            if self._semantic_available and self._semantic is not None:
                t1 = time.perf_counter()
                classification = self._semantic.classify(text)
                onnx_ms = (time.perf_counter() - t1) * 1000
                semantic_verdict = classification.verdict

            total_ms = regex_ms + onnx_ms

            if result.verdict != Verdict.CLEAN or semantic_verdict in (
                "MALICIOUS",
                "SUSPICIOUS",
            ):
                logger.warning(
                    "CloneGuard: response %s flagged — scanned in %.1fms "
                    "(regex=%.1fms, onnx=%.1fms), verdict: %s, "
                    "matches=%d, semantic=%s",
                    source,
                    total_ms,
                    regex_ms,
                    onnx_ms,
                    result.verdict.value,
                    len(result.matches),
                    semantic_verdict or "n/a",
                )
            else:
                logger.debug(
                    "CloneGuard: scanned response %s in %.1fms, verdict: CLEAN",
                    source,
                    total_ms,
                )

        # Return original response — we log but don't modify tool output
        return response
