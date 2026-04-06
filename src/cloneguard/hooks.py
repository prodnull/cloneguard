#!/usr/bin/env python3
"""CloneGuard hook handlers -- thin shim layer with multi-agent adapter support.

Provides in-process defense layers (1-3) running inside any supported agent process:
- Layer 1 (InstructionsLoaded): Scan instruction files for injection patterns
- Layer 2 (PostToolUse): Scan tool output for injection patterns
- Layer 3 (PreToolUse): Protect config paths, gate build commands, scan writes

Event normalization is delegated to the InputAdapter registry (D-04). The adapter
auto-detects the agent platform from JSON structure and normalizes into ToolCallEvent.
Handlers dispatch by event_type, not by platform-specific field names.

Each handler is a thin shim (~10 lines) that delegates to DetectionEngine for
all detection logic, then maps the result back to the hook protocol (exit 0/2).
Audit events are emitted via NDJSONEmitter AFTER the exit code is determined,
never on the critical path (Pitfall 6).

TOCTOU hardening: All content is scanned from the stdin JSON payload provided
by the agent's hook protocol. File content is NEVER re-read from disk.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from cloneguard.adapters import get_adapter
from cloneguard.detection.engine import (
    DetectionResult,
    get_detection_engine,
)
from cloneguard.detection.engine import (
    _detect_mode_for_tier15 as _engine_detect_mode_for_tier15,
)
from cloneguard.detection.patterns import PatternEngine, ScanMode
from cloneguard.monitor import get_monitor  # noqa: F401  # Re-export: 6 tests patch this name

# ---------------------------------------------------------------------------
# Content heuristic markers -- re-exported for backward compatibility
# ---------------------------------------------------------------------------
_WORKFLOW_MARKER = re.compile(r"(?m)^(?:on:|jobs:)\s")
_AGENT_INSTRUCTION_MARKER = re.compile(r"(?m)^#\s*Instructions?\b")
_CI_CONFIG_MARKER = re.compile(r"(?m)^(?:stages:|pipeline:|image:)\s")

# Singleton engine — loaded once per process lifetime.
# Kept at module level for backward compat (tests monkeypatch these).
_engine: PatternEngine | None = None
_mini_classifier: Any = None  # MiniSemanticClassifier (lazy-loaded)
_mini_attempted: bool = False


def _get_engine() -> PatternEngine:
    global _engine  # noqa: PLW0603
    if _engine is None:
        _engine = PatternEngine()
    return _engine


def _get_mini_classifier() -> Any:
    """Lazy-load Tier 1.5 mini semantic classifier. Returns None if unavailable."""
    global _mini_classifier, _mini_attempted  # noqa: PLW0603
    if _mini_attempted:
        return _mini_classifier
    _mini_attempted = True
    try:
        from cloneguard.mini_semantic import MiniSemanticClassifier

        classifier = MiniSemanticClassifier()
        if classifier.available:
            _mini_classifier = classifier
    except ImportError:
        pass
    return _mini_classifier


# In-memory session trust — reset each session (process lifetime).
_session_trust: dict[str, str] = {}  # path -> sha256 of approved content


def _detect_mode_for_tier15(
    source_path: str,
    content: str,
    hook_default: ScanMode,
    engine: PatternEngine | None = None,
) -> ScanMode:
    """Backward-compatible wrapper -- delegates to engine implementation.

    Tests call this with 3 args (no engine); internal callers pass 4 args.
    When engine is None, uses the hooks-level singleton via _get_engine().
    """
    return _engine_detect_mode_for_tier15(
        source_path, content, hook_default, engine or _get_engine()
    )


# ---------------------------------------------------------------------------
# Audit emission helper -- lazy-imports Pydantic (Pitfall 6: never on hot path)
# ---------------------------------------------------------------------------


def _emit_audit_event(
    data: dict[str, Any],
    result: DetectionResult,
    event_type_str: str,
    policy_decision: Any = None,  # PolicyDecision from enforcement
    agent_type: str = "claude-code",  # Agent platform that generated this event
) -> None:
    """Emit structured audit event. Lazy-imports Pydantic. Never raises (T-02-02).

    When policy_decision is provided, enforcement fields are derived from it:
    - action="block" -> enforcement_action="BLOCK"
    - action="constrain", dry_run=True -> enforcement_action="DRY_RUN", would_apply populated
    - action="constrain", dry_run=False -> "CONSTRAIN", constraints_applied set
    When policy_decision is None (backward compat), derives from exit code.
    agent_type is propagated to AuditEvent for observability (D-04).
    """
    try:
        import hashlib

        from cloneguard.audit.ndjson import NDJSONEmitter
        from cloneguard.audit.types import AuditEvent, EventType, SignalDetails

        # Map event type string
        event_map = {
            "InstructionsLoaded": EventType.HOOK_INVOKED,
            "PreToolUse": EventType.HOOK_INVOKED,
            "PostToolUse": EventType.HOOK_INVOKED,
        }
        et = event_map.get(event_type_str, EventType.HOOK_INVOKED)

        # Build tool input hash (T-02-03: never raw content)
        tool_input = data.get("tool_input", {})
        tool_input_str = json.dumps(tool_input, sort_keys=True)
        tool_input_hash = hashlib.sha256(tool_input_str.encode()).hexdigest()

        # Build signals from DetectionResult
        sig_data = SignalDetails(
            summary=result.message[:200] if result.message else "",
            primary_rule_id=result.primary_rule_id,
            line_number=result.line_number,
        )

        # Enforcement details (Phase 2)
        enforcement_action_str = "ALLOW"
        constraints_dict: dict[str, list[str]] = {}
        would_apply_dict: dict[str, list[str]] = {}
        adapter_name = "noop"

        if policy_decision is not None:
            if policy_decision.action == "block":
                enforcement_action_str = "BLOCK"
            elif policy_decision.action == "constrain":
                if policy_decision.dry_run:
                    enforcement_action_str = "DRY_RUN"
                    would_apply_dict = {
                        "filesystem_writable": list(
                            policy_decision.constraints.filesystem_writable
                        ),
                        "filesystem_readable": list(
                            policy_decision.constraints.filesystem_readable
                        ),
                        "network_allow": list(policy_decision.constraints.network_allow),
                    }
                else:
                    enforcement_action_str = "CONSTRAIN"
                    constraints_dict = {
                        "filesystem_writable": list(
                            policy_decision.constraints.filesystem_writable
                        ),
                        "filesystem_readable": list(
                            policy_decision.constraints.filesystem_readable
                        ),
                        "network_allow": list(policy_decision.constraints.network_allow),
                    }
        else:
            # Backward compat: no policy decision available, derive from exit code
            enforcement_action_str = "ALLOW" if result.exit_code == 0 else "BLOCK"

        from cloneguard import __version__

        event = AuditEvent(
            session_id=data.get("session_id", ""),
            event_type=et,
            tool_name=data.get("tool_name", event_type_str),
            tool_input_hash=tool_input_hash,
            verdict=result.verdict,
            confidence=result.confidence,
            signals=sig_data,
            enforcement_action=enforcement_action_str,
            constraints_applied=constraints_dict,
            would_apply=would_apply_dict,
            sandbox_adapter=adapter_name,
            cloneguard_version=__version__,
            source_path=result.source_path,
        )

        emitter = NDJSONEmitter.from_env()
        try:
            emitter.emit(event)
        finally:
            emitter.close()
    except Exception:
        pass  # Audit failure must never block agent (T-02-02)


# ---------------------------------------------------------------------------
# Engine bridge — shares hooks-level session trust with the engine singleton
# ---------------------------------------------------------------------------


def _get_bridged_engine() -> Any:
    """Get engine singleton with session trust bridged to hooks-level dict.

    Ensures the engine and hooks.py share the same _session_trust dict
    so tests that manipulate _session_trust at the hooks level see
    consistent state in the engine (T-04-01).
    """
    engine = get_detection_engine()
    engine._session_trust = _session_trust
    return engine


# ---------------------------------------------------------------------------
# Hook handlers -- thin shims delegating to DetectionEngine (D-02)
# ---------------------------------------------------------------------------


def handle_instructions_loaded(data: dict[str, Any]) -> int:
    """Handle InstructionsLoaded hook -- thin shim with enforcement (Phase 2).

    Scans each instruction file with STRICT mode.
    Blocks (exit 2) if any CRITICAL/HIGH detection.
    Warns (exit 0 + stdout) if MEDIUM/LOW detection.
    Trusts (exit 0, no output) if clean or already approved.
    Policy evaluation for audit trail completeness (no constraint spec -- no subprocess).
    """
    engine = _get_bridged_engine()
    result = engine.scan_instructions_loaded(data)

    # Phase 2: Policy evaluation for audit trail (no subprocess to sandbox)
    policy_decision = None
    try:
        from cloneguard.enforcement.policy import get_policy_engine

        policy_engine = get_policy_engine()
        policy_decision = policy_engine.evaluate(
            result,
            tool_name=data.get("tool_name", "InstructionsLoaded"),
        )
    except Exception:
        pass  # Enforcement failure must never break the hook pipeline

    if result.message:
        print(result.message)
    _emit_audit_event(data, result, "InstructionsLoaded", policy_decision)
    return result.exit_code


def handle_pre_tool_use(data: dict[str, Any]) -> int:
    """Handle PreToolUse hook -- thin shim with enforcement (Phase 2).

    Pipeline: DetectionEngine.scan() -> PolicyEngine.evaluate() -> enforcement
    Exit code unchanged: SAFE/SUSPICIOUS -> 0, MALICIOUS -> 2 (Pitfall 5)
    """
    engine = _get_bridged_engine()
    result = engine.scan_pre_tool_use(data)

    # Phase 2: Policy evaluation
    policy_decision = None
    try:
        from cloneguard.enforcement.policy import get_policy_engine

        policy_engine = get_policy_engine()
        policy_decision = policy_engine.evaluate(
            result,
            tool_name=data.get("tool_name", ""),
        )

        # Write constraint spec for sandbox-exec wrapper (only if not dry-run
        # and action is constrain). The spec file is consumed by
        # cloneguard-sandbox-exec which applies OS-level restrictions.
        if policy_decision.action == "constrain" and not policy_decision.dry_run:
            from cloneguard.enforcement.adapter import get_sandbox_adapter
            from cloneguard.enforcement.sandbox_exec import write_constraint_spec

            adapter = get_sandbox_adapter(preferred=policy_engine.sandbox_preferred)
            spec = {
                "adapter": adapter.name,
                "writable": list(policy_decision.constraints.filesystem_writable),
                "readable": list(policy_decision.constraints.filesystem_readable),
                "network_allow": list(policy_decision.constraints.network_allow),
            }
            spec_path = write_constraint_spec(spec)
            import os

            os.environ["CLONEGUARD_ENFORCE_SPEC"] = spec_path
    except Exception:
        pass  # Enforcement failure must never break the hook pipeline

    if result.message:
        print(result.message)
    if result.exit_code != 0 or result.verdict != "clean":
        _emit_audit_event(data, result, "PreToolUse", policy_decision)
    elif policy_decision is not None and policy_decision.action != "allow":
        # Emit audit event for enforcement actions even when detection is clean
        _emit_audit_event(data, result, "PreToolUse", policy_decision)
    return result.exit_code


def handle_post_tool_use(data: dict[str, Any]) -> int:
    """Handle PostToolUse hook -- thin shim with enforcement (Phase 2).

    Scans tool output for injection patterns.
    CRITICAL -> exit 2 (block/inject warning into context, D5)
    HIGH/MEDIUM -> exit 0 + stdout warning injected into context
    CLEAN -> exit 0, no output
    Policy evaluation for audit trail completeness (post-execution, no constraint spec).
    """
    engine = _get_bridged_engine()
    result = engine.scan_post_tool_use(data)

    # Phase 2: Policy evaluation for audit trail (post-execution, no constraint spec)
    policy_decision = None
    try:
        from cloneguard.enforcement.policy import get_policy_engine

        policy_engine = get_policy_engine()
        policy_decision = policy_engine.evaluate(
            result,
            tool_name=data.get("tool_name", ""),
        )
    except Exception:
        pass  # Enforcement failure must never break the hook pipeline

    if result.message:
        print(result.message)
    if result.exit_code != 0 or result.verdict != "clean":
        _emit_audit_event(data, result, "PostToolUse", policy_decision)
    return result.exit_code


def main() -> None:
    """Entry point for hook handler. Reads JSON from stdin, dispatches to handler.

    Auto-detects the agent platform from JSON structure via the adapter registry
    (D-04). For Claude Code, delegates to existing handler methods for backward
    compatibility. For other agents, normalizes via adapter.normalize() and uses
    the generic DetectionEngine.scan() path.
    """
    data = json.load(sys.stdin)

    # Auto-detect agent platform and get the appropriate adapter
    adapter = get_adapter("auto", raw_event=data)

    if adapter.agent_type == "claude-code":
        # Claude Code: use existing handler methods for full backward compatibility
        hook_type = data.get("hook_type", "")
        if hook_type == "InstructionsLoaded":
            exit_code = handle_instructions_loaded(data)
        elif hook_type == "PreToolUse":
            exit_code = handle_pre_tool_use(data)
        elif hook_type == "PostToolUse":
            exit_code = handle_post_tool_use(data)
        else:
            exit_code = 0
        sys.exit(exit_code)

    # Non-Claude agents: normalize via adapter, scan via generic engine path
    event = adapter.normalize(data)

    if event.event_type in ("InstructionsLoaded", "PreToolUse", "PostToolUse"):
        engine = _get_bridged_engine()
        result = engine.scan(event)

        # Policy evaluation for audit trail
        policy_decision = None
        try:
            from cloneguard.enforcement.policy import get_policy_engine

            policy_engine = get_policy_engine()
            policy_decision = policy_engine.evaluate(
                result,
                tool_name=event.tool_name,
            )
        except Exception:
            pass  # Enforcement failure must never break the hook pipeline

        if result.message:
            # Non-Claude agents use JSON stdout protocol; messages go to stderr
            print(result.message, file=sys.stderr)
        _emit_audit_event(
            data,
            result,
            event.event_type,
            policy_decision,
            agent_type=adapter.agent_type,
        )

        # Format response for the agent's protocol
        response = adapter.format_response(result, data)

        # For non-Claude agents, output JSON response to stdout
        if response.get("exit_code") is not None:
            sys.exit(response["exit_code"])
        else:
            # JSON response protocol (Gemini CLI, Cursor)
            print(json.dumps(response))
            sys.exit(0 if result.exit_code == 0 else 2)
    else:
        # Unknown event type -- pass through
        sys.exit(0)


if __name__ == "__main__":
    main()
