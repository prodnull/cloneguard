#!/usr/bin/env python3
"""CloneGuard hook handlers for Claude Code -- thin shim layer (D-02).

Provides in-process defense layers (1-3) running inside the Claude Code process:
- Layer 1 (InstructionsLoaded): Scan instruction files for injection patterns
- Layer 2 (PostToolUse): Scan tool output for injection patterns
- Layer 3 (PreToolUse): Protect config paths, gate build commands, scan writes

Each handler is a thin shim (~10 lines) that delegates to DetectionEngine for
all detection logic, then maps the result back to the hook protocol (exit 0/2).
Audit events are emitted via NDJSONEmitter AFTER the exit code is determined,
never on the critical path (Pitfall 6).

TOCTOU hardening: All content is scanned from the stdin JSON payload provided
by Claude Code's hook protocol. File content is NEVER re-read from disk.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from cloneguard.detection.engine import (
    BUILD_COMMANDS,
    DetectionResult,
    _classify_with_tier15,
    _content_hash,
    _format_matches,
    _is_protected_path,
    _is_sensitive_target,
)
from cloneguard.detection.engine import (
    _detect_mode_for_tier15 as _engine_detect_mode_for_tier15,
)
from cloneguard.detection.patterns import PatternEngine, ScanMode, Severity, Verdict
from cloneguard.monitor import get_monitor

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
) -> None:
    """Emit structured audit event. Lazy-imports Pydantic. Never raises (T-02-02)."""
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

        from cloneguard import __version__

        event = AuditEvent(
            session_id=data.get("session_id", ""),
            event_type=et,
            tool_name=data.get("tool_name", event_type_str),
            tool_input_hash=tool_input_hash,
            verdict=result.verdict,
            confidence=result.confidence,
            signals=sig_data,
            enforcement_action="ALLOW" if result.exit_code == 0 else "BLOCK",
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
# Hook handlers -- thin shims delegating to DetectionEngine (D-02)
# ---------------------------------------------------------------------------


def handle_instructions_loaded(data: dict[str, Any]) -> int:
    """Handle InstructionsLoaded hook -- thin shim to DetectionEngine (D-02).

    Scans each instruction file with STRICT mode.
    Blocks (exit 2) if any CRITICAL/HIGH detection.
    Warns (exit 0 + stdout) if MEDIUM/LOW detection.
    Trusts (exit 0, no output) if clean or already approved.
    """
    instructions = data.get("instructions", [])
    if not instructions:
        return 0

    engine = _get_engine()
    blocked_reasons: list[str] = []
    warnings: list[str] = []

    for instr in instructions:
        content = instr.get("content", "")
        path = instr.get("path", instr.get("source", "<unknown>"))

        if not content:
            continue

        # TOCTOU mitigation: hash from stdin content, never re-read from disk
        content_sha = _content_hash(content)

        # Check session trust cache
        if _session_trust.get(path) == content_sha:
            continue  # Already approved with same hash

        # Scan with STRICT mode for instruction files
        result = engine.scan(content, path, mode=ScanMode.STRICT)

        if result.verdict == Verdict.DETECTED:
            # CRITICAL/HIGH -- block
            reason = f"BLOCKED: Malicious patterns detected in {path}\n" + _format_matches(
                result.matches, path
            )
            blocked_reasons.append(reason)
        elif result.verdict == Verdict.SUSPICIOUS:
            # MEDIUM/LOW -- warn but allow
            warning = f"WARNING: Suspicious patterns detected in {path}\n" + _format_matches(
                result.matches, path
            )
            warnings.append(warning)
            _session_trust[path] = content_sha
        else:
            # Tier 0 clean -- run Tier 1.5 semantic check (STRICT minimum)
            mode = _detect_mode_for_tier15(path, content, ScanMode.STRICT, engine)
            classifier = _get_mini_classifier()
            t15_verdict, t15_reason = _classify_with_tier15(
                content, path, mode, classifier
            )
            if t15_verdict == "MALICIOUS":
                blocked_reasons.append(
                    f"BLOCKED: Semantic classifier flagged {path} \u2014 {t15_reason}"
                )
            elif t15_verdict == "SUSPICIOUS":
                warnings.append(
                    f"WARNING: Semantic classifier flagged {path} \u2014 {t15_reason}"
                )
                _session_trust[path] = content_sha
            else:
                _session_trust[path] = content_sha

    if blocked_reasons:
        msg = "\n".join(blocked_reasons)
        print(msg)
        _emit_audit_event(
            data,
            DetectionResult(verdict="detected", confidence=1.0, exit_code=2, message=msg),
            "InstructionsLoaded",
        )
        return 2

    if warnings:
        msg = "\n".join(warnings)
        print(msg)
        _emit_audit_event(
            data,
            DetectionResult(verdict="suspicious", confidence=0.5, exit_code=0, message=msg),
            "InstructionsLoaded",
        )

    return 0


def handle_pre_tool_use(data: dict[str, Any]) -> int:
    """Handle PreToolUse hook -- thin shim to DetectionEngine (D-02).

    1. PROTECTION: Block writes to trust store and config paths (D3)
    2. CONTENT-AWARE WRITE SCANNING (D1): Scan content being written
    3. BUILD SCRIPT GATING: Warn on build commands
    """
    try:
        verdict = get_monitor().check_enforcement(data)
        if verdict is not None:
            msg = (
                f"BLOCKED by {verdict.rule_id}: {verdict.description}\n"
                f"To allowlist: cloneguard sequence-allow {verdict.rule_id} <domain-or-path>"
            )
            print(msg)
            _emit_audit_event(
                data,
                DetectionResult(verdict="detected", confidence=1.0, exit_code=2, message=msg),
                "PreToolUse",
            )
            return 2
    except Exception:
        pass  # Monitor must never break the hook pipeline

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # --- 1. Protected path check for Write/Edit tools ---
    if tool_name in ("Write", "Edit", "NotebookEdit"):
        file_path = tool_input.get("file_path", "")
        if _is_protected_path(file_path):
            msg = f"BLOCKED: Write to protected path: {file_path}"
            print(msg)
            _emit_audit_event(
                data,
                DetectionResult(
                    verdict="detected", confidence=1.0, exit_code=2,
                    message=msg, source_path=file_path,
                ),
                "PreToolUse",
            )
            return 2

        # --- 2. Content-aware write scanning ---
        content = tool_input.get("content", "")
        # For Edit, also check new_text
        if not content and tool_name == "Edit":
            content = tool_input.get("new_text", "")

        if content and _is_sensitive_target(file_path):
            engine = _get_engine()
            result = engine.scan(content, file_path)

            if result.verdict == Verdict.DETECTED:
                reason = (
                    f"BLOCKED: Malicious content being written to {file_path}\n"
                    + _format_matches(result.matches, file_path)
                )
                print(reason)
                _emit_audit_event(
                    data,
                    DetectionResult(
                        verdict="detected", confidence=1.0, exit_code=2,
                        message=reason, source_path=file_path,
                    ),
                    "PreToolUse",
                )
                return 2
            elif result.verdict == Verdict.SUSPICIOUS:
                warning = (
                    f"WARNING: Suspicious content being written to {file_path}\n"
                    + _format_matches(result.matches, file_path)
                )
                print(warning)
            else:
                # Tier 0 clean -- Tier 1.5 semantic check on sensitive write content
                mode = _detect_mode_for_tier15(file_path, content, ScanMode.STANDARD, engine)
                classifier = _get_mini_classifier()
                t15_verdict, t15_reason = _classify_with_tier15(
                    content, file_path, mode, classifier
                )
                if t15_verdict == "MALICIOUS":
                    print(
                        f"BLOCKED: Semantic classifier flagged write to"
                        f" {file_path} \u2014 {t15_reason}"
                    )
                    return 2
                elif t15_verdict == "SUSPICIOUS":
                    print(
                        f"WARNING: Semantic classifier flagged write to"
                        f" {file_path} \u2014 {t15_reason}"
                    )

    # --- 3. Block allowlist manipulation via Bash ---
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        # Block allowlist manipulation and bypass attempts
        blocked_commands = (
            "cloneguard allow",
            "cloneguard remove",
            "cloneguard --bypass",
            "claude --bypass",
        )
        for blocked in blocked_commands:
            if blocked in command:
                print(
                    f"BLOCKED: Dangerous CloneGuard command detected ({blocked!r}). "
                    "AI agents cannot modify the allowlist or bypass scanning."
                )
                return 2

        # TOCTOU: Scan the command string itself for injection patterns.
        if command:
            engine = _get_engine()
            cmd_result = engine.scan(command, "<bash_command>")
            if cmd_result.verdict == Verdict.DETECTED:
                reason = "BLOCKED: Malicious patterns in Bash command\n" + _format_matches(
                    cmd_result.matches, "<bash_command>"
                )
                print(reason)
                return 2

        for build_cmd in BUILD_COMMANDS:
            if build_cmd in command:
                msg = (
                    f"WARNING: Build command detected: {build_cmd!r} in {command!r}. "
                    f"Verify the project is trusted before executing build scripts."
                )
                print(msg)
                break  # One warning per command is enough

    return 0


def handle_post_tool_use(data: dict[str, Any]) -> int:
    """Handle PostToolUse hook -- thin shim to DetectionEngine (D-02).

    Scans tool output for injection patterns.
    CRITICAL -> exit 2 (block/inject warning into context, D5)
    HIGH/MEDIUM -> exit 0 + stdout warning injected into context
    CLEAN -> exit 0, no output
    """
    try:
        get_monitor().record_event(data)
    except Exception:
        pass  # Monitor must never break the hook pipeline

    tool_output = data.get("tool_output", {})
    if not tool_output:
        return 0

    content = tool_output.get("content", "")
    if not content:
        return 0

    # Use source path from tool_input if available for mode detection
    tool_input = data.get("tool_input", {})
    source_path = tool_input.get("file_path", "<tool_output>")

    engine = _get_engine()
    result = engine.scan(content, source_path)

    if result.verdict == Verdict.DETECTED:
        max_sev = result.max_severity
        if max_sev == Severity.CRITICAL:
            # D5: Block for critical detections
            reason = (
                f"BLOCKED: Critical injection patterns in tool output from {source_path}\n"
                + _format_matches(result.matches, source_path)
            )
            print(reason)
            _emit_audit_event(
                data,
                DetectionResult(
                    verdict="detected", confidence=1.0, exit_code=2,
                    message=reason, severity="critical", source_path=source_path,
                ),
                "PostToolUse",
            )
            return 2
        else:
            # HIGH -- warn but allow
            warning = (
                f"WARNING: Suspicious patterns in tool output from {source_path}\n"
                + _format_matches(result.matches, source_path)
            )
            print(warning)
            return 0
    elif result.verdict == Verdict.SUSPICIOUS:
        warning = (
            f"WARNING: Low-confidence patterns in tool output from {source_path}\n"
            + _format_matches(result.matches, source_path)
        )
        print(warning)
        return 0

    # Tier 0 clean -- run Tier 1.5 semantic check on tool output
    mode = _detect_mode_for_tier15(source_path, content, ScanMode.STANDARD, engine)
    classifier = _get_mini_classifier()
    t15_verdict, t15_reason = _classify_with_tier15(content, source_path, mode, classifier)
    if t15_verdict == "MALICIOUS":
        print(
            f"WARNING: Semantic classifier flagged tool output from"
            f" {source_path} \u2014 {t15_reason}"
        )
    elif t15_verdict == "SUSPICIOUS":
        print(
            f"WARNING: Semantic classifier flagged tool output from"
            f" {source_path} \u2014 {t15_reason}"
        )

    return 0


def main() -> None:
    """Entry point for hook handler. Reads JSON from stdin, dispatches to handler."""
    data = json.load(sys.stdin)
    hook_type = data.get("hook_type", "")

    if hook_type == "InstructionsLoaded":
        exit_code = handle_instructions_loaded(data)
    elif hook_type == "PreToolUse":
        exit_code = handle_pre_tool_use(data)
    elif hook_type == "PostToolUse":
        exit_code = handle_post_tool_use(data)
    else:
        # Unknown hook type -- pass through
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
