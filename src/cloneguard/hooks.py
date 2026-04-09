#!/usr/bin/env python3
"""CloneGuard hook handlers for Claude Code.

Provides in-process defense layers (1-3) running inside the Claude Code process:
- Layer 1 (InstructionsLoaded): Scan instruction files for injection patterns
- Layer 2 (PostToolUse): Scan tool output for injection patterns
- Layer 3 (PreToolUse): Protect config paths, gate build commands, scan writes

TOCTOU hardening: All content is scanned from the stdin JSON payload provided
by Claude Code's hook protocol. File content is NEVER re-read from disk. For
Write/Edit tools, the content is in tool_input. For Bash commands referencing
files, we scan the command string itself (the content is the command, not the
file). This binds the security decision to exactly what will be executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from cloneguard.monitor import get_monitor
from cloneguard.patterns import PatternEngine, PatternMatch, ScanMode, Severity, Verdict

# ---------------------------------------------------------------------------
# Content heuristic markers for three-signal mode detection (locked — CONTEXT.md)
# ---------------------------------------------------------------------------
# These lightweight regexes detect content type when path alone is ambiguous.
# Workflow/CI markers confirm STANDARD context (do not upgrade).
# Agent instruction markers upgrade toward STRICT.

_WORKFLOW_MARKER = re.compile(r"(?m)^(?:on:|jobs:)\s")
_AGENT_INSTRUCTION_MARKER = re.compile(r"(?m)^#\s*Instructions?\b")
_CI_CONFIG_MARKER = re.compile(r"(?m)^(?:stages:|pipeline:|image:)\s")

# Singleton engine — loaded once per process lifetime.
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


def _detect_mode_for_tier15(
    source_path: str,
    content: str,
    hook_default: ScanMode,
) -> ScanMode:
    """Determine Tier 1.5 ScanMode via three signals (path + hook layer + content markers).

    Signal precedence (highest wins; content markers can only upgrade, never downgrade):
    1. Hook-layer default (hook_default): the implicit mode for this hook context.
    2. Path-based detection: reuses PatternEngine._detect_mode() logic.
    3. Content marker heuristics: agent instruction markers upgrade toward STRICT.
       Workflow/CI markers do NOT upgrade mode — they confirm STANDARD context.

    Final mode = max(hook_default, path_mode, content_upgrade) where
    STRICT > STANDARD > LENIENT — ensuring markers only move mode upward.
    """
    # Signal 2: path-based detection via PatternEngine (primary signal)
    path_mode = _get_engine()._detect_mode(source_path)

    # Signal 3: content markers — only agent instruction marker upgrades to STRICT.
    # Workflow/CI markers confirm STANDARD context; they do not upgrade mode.
    # Content markers can only upgrade mode toward STRICT, never downgrade.
    if _AGENT_INSTRUCTION_MARKER.search(content):
        content_upgrade = ScanMode.STRICT
    else:
        content_upgrade = ScanMode.LENIENT  # no upgrade from content

    # Precedence: path is primary. hook_default applies when path says STANDARD
    # (i.e. no specific path signal). Content markers only upgrade, never downgrade.
    # STRICT > STANDARD > LENIENT ordinal for max() comparison.
    _rank = {ScanMode.LENIENT: 0, ScanMode.STANDARD: 1, ScanMode.STRICT: 2}
    rank_to_mode = {0: ScanMode.LENIENT, 1: ScanMode.STANDARD, 2: ScanMode.STRICT}

    # Path is authoritative for LENIENT (test files) and STRICT (agent configs).
    # hook_default overrides only when path returns STANDARD (no strong path signal).
    if path_mode == ScanMode.STANDARD:
        # No strong path signal — use hook_default as baseline, content can upgrade
        base_rank = max(_rank[hook_default], _rank[content_upgrade])
    else:
        # Path has a strong signal (STRICT or LENIENT) — path wins over hook_default.
        # Content markers can still upgrade from path_mode toward STRICT.
        base_rank = max(_rank[path_mode], _rank[content_upgrade])

    return rank_to_mode[base_rank]


def _classify_with_tier15(
    content: str,
    source: str,
    mode: ScanMode = ScanMode.STANDARD,
) -> tuple[str | None, str]:
    """Run Tier 1.5 classification on content. Returns (verdict, reason) or (None, '')."""
    classifier = _get_mini_classifier()
    if classifier is None:
        return None, ""
    result = classifier.classify(content, mode=mode)
    if result.verdict != "SAFE":
        return result.verdict, f"Tier 1.5: {result.reason}"
    return None, ""


# In-memory session trust — reset each session (process lifetime).
_session_trust: dict[str, str] = {}  # path -> sha256 of approved content

# Protected paths — writes to these are always blocked (D3).
PROTECTED_PATHS = [
    "~/.claude/trusted-instructions.json",
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
]

# Build commands to gate with warnings.
BUILD_COMMANDS = [
    "npm install",
    "npm ci",
    "npm run",
    "npx ",
    "yarn install",
    "yarn run",
    "pip install",
    "pip3 install",
    "cargo build",
    "cargo run",
    "make",
    "cmake",
    "go build",
    "go run",
    "bundle install",
    "gem install",
]

# Sensitive files where injected content is especially dangerous.
SENSITIVE_WRITE_TARGETS = [
    "package.json",
    "Makefile",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "Gemfile",
    "build.gradle",
    ".github/workflows/",
    ".gitlab-ci.yml",
    "Dockerfile",
    "docker-compose.yml",
    ".claude/",
    ".cursorrules",
    "CLAUDE.md",
    "GEMINI.md",
]


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _normalize_path(file_path: str) -> str:
    """Normalize a path for comparison: expand ~ and resolve."""
    expanded = os.path.expanduser(file_path)
    return str(Path(expanded).resolve())


def _is_protected_path(file_path: str) -> bool:
    """Check if file_path matches any protected path."""
    normalized = _normalize_path(file_path)
    for protected in PROTECTED_PATHS:
        protected_norm = _normalize_path(protected)
        if normalized == protected_norm or file_path == protected:
            return True
    return False


def _is_sensitive_target(file_path: str) -> bool:
    """Check if file_path is a sensitive write target."""
    normalized = file_path.replace("\\", "/")
    for target in SENSITIVE_WRITE_TARGETS:
        if target.endswith("/"):
            # Directory prefix match
            if target in normalized or normalized.endswith(target.rstrip("/")):
                return True
        else:
            # Basename or suffix match
            basename = normalized.rsplit("/", 1)[-1]
            if basename == target:
                return True
    return False


def _format_matches(matches: list[PatternMatch], source: str) -> str:
    """Format pattern matches into a human-readable warning string."""
    lines = []
    for m in matches:
        lines.append(
            f"  [{m.severity.value.upper()}] {m.pattern_id}: {m.description} "
            f"(line {m.line_number}, matched: {m.matched_text!r})"
        )
    header = f"CloneGuard detected suspicious patterns in {source}:"
    return header + "\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Audit event emission
# ---------------------------------------------------------------------------

# Lazy-loaded audit emitter and SPIFFE identity
_ndjson_emitter: Any = None
_ndjson_attempted: bool = False


def _get_emitter() -> Any:
    """Lazy-load NDJSONEmitter. Returns None if audit module unavailable."""
    global _ndjson_emitter, _ndjson_attempted  # noqa: PLW0603
    if _ndjson_attempted:
        return _ndjson_emitter
    _ndjson_attempted = True
    try:
        from cloneguard.audit.ndjson import NDJSONEmitter

        _ndjson_emitter = NDJSONEmitter.from_env()
    except Exception:
        pass
    return _ndjson_emitter


def _emit_audit_event(
    data: dict[str, Any],
    result: Any,
    event_type_str: str,
    policy_decision: Any = None,
    agent_type: str = "claude-code",
) -> None:
    """Emit an audit event for SIEM consumption. Never raises, never blocks.

    Constructs an AuditEvent from detection results and emits via NDJSONEmitter.
    SPIFFE agent identity is injected when available (GOVN-06).
    """
    emitter = _get_emitter()
    if emitter is None:
        return

    try:
        from cloneguard.audit.types import AuditEvent, EventType

        # SPIFFE agent identity (GOVN-06: zero-trust attribution)
        agent_identity_str = ""
        try:
            from cloneguard.identity import get_agent_identity

            identity = get_agent_identity()
            agent_identity_str = identity.spiffe_id
        except Exception:
            pass  # SPIFFE failure must never block agent

        # Map event type string to enum
        event_type_map = {
            "instructions_loaded": EventType.INSTRUCTIONS_LOADED,
            "pre_tool_use": EventType.PRE_TOOL_USE,
            "post_tool_use": EventType.POST_TOOL_USE,
            "scan": EventType.SCAN,
        }
        event_type = event_type_map.get(event_type_str, EventType.SCAN)

        event = AuditEvent(
            session_id=data.get("session_id", ""),
            agent_type=agent_type,
            agent_identity=agent_identity_str,
            event_type=event_type,
            tool_name=data.get("tool_name", ""),
            tool_input_hash=_content_hash(json.dumps(data.get("tool_input", {}), sort_keys=True)),
            verdict=getattr(result, "verdict", "clean") if result else "clean",
            confidence=getattr(result, "confidence", 0.0) if result else 0.0,
            cloneguard_version="0.6.0",
            source_path=data.get("tool_input", {}).get("file_path", ""),
        )
        emitter.emit(event)
    except Exception:
        pass  # Audit emission must never break the hook pipeline


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------


def handle_instructions_loaded(data: dict[str, Any]) -> int:
    """Handle InstructionsLoaded hook.

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
            # CRITICAL/HIGH — block
            reason = f"BLOCKED: Malicious patterns detected in {path}\n" + _format_matches(
                result.matches, path
            )
            blocked_reasons.append(reason)
        elif result.verdict == Verdict.SUSPICIOUS:
            # MEDIUM/LOW — warn but allow
            warning = f"WARNING: Suspicious patterns detected in {path}\n" + _format_matches(
                result.matches, path
            )
            warnings.append(warning)
            _session_trust[path] = content_sha
        else:
            # Tier 0 clean — run Tier 1.5 semantic check (STRICT minimum for InstructionsLoaded)
            mode = _detect_mode_for_tier15(path, content, ScanMode.STRICT)
            t15_verdict, t15_reason = _classify_with_tier15(content, path, mode=mode)
            if t15_verdict == "MALICIOUS":
                blocked_reasons.append(
                    f"BLOCKED: Semantic classifier flagged {path} — {t15_reason}"
                )
            elif t15_verdict == "SUSPICIOUS":
                warnings.append(f"WARNING: Semantic classifier flagged {path} — {t15_reason}")
                _session_trust[path] = content_sha
            else:
                _session_trust[path] = content_sha

    if blocked_reasons:
        print("\n".join(blocked_reasons))
        return 2

    if warnings:
        print("\n".join(warnings))

    return 0


def handle_pre_tool_use(data: dict[str, Any]) -> int:
    """Handle PreToolUse hook.

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
                return 2
            elif result.verdict == Verdict.SUSPICIOUS:
                warning = (
                    f"WARNING: Suspicious content being written to {file_path}\n"
                    + _format_matches(result.matches, file_path)
                )
                print(warning)
            else:
                # Tier 0 clean — Tier 1.5 semantic check on sensitive write content
                mode = _detect_mode_for_tier15(file_path, content, ScanMode.STANDARD)
                t15_verdict, t15_reason = _classify_with_tier15(content, file_path, mode=mode)
                if t15_verdict == "MALICIOUS":
                    print(
                        f"BLOCKED: Semantic classifier flagged write to {file_path} — {t15_reason}"
                    )
                    return 2
                elif t15_verdict == "SUSPICIOUS":
                    print(
                        f"WARNING: Semantic classifier flagged write to {file_path} — {t15_reason}"
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
        # The command from stdin JSON is exactly what will be executed.
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
    """Handle PostToolUse hook (wildcard matcher -- all tools, D2).

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
            return 2
        else:
            # HIGH — warn but allow
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

    # Tier 0 clean — run Tier 1.5 semantic check on tool output
    mode = _detect_mode_for_tier15(source_path, content, ScanMode.STANDARD)
    t15_verdict, t15_reason = _classify_with_tier15(content, source_path, mode=mode)
    if t15_verdict == "MALICIOUS":
        print(f"WARNING: Semantic classifier flagged tool output from {source_path} — {t15_reason}")
    elif t15_verdict == "SUSPICIOUS":
        print(f"WARNING: Semantic classifier flagged tool output from {source_path} — {t15_reason}")

    return 0


def _normalize_gemini_input(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize Gemini CLI hook format to Claude Code format.

    Gemini differences:
    - tool_response.llmContent instead of tool_output.content
    - hook_event_name instead of hook_type
    - Tool names: read_file/read_many_files/run_shell_command/edit_file/write_file
      vs Claude's Read/Bash/Edit/Write
    """
    # Normalize tool output: Gemini nests under tool_response.llmContent
    if "tool_response" in data and "tool_output" not in data:
        llm_content = data["tool_response"].get("llmContent", "")
        data["tool_output"] = {"content": llm_content}

    # Normalize tool names: Gemini -> Claude Code equivalents
    tool_name_map = {
        "read_file": "Read",
        "read_many_files": "Read",
        "run_shell_command": "Bash",
        "edit_file": "Edit",
        "write_file": "Write",
    }
    raw_name = data.get("tool_name", "")
    if raw_name in tool_name_map:
        data["tool_name"] = tool_name_map[raw_name]

    # Normalize Bash command field: Gemini uses tool_input.command (same as Claude)
    # No change needed — both use tool_input.command

    return data


def main() -> None:
    """Entry point for hook handler. Reads JSON from stdin, dispatches to handler."""
    data = json.load(sys.stdin)

    # Determine hook type: prefer --event CLI arg, fall back to JSON fields
    hook_type = ""
    for i, arg in enumerate(sys.argv):
        if arg == "--event" and i + 1 < len(sys.argv):
            hook_type = sys.argv[i + 1]
            break
    if not hook_type:
        hook_type = data.get("hook_type", "")
    if not hook_type:
        # Gemini sends hook_event_name (BeforeTool/AfterTool)
        gemini_event = data.get("hook_event_name", "")
        event_map = {"BeforeTool": "PreToolUse", "AfterTool": "PostToolUse"}
        hook_type = event_map.get(gemini_event, "")

    # Normalize Gemini input format if detected
    if data.get("hook_event_name"):
        data = _normalize_gemini_input(data)

    if hook_type == "InstructionsLoaded":
        exit_code = handle_instructions_loaded(data)
    elif hook_type == "PreToolUse":
        exit_code = handle_pre_tool_use(data)
    elif hook_type == "PostToolUse":
        exit_code = handle_post_tool_use(data)
    else:
        # Unknown hook type — pass through
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
