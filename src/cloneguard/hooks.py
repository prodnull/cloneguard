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
import sys
from pathlib import Path
from typing import Any

from cloneguard.patterns import PatternEngine, PatternMatch, ScanMode, Severity, Verdict

# Singleton engine — loaded once per process lifetime.
_engine: PatternEngine | None = None


def _get_engine() -> PatternEngine:
    global _engine  # noqa: PLW0603
    if _engine is None:
        _engine = PatternEngine()
    return _engine


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
            # Trust it (user will see the warning in context)
            _session_trust[path] = content_sha
        else:
            # CLEAN — trust
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
        # Unknown hook type — pass through
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
