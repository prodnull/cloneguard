"""DetectionEngine — orchestrates pattern, semantic, and sequence signals.

Centralizes detection logic previously scattered across hooks.py handlers.
Exposes handler-specific scan methods (scan_instructions_loaded, scan_pre_tool_use,
scan_post_tool_use) that replicate current hooks.py behavior exactly, plus a
generic scan() method for ToolCallEvent-based invocation.

Threat model T-01-02: all JSON parsing wrapped in try/except; malformed input
returns exit 0 (allow, not crash). Detection failures never block agents.
Threat model T-01-03: raw_data never logged verbatim; only content hashes used.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from cloneguard.detection.patterns import (
    PatternEngine,
    PatternMatch,
    ScanMode,
    Severity,
    Verdict,
)
from cloneguard.detection.types import DetectionResult, SignalResult, ToolCallEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Content heuristic markers for three-signal mode detection (locked -- CONTEXT.md)
# ---------------------------------------------------------------------------
_WORKFLOW_MARKER = re.compile(r"(?m)^(?:on:|jobs:)\s")
_AGENT_INSTRUCTION_MARKER = re.compile(r"(?m)^#\s*Instructions?\b")
_CI_CONFIG_MARKER = re.compile(r"(?m)^(?:stages:|pipeline:|image:)\s")

# Protected paths -- writes to these are always blocked (D3).
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


# ---------------------------------------------------------------------------
# Helper functions (moved from hooks.py)
# ---------------------------------------------------------------------------


def _content_hash(content: str) -> str:
    """SHA-256 hash of content for trust cache keying."""
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
            if target in normalized or normalized.endswith(target.rstrip("/")):
                return True
        else:
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


def _detect_mode_for_tier15(
    source_path: str,
    content: str,
    hook_default: ScanMode,
    engine: PatternEngine,
) -> ScanMode:
    """Determine Tier 1.5 ScanMode via three signals (path + hook layer + content markers).

    Signal precedence (highest wins; content markers can only upgrade, never downgrade):
    1. Hook-layer default (hook_default): the implicit mode for this hook context.
    2. Path-based detection: reuses PatternEngine._detect_mode() logic.
    3. Content marker heuristics: agent instruction markers upgrade toward STRICT.
    """
    path_mode = engine._detect_mode(source_path)

    if _AGENT_INSTRUCTION_MARKER.search(content):
        content_upgrade = ScanMode.STRICT
    else:
        content_upgrade = ScanMode.LENIENT

    _rank = {ScanMode.LENIENT: 0, ScanMode.STANDARD: 1, ScanMode.STRICT: 2}
    rank_to_mode = {0: ScanMode.LENIENT, 1: ScanMode.STANDARD, 2: ScanMode.STRICT}

    if path_mode == ScanMode.STANDARD:
        base_rank = max(_rank[hook_default], _rank[content_upgrade])
    else:
        base_rank = max(_rank[path_mode], _rank[content_upgrade])

    return rank_to_mode[base_rank]


def _classify_with_tier15(
    content: str,
    source: str,
    mode: ScanMode,
    classifier: Any,
) -> tuple[str | None, str]:
    """Run Tier 1.5 classification. Returns (verdict, reason) or (None, '')."""
    if classifier is None:
        return None, ""
    result = classifier.classify(content, mode=mode)
    if result.verdict != "SAFE":
        return result.verdict, f"Tier 1.5: {result.reason}"
    return None, ""


# ---------------------------------------------------------------------------
# DetectionEngine
# ---------------------------------------------------------------------------


class DetectionEngine:
    """Orchestrates all three detection signal types into a unified result.

    Signal types:
    - Pattern matching via PatternEngine (Tier 0)
    - Semantic classification via MiniSemanticClassifier (Tier 1.5, lazy-loaded)
    - Sequence monitoring via ToolCallMonitor (behavioral, lazy-loaded)

    Conforms to DetectionEngineProtocol (structural subtyping).
    """

    def __init__(self) -> None:
        self._pattern_engine: PatternEngine | None = None
        self._mini_classifier: Any = None
        self._mini_attempted: bool = False
        self._session_trust: dict[str, str] = {}
        self._registry_client: Any = None

    def _get_pattern_engine(self) -> PatternEngine:
        """Lazy-load PatternEngine singleton."""
        if self._pattern_engine is None:
            self._pattern_engine = PatternEngine()
        return self._pattern_engine

    def _get_mini_classifier(self) -> Any:
        """Lazy-load Tier 1.5 mini semantic classifier. Returns None if unavailable."""
        if self._mini_attempted:
            return self._mini_classifier
        self._mini_attempted = True
        try:
            from cloneguard.detection.semantic import MiniSemanticClassifier

            classifier = MiniSemanticClassifier()
            if classifier.available:
                self._mini_classifier = classifier
        except ImportError:
            pass
        return self._mini_classifier

    def _get_registry_client(self) -> Any:
        """Lazy-load PackageRegistryClient. Returns None if import fails."""
        if self._registry_client is not None:
            return self._registry_client
        try:
            from cloneguard.enforcement.registry import PackageRegistryClient

            self._registry_client = PackageRegistryClient()
        except ImportError:
            pass
        return self._registry_client

    def scan(self, event: ToolCallEvent) -> DetectionResult:
        """Generic scan: run pattern engine on content, optionally semantic.

        Returns a DetectionResult with verdict, confidence, signals, and exit_code.
        """
        engine = self._get_pattern_engine()
        content = event.content
        source_path = event.source_path

        if not content:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        # Determine scan mode
        if event.scan_mode_hint:
            try:
                mode = ScanMode(event.scan_mode_hint)
            except ValueError:
                mode = engine._detect_mode(source_path)
        else:
            mode = engine._detect_mode(source_path)

        # Tier 0: pattern scan
        result = engine.scan(content, source_path, mode=mode)
        signals: list[SignalResult] = []

        if result.verdict != Verdict.CLEAN:
            severity_str = ""
            rule_id = ""
            matched_text = ""
            line_number = 0
            confidence = 1.0

            if result.matches:
                top = result.matches[0]
                severity_str = top.severity.value
                rule_id = top.pattern_id
                matched_text = top.matched_text
                line_number = top.line_number

            signals.append(
                SignalResult(
                    signal_type="pattern",
                    verdict=result.verdict.value,
                    confidence=confidence,
                    details={
                        "match_count": len(result.matches),
                        "scan_time_ms": result.scan_time_ms,
                    },
                )
            )

            exit_code = 2 if result.verdict == Verdict.DETECTED else 0
            message = _format_matches(result.matches, source_path)

            return DetectionResult(
                verdict=result.verdict.value,
                confidence=confidence,
                signals=signals,
                exit_code=exit_code,
                message=message,
                severity=severity_str,
                primary_rule_id=rule_id,
                matched_text=matched_text,
                source_path=source_path,
                line_number=line_number,
            )

        # Tier 1.5: semantic classification (if available)
        tier15_mode = _detect_mode_for_tier15(source_path, content, ScanMode.STANDARD, engine)
        t15_verdict, t15_reason = _classify_with_tier15(
            content, source_path, tier15_mode, self._get_mini_classifier()
        )

        if t15_verdict is not None:
            signals.append(
                SignalResult(
                    signal_type="semantic",
                    verdict="detected" if t15_verdict == "MALICIOUS" else "suspicious",
                    confidence=0.8 if t15_verdict == "MALICIOUS" else 0.5,
                    details={"reason": t15_reason},
                )
            )
            exit_code = 2 if t15_verdict == "MALICIOUS" else 0
            return DetectionResult(
                verdict="detected" if t15_verdict == "MALICIOUS" else "suspicious",
                confidence=0.8 if t15_verdict == "MALICIOUS" else 0.5,
                signals=signals,
                exit_code=exit_code,
                message=t15_reason,
                source_path=source_path,
            )

        return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

    def scan_instructions_loaded(self, data: dict[str, Any]) -> DetectionResult:
        """Handle InstructionsLoaded hook -- replicates hooks.py detection logic.

        Scans each instruction file with STRICT mode.
        Blocks (exit 2) if any CRITICAL/HIGH detection.
        Warns (exit 0 + message) if MEDIUM/LOW detection.
        Trusts (exit 0) if clean or already approved.
        """
        instructions = data.get("instructions", [])
        if not instructions:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        engine = self._get_pattern_engine()
        blocked_reasons: list[str] = []
        warnings: list[str] = []
        all_signals: list[SignalResult] = []

        for instr in instructions:
            content = instr.get("content", "")
            path = instr.get("path", instr.get("source", "<unknown>"))

            if not content:
                continue

            content_sha = _content_hash(content)

            if self._session_trust.get(path) == content_sha:
                continue

            result = engine.scan(content, path, mode=ScanMode.STRICT)

            if result.verdict == Verdict.DETECTED:
                reason = f"BLOCKED: Malicious patterns detected in {path}\n" + _format_matches(
                    result.matches, path
                )
                blocked_reasons.append(reason)
                all_signals.append(
                    SignalResult(
                        signal_type="pattern",
                        verdict="detected",
                        confidence=1.0,
                        details={"path": path, "match_count": len(result.matches)},
                    )
                )
            elif result.verdict == Verdict.SUSPICIOUS:
                warning = f"WARNING: Suspicious patterns detected in {path}\n" + _format_matches(
                    result.matches, path
                )
                warnings.append(warning)
                self._session_trust[path] = content_sha
                all_signals.append(
                    SignalResult(
                        signal_type="pattern",
                        verdict="suspicious",
                        confidence=0.5,
                        details={"path": path},
                    )
                )
            else:
                # Tier 0 clean -- run Tier 1.5 semantic check
                mode = _detect_mode_for_tier15(path, content, ScanMode.STRICT, engine)
                t15_verdict, t15_reason = _classify_with_tier15(
                    content, path, mode, self._get_mini_classifier()
                )
                if t15_verdict == "MALICIOUS":
                    blocked_reasons.append(
                        f"BLOCKED: Semantic classifier flagged {path} -- {t15_reason}"
                    )
                    all_signals.append(
                        SignalResult(
                            signal_type="semantic",
                            verdict="detected",
                            confidence=0.8,
                            details={"path": path, "reason": t15_reason},
                        )
                    )
                elif t15_verdict == "SUSPICIOUS":
                    warnings.append(f"WARNING: Semantic classifier flagged {path} -- {t15_reason}")
                    self._session_trust[path] = content_sha
                    all_signals.append(
                        SignalResult(
                            signal_type="semantic",
                            verdict="suspicious",
                            confidence=0.5,
                            details={"path": path, "reason": t15_reason},
                        )
                    )
                else:
                    self._session_trust[path] = content_sha

        if blocked_reasons:
            return DetectionResult(
                verdict="detected",
                confidence=1.0,
                signals=all_signals,
                exit_code=2,
                message="\n".join(blocked_reasons),
            )

        if warnings:
            return DetectionResult(
                verdict="suspicious",
                confidence=0.5,
                signals=all_signals,
                exit_code=0,
                message="\n".join(warnings),
            )

        return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

    def scan_pre_tool_use(self, data: dict[str, Any]) -> DetectionResult:
        """Handle PreToolUse hook -- replicates hooks.py detection logic.

        1. PROTECTION: Block writes to trust store and config paths (D3)
        2. CONTENT-AWARE WRITE SCANNING (D1): Scan content being written
        3. BUILD SCRIPT GATING: Warn on build commands
        """
        # Sequence enforcement check
        try:
            from cloneguard.detection.sequence import get_monitor

            verdict = get_monitor().check_enforcement(data)
            if verdict is not None:
                msg = (
                    f"BLOCKED by {verdict.rule_id}: {verdict.description}\n"
                    f"To allowlist: cloneguard sequence-allow {verdict.rule_id} <domain-or-path>"
                )
                return DetectionResult(
                    verdict="detected",
                    confidence=1.0,
                    exit_code=2,
                    message=msg,
                    signals=[
                        SignalResult(
                            signal_type="sequence",
                            verdict="detected",
                            confidence=1.0,
                            details={"rule_id": verdict.rule_id},
                        )
                    ],
                )
        except Exception:
            pass  # Monitor must never break the hook pipeline

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        engine = self._get_pattern_engine()
        signals: list[SignalResult] = []

        # --- 1. Protected path check for Write/Edit tools ---
        if tool_name in ("Write", "Edit", "NotebookEdit"):
            file_path = tool_input.get("file_path", "")
            if _is_protected_path(file_path):
                msg = f"BLOCKED: Write to protected path: {file_path}"
                return DetectionResult(
                    verdict="detected",
                    confidence=1.0,
                    exit_code=2,
                    message=msg,
                    source_path=file_path,
                )

            # --- 2. Content-aware write scanning ---
            content = tool_input.get("content", "")
            if not content and tool_name == "Edit":
                content = tool_input.get("new_text", "")

            if content and _is_sensitive_target(file_path):
                result = engine.scan(content, file_path)

                if result.verdict == Verdict.DETECTED:
                    reason = (
                        f"BLOCKED: Malicious content being written to {file_path}\n"
                        + _format_matches(result.matches, file_path)
                    )
                    return DetectionResult(
                        verdict="detected",
                        confidence=1.0,
                        exit_code=2,
                        message=reason,
                        source_path=file_path,
                        signals=[
                            SignalResult(
                                signal_type="pattern",
                                verdict="detected",
                                confidence=1.0,
                            )
                        ],
                    )
                elif result.verdict == Verdict.SUSPICIOUS:
                    warning = (
                        f"WARNING: Suspicious content being written to {file_path}\n"
                        + _format_matches(result.matches, file_path)
                    )
                    signals.append(
                        SignalResult(
                            signal_type="pattern",
                            verdict="suspicious",
                            confidence=0.5,
                        )
                    )
                    return DetectionResult(
                        verdict="suspicious",
                        confidence=0.5,
                        exit_code=0,
                        message=warning,
                        source_path=file_path,
                        signals=signals,
                    )
                else:
                    # Tier 0 clean -- Tier 1.5 semantic check on sensitive write content
                    mode = _detect_mode_for_tier15(file_path, content, ScanMode.STANDARD, engine)
                    t15_verdict, t15_reason = _classify_with_tier15(
                        content, file_path, mode, self._get_mini_classifier()
                    )
                    if t15_verdict == "MALICIOUS":
                        return DetectionResult(
                            verdict="detected",
                            confidence=0.8,
                            exit_code=2,
                            message=(
                                f"BLOCKED: Semantic classifier flagged write to"
                                f" {file_path} -- {t15_reason}"
                            ),
                            source_path=file_path,
                            signals=[
                                SignalResult(
                                    signal_type="semantic",
                                    verdict="detected",
                                    confidence=0.8,
                                )
                            ],
                        )
                    elif t15_verdict == "SUSPICIOUS":
                        return DetectionResult(
                            verdict="suspicious",
                            confidence=0.5,
                            exit_code=0,
                            message=(
                                f"WARNING: Semantic classifier flagged write to"
                                f" {file_path} -- {t15_reason}"
                            ),
                            source_path=file_path,
                            signals=[
                                SignalResult(
                                    signal_type="semantic",
                                    verdict="suspicious",
                                    confidence=0.5,
                                )
                            ],
                        )

        # --- 3. Block allowlist manipulation via Bash ---
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            blocked_commands = (
                "cloneguard allow",
                "cloneguard remove",
                "cloneguard --bypass",
                "claude --bypass",
            )
            for blocked in blocked_commands:
                if blocked in command:
                    return DetectionResult(
                        verdict="detected",
                        confidence=1.0,
                        exit_code=2,
                        message=(
                            f"BLOCKED: Dangerous CloneGuard command detected ({blocked!r}). "
                            "AI agents cannot modify the allowlist or bypass scanning."
                        ),
                    )

            # Scan bash command for injection patterns
            if command:
                cmd_result = engine.scan(command, "<bash_command>")
                if cmd_result.verdict == Verdict.DETECTED:
                    reason = "BLOCKED: Malicious patterns in Bash command\n" + _format_matches(
                        cmd_result.matches, "<bash_command>"
                    )
                    return DetectionResult(
                        verdict="detected",
                        confidence=1.0,
                        exit_code=2,
                        message=reason,
                        signals=[
                            SignalResult(
                                signal_type="pattern",
                                verdict="detected",
                                confidence=1.0,
                            )
                        ],
                    )

            # --- Package hallucination check (D-15, D-16, D-17) ---
            registry_client = self._get_registry_client()
            if registry_client is not None:
                try:
                    hallucination_signals = registry_client.check_packages_for_hallucination(
                        command
                    )
                    if hallucination_signals:
                        hallucinated = [
                            s.details.get("package", "?") for s in hallucination_signals
                        ]
                        msg = (
                            f"WARNING: Potentially hallucinated package(s) detected: "
                            f"{', '.join(hallucinated)}. These packages do not exist "
                            f"in their respective registries and may be slopsquatting "
                            f"targets."
                        )
                        return DetectionResult(
                            verdict="detected",
                            confidence=0.95,
                            exit_code=2,
                            message=msg,
                            signals=hallucination_signals,
                        )
                except Exception:
                    pass  # Registry check must never break the hook pipeline

            # Build command warnings
            for build_cmd in BUILD_COMMANDS:
                if build_cmd in command:
                    return DetectionResult(
                        verdict="clean",
                        confidence=1.0,
                        exit_code=0,
                        message=(
                            f"WARNING: Build command detected: {build_cmd!r} in {command!r}. "
                            "Verify the project is trusted before executing build scripts."
                        ),
                    )

        return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

    def scan_post_tool_use(self, data: dict[str, Any]) -> DetectionResult:
        """Handle PostToolUse hook -- replicates hooks.py detection logic.

        Scans tool output for injection patterns.
        CRITICAL -> exit 2 (block)
        HIGH/MEDIUM -> exit 0 + warning
        CLEAN -> exit 0, no output
        """
        # Record event in monitor
        try:
            from cloneguard.detection.sequence import get_monitor

            get_monitor().record_event(data)
        except Exception:
            pass  # Monitor must never break the hook pipeline

        tool_output = data.get("tool_output", {})
        if not tool_output:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        content = tool_output.get("content", "")
        if not content:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        tool_input = data.get("tool_input", {})
        source_path = tool_input.get("file_path", "<tool_output>")

        engine = self._get_pattern_engine()
        result = engine.scan(content, source_path)
        signals: list[SignalResult] = []

        if result.verdict == Verdict.DETECTED:
            max_sev = result.max_severity
            if max_sev == Severity.CRITICAL:
                reason = (
                    f"BLOCKED: Critical injection patterns in tool output from {source_path}\n"
                    + _format_matches(result.matches, source_path)
                )
                signals.append(
                    SignalResult(
                        signal_type="pattern",
                        verdict="detected",
                        confidence=1.0,
                        details={"severity": "critical"},
                    )
                )
                return DetectionResult(
                    verdict="detected",
                    confidence=1.0,
                    exit_code=2,
                    message=reason,
                    severity="critical",
                    source_path=source_path,
                    signals=signals,
                )
            else:
                warning = (
                    f"WARNING: Suspicious patterns in tool output from {source_path}\n"
                    + _format_matches(result.matches, source_path)
                )
                signals.append(
                    SignalResult(
                        signal_type="pattern",
                        verdict="detected",
                        confidence=0.8,
                        details={"severity": max_sev.value if max_sev else ""},
                    )
                )
                return DetectionResult(
                    verdict="detected",
                    confidence=0.8,
                    exit_code=0,
                    message=warning,
                    source_path=source_path,
                    signals=signals,
                )
        elif result.verdict == Verdict.SUSPICIOUS:
            warning = (
                f"WARNING: Low-confidence patterns in tool output from {source_path}\n"
                + _format_matches(result.matches, source_path)
            )
            signals.append(
                SignalResult(
                    signal_type="pattern",
                    verdict="suspicious",
                    confidence=0.5,
                )
            )
            return DetectionResult(
                verdict="suspicious",
                confidence=0.5,
                exit_code=0,
                message=warning,
                source_path=source_path,
                signals=signals,
            )

        # Tier 0 clean -- run Tier 1.5 semantic check on tool output
        mode = _detect_mode_for_tier15(source_path, content, ScanMode.STANDARD, engine)
        t15_verdict, t15_reason = _classify_with_tier15(
            content, source_path, mode, self._get_mini_classifier()
        )
        if t15_verdict == "MALICIOUS":
            return DetectionResult(
                verdict="suspicious",
                confidence=0.8,
                exit_code=0,
                message=(
                    f"WARNING: Semantic classifier flagged tool output from"
                    f" {source_path} -- {t15_reason}"
                ),
                source_path=source_path,
                signals=[
                    SignalResult(
                        signal_type="semantic",
                        verdict="detected",
                        confidence=0.8,
                    )
                ],
            )
        elif t15_verdict == "SUSPICIOUS":
            return DetectionResult(
                verdict="suspicious",
                confidence=0.5,
                exit_code=0,
                message=(
                    f"WARNING: Semantic classifier flagged tool output from"
                    f" {source_path} -- {t15_reason}"
                ),
                source_path=source_path,
                signals=[
                    SignalResult(
                        signal_type="semantic",
                        verdict="suspicious",
                        confidence=0.5,
                    )
                ],
            )

        return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_detection_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    """Return the module-level singleton DetectionEngine.

    Creates the engine on first call. Subsequent calls return the same instance.
    """
    global _detection_engine  # noqa: PLW0603
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine
