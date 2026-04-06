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


def _pattern_confidence(matches: list[PatternMatch], verdict: Verdict) -> float:
    """Compute graduated pattern signal confidence from match severity and count.

    Maps severity to base confidence, then scales by match count (diminishing returns).
    This produces differentiated confidence that lets the fusion layer separate
    high-severity multi-match detections from low-severity single-match suspicions.

    Severity mapping:
      critical -> 1.0, high -> 0.85, medium -> 0.65, low -> 0.50
    Multi-match bonus: min(1.0, base + 0.05 * (count - 1))
    Verdict boost: "detected" adds 0.1 (clamped to 1.0)
    """
    if not matches:
        return 0.5  # Non-clean with no matches (shouldn't happen, defensive)

    severity_map = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.85,
        Severity.MEDIUM: 0.65,
        Severity.LOW: 0.50,
    }

    # Use the highest-severity match as base
    base = max(severity_map.get(m.severity, 0.5) for m in matches)

    # Multi-match bonus (diminishing returns)
    count_bonus = min(0.15, 0.05 * (len(matches) - 1))
    confidence = base + count_bonus

    # Verdict boost for "detected" (vs "suspicious")
    if verdict == Verdict.DETECTED:
        confidence += 0.1

    return min(1.0, confidence)


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
    - MELON selective re-execution (post-fusion, ambiguous zone only)

    Conforms to DetectionEngineProtocol (structural subtyping).
    """

    def __init__(self, agent_type: str = "default") -> None:
        self._pattern_engine: PatternEngine | None = None
        self._mini_classifier: Any = None
        self._mini_attempted: bool = False
        self._session_trust: dict[str, str] = {}
        self._registry_client: Any = None
        self._fusion_layer: Any = None
        self._melon_detector: Any = None
        self._agent_type = agent_type
        self._init_fusion()
        self._init_melon()

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

    def _init_fusion(self) -> None:
        """Initialize fusion layer with graceful degradation.

        If fusion module fails to import, engine falls back to old waterfall behavior.
        """
        try:
            from cloneguard.detection.fusion import FusionLayer, load_weight_profile

            profile = load_weight_profile(agent_type=self._agent_type)
            self._fusion_layer = FusionLayer(profile)
        except Exception:
            logger.debug("Fusion layer unavailable; falling back to waterfall behavior")
            self._fusion_layer = None

    def _init_melon(self) -> None:
        """Initialize MELON detector with graceful degradation.

        MELON fires post-fusion when confidence is in the ambiguous zone.
        If the module fails to import, MELON is simply unavailable.
        """
        try:
            from cloneguard.detection.melon import MELONDetector

            self._melon_detector = MELONDetector()
        except Exception:
            logger.debug("MELON detector unavailable")
            self._melon_detector = None

    def _collect_signals(
        self, content: str, source_path: str, mode: ScanMode
    ) -> list[SignalResult]:
        """Collect all three signal types without early return.

        Runs pattern scan, semantic classification, and sequence check in order,
        appending each non-clean signal to the list. Does NOT return on first
        non-clean signal -- all signals are always collected.
        """
        engine = self._get_pattern_engine()
        signals: list[SignalResult] = []

        # Tier 0: pattern scan (always runs)
        result = engine.scan(content, source_path, mode=mode)
        if result.verdict != Verdict.CLEAN:
            confidence = _pattern_confidence(result.matches, result.verdict)
            details: dict[str, Any] = {
                "match_count": len(result.matches),
                "scan_time_ms": result.scan_time_ms,
            }
            if result.matches:
                details["top_rule_id"] = result.matches[0].pattern_id
                details["top_severity"] = result.matches[0].severity.value
            signals.append(
                SignalResult(
                    signal_type="pattern",
                    verdict=result.verdict.value,
                    confidence=confidence,
                    details=details,
                )
            )

        # Tier 1.5: semantic classification (always runs, not only when pattern clean)
        tier15_mode = _detect_mode_for_tier15(source_path, content, mode, engine)
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

        # Sequence monitoring check (if available)
        try:
            from cloneguard.detection.sequence import get_monitor

            monitor = get_monitor()
            enforcement = monitor.check_enforcement(
                {"tool_name": "", "tool_input": {"content": content}}
            )
            if enforcement is not None:
                signals.append(
                    SignalResult(
                        signal_type="sequence",
                        verdict="detected",
                        confidence=1.0,
                        details={"rule_id": enforcement.rule_id},
                    )
                )
        except Exception:
            pass  # Sequence monitor must never break detection

        return signals

    def _fuse_signals_to_result(
        self,
        signals: list[SignalResult],
        content: str,
        source_path: str,
        mode: ScanMode,
    ) -> DetectionResult:
        """Fuse collected signals into a DetectionResult via FusionLayer + MELON.

        Encapsulates the fusion + MELON logic shared by scan() and all handler
        methods. When fusion is unavailable, falls back to waterfall aggregation
        from signals.

        Returns a DetectionResult with verdict, confidence, signals, and exit_code.
        """
        if self._fusion_layer is not None:
            from cloneguard.detection.fusion import FusionResult

            fusion_result: FusionResult = self._fusion_layer.fuse(signals, mode)

            # MELON post-fusion: selective re-execution for ambiguous zone
            melon_verdict = fusion_result.verdict
            melon_confidence = fusion_result.confidence
            if self._melon_detector is not None and self._melon_detector.should_trigger(
                fusion_result.confidence
            ):
                try:
                    suspicious_spans: list[tuple[int, int]] | None = None
                    for sig in signals:
                        if sig.signal_type == "pattern" and sig.details.get("top_rule_id"):
                            break

                    melon_result = self._melon_detector.detect(
                        content, self._get_mini_classifier(), suspicious_spans
                    )
                    if melon_result.verdict_upgraded:
                        melon_verdict = "detected"
                        melon_confidence = max(fusion_result.confidence, 0.7)
                        logger.info(
                            "MELON upgraded verdict: divergence=%.3f",
                            melon_result.divergence_score,
                        )
                except Exception:
                    logger.debug("MELON detection failed", exc_info=True)

            # Extract pattern match details for message formatting
            severity_str = ""
            rule_id = ""
            matched_text = ""
            line_number = 0
            message = ""

            engine = self._get_pattern_engine()
            pattern_result = engine.scan(content, source_path, mode=mode)
            if pattern_result.matches:
                top = pattern_result.matches[0]
                severity_str = top.severity.value
                rule_id = top.pattern_id
                matched_text = top.matched_text
                line_number = top.line_number
                message = _format_matches(pattern_result.matches, source_path)

            if not message:
                for sig in fusion_result.signals:
                    if sig.signal_type == "semantic" and sig.details.get("reason"):
                        message = sig.details["reason"]
                        break

            exit_code = 2 if melon_verdict == "detected" else 0

            return DetectionResult(
                verdict=melon_verdict,
                confidence=melon_confidence,
                signals=list(fusion_result.signals),
                exit_code=exit_code,
                message=message,
                severity=severity_str,
                primary_rule_id=rule_id,
                matched_text=matched_text,
                source_path=source_path,
                line_number=line_number,
            )

        # Fallback: aggregate from signals directly (fusion unavailable)
        if not signals:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        # Find worst signal
        worst_verdict = "clean"
        worst_confidence = 0.0
        worst_message = ""
        for sig in signals:
            if sig.verdict == "detected":
                worst_verdict = "detected"
                worst_confidence = max(worst_confidence, sig.confidence)
                if sig.details.get("reason"):
                    worst_message = sig.details["reason"]
            elif sig.verdict == "suspicious" and worst_verdict != "detected":
                worst_verdict = "suspicious"
                worst_confidence = max(worst_confidence, sig.confidence)
                if sig.details.get("reason"):
                    worst_message = sig.details["reason"]

        exit_code = 2 if worst_verdict == "detected" else 0
        return DetectionResult(
            verdict=worst_verdict,
            confidence=worst_confidence if worst_verdict != "clean" else 1.0,
            signals=signals,
            exit_code=exit_code,
            message=worst_message,
            source_path=source_path,
        )

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
        """Generic scan: collect all signals, fuse into calibrated result.

        Uses FusionLayer when available; falls back to waterfall behavior if
        the fusion module failed to load (graceful degradation).

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

        # Collect all signals (no early return)
        signals = self._collect_signals(content, source_path, mode)

        # Fuse signals via shared helper (fusion + MELON + fallback)
        fused = self._fuse_signals_to_result(signals, content, source_path, mode)
        if fused.verdict != "clean" or fused.exit_code != 0:
            return fused

        # If fusion returned clean but fusion layer was unavailable, try waterfall
        if self._fusion_layer is None:
            return self._scan_waterfall(content, source_path, mode, engine)

        return fused

    def _scan_waterfall(
        self,
        content: str,
        source_path: str,
        mode: ScanMode,
        engine: PatternEngine,
    ) -> DetectionResult:
        """Legacy waterfall scan path -- used when fusion module is unavailable.

        Preserves backward-compatible early-return behavior for graceful degradation.
        """
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
        """Handle InstructionsLoaded hook -- uses fusion for each instruction.

        Scans each instruction file with STRICT mode via _collect_signals + fusion.
        Blocks (exit 2) if any DETECTED result.
        Warns (exit 0 + message) if SUSPICIOUS result.
        Trusts (exit 0) if clean or already approved.
        """
        instructions = data.get("instructions", [])
        if not instructions:
            return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

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

            # Collect all signals and fuse
            signals = self._collect_signals(content, path, ScanMode.STRICT)
            fused = self._fuse_signals_to_result(signals, content, path, ScanMode.STRICT)

            # Severity hierarchy: MEDIUM/LOW pattern matches warn, not block.
            # Only CRITICAL/HIGH pattern severity can produce exit_code=2.
            # This preserves backward compat (hooks.py contract).
            severity_downgrade = False
            if fused.exit_code == 2 and fused.severity in ("medium", "low", ""):
                # Check if there's a CRITICAL/HIGH pattern signal
                has_critical_high = fused.severity in ("critical", "high")
                if not has_critical_high:
                    severity_downgrade = True

            if fused.exit_code == 2 and not severity_downgrade:
                msg = fused.message or f"Detection triggered in {path}"
                reason = f"BLOCKED: {msg}" if not msg.startswith("BLOCKED") else msg
                blocked_reasons.append(reason)
                all_signals.extend(fused.signals)
            elif fused.verdict == "suspicious" or severity_downgrade:
                msg = fused.message or f"Suspicious content in {path}"
                warning = f"WARNING: {msg}" if not msg.startswith("WARNING") else msg
                warnings.append(warning)
                self._session_trust[path] = content_sha
                all_signals.extend(fused.signals)
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

            # --- 2. Content-aware write scanning via fusion ---
            content = tool_input.get("content", "")
            if not content and tool_name == "Edit":
                content = tool_input.get("new_text", "")

            if content and _is_sensitive_target(file_path):
                mode = _detect_mode_for_tier15(file_path, content, ScanMode.STANDARD, engine)
                write_signals = self._collect_signals(content, file_path, mode)
                fused = self._fuse_signals_to_result(write_signals, content, file_path, mode)

                if fused.exit_code == 2:
                    return DetectionResult(
                        verdict=fused.verdict,
                        confidence=fused.confidence,
                        exit_code=2,
                        message=fused.message
                        or f"BLOCKED: Malicious content being written to {file_path}",
                        source_path=file_path,
                        signals=fused.signals,
                    )
                elif fused.verdict == "suspicious":
                    return DetectionResult(
                        verdict="suspicious",
                        confidence=fused.confidence,
                        exit_code=0,
                        message=fused.message
                        or f"WARNING: Suspicious content being written to {file_path}",
                        source_path=file_path,
                        signals=fused.signals,
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

        # Collect all signals and fuse
        signals = self._collect_signals(content, source_path, ScanMode.STANDARD)
        fused = self._fuse_signals_to_result(signals, content, source_path, ScanMode.STANDARD)

        if fused.verdict == "detected":
            # Check severity for CRITICAL -> exit 2, non-CRITICAL -> exit 0 WARNING
            pattern_result = engine.scan(content, source_path)
            max_sev = pattern_result.max_severity
            if max_sev == Severity.CRITICAL:
                reason = (
                    f"BLOCKED: Critical injection patterns in tool output from {source_path}\n"
                    + (fused.message or "")
                )
                return DetectionResult(
                    verdict="detected",
                    confidence=fused.confidence,
                    exit_code=2,
                    message=reason,
                    severity="critical",
                    source_path=source_path,
                    signals=fused.signals,
                )
            else:
                warning = f"WARNING: Suspicious patterns in tool output from {source_path}\n" + (
                    fused.message or ""
                )
                return DetectionResult(
                    verdict="detected",
                    confidence=fused.confidence,
                    exit_code=0,
                    message=warning,
                    source_path=source_path,
                    signals=fused.signals,
                )
        elif fused.verdict == "suspicious":
            warning = fused.message or (
                f"WARNING: Suspicious content in tool output from {source_path}"
            )
            return DetectionResult(
                verdict="suspicious",
                confidence=fused.confidence,
                exit_code=0,
                message=warning,
                source_path=source_path,
                signals=fused.signals,
            )

        return DetectionResult(verdict="clean", confidence=1.0, exit_code=0)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_detection_engine: DetectionEngine | None = None


def get_detection_engine(agent_type: str = "default") -> DetectionEngine:
    """Return the module-level singleton DetectionEngine.

    Creates the engine on first call with the given agent_type.
    Subsequent calls return the same instance (agent_type ignored after first call).
    """
    global _detection_engine  # noqa: PLW0603
    if _detection_engine is None:
        _detection_engine = DetectionEngine(agent_type=agent_type)
    return _detection_engine
