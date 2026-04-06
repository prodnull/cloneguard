"""Tier 1 Pattern Engine for CloneGuard.

Fast regex-based detection of prompt injection patterns in files
read by AI coding agents. Designed for <50ms scan time on typical files.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    DETECTED = "detected"


class ScanMode(Enum):
    STRICT = "strict"  # CLAUDE.md, .cursorrules, agent configs
    STANDARD = "standard"  # README, docs, source code
    LENIENT = "lenient"  # test fixtures, example data


@dataclass
class PatternMatch:
    pattern_id: str
    category: str
    severity: Severity
    description: str
    matched_text: str
    line_number: int


@dataclass
class ScanResult:
    verdict: Verdict
    matches: list[PatternMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0

    @property
    def max_severity(self) -> Severity | None:
        if not self.matches:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(m.severity == s for m in self.matches):
                return s
        return None


# Paths (basename or suffix) that trigger STRICT mode
_STRICT_BASENAMES = {
    "claude.md",
    ".cursorrules",
    "gemini.md",
    "agents.md",
    "guidelines.md",
    ".copilot-instructions.md",
    "copilot-instructions.md",
}

_STRICT_PATH_PATTERNS = [
    re.compile(r"(?i)\.claude/"),
    re.compile(r"(?i)\.github/copilot-instructions"),
]

# Path segments that trigger LENIENT mode
_LENIENT_SEGMENTS = re.compile(
    r"(?:^|/)(?:tests?|__tests__|fixtures?|test_fixtures?|testdata|__mocks__)/",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _CompiledRule:
    """A pre-compiled pattern rule for efficient scanning."""

    pattern_id: str
    category: str
    severity: Severity
    description: str
    compiled: re.Pattern[str]
    raw: dict[str, Any]
    modes: frozenset[ScanMode] | None = None  # None = all modes


class PatternEngine:
    """Fast regex-based pattern matching engine for prompt injection detection."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        """Load all YAML rule files from rules_dir."""
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"

        self._compiled_rules: list[_CompiledRule] = []
        self._raw_rules: list[dict[str, Any]] = []

        if not rules_dir.is_dir():
            return

        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            self._load_rule_file(yaml_file)

    def _load_rule_file(self, path: Path) -> None:
        """Load and compile patterns from a single YAML rule file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or "patterns" not in data:
            return

        category = data.get("category", path.stem)

        for pattern in data["patterns"]:
            severity = Severity(pattern["severity"])
            compiled = re.compile(pattern["regex"])
            modes: frozenset[ScanMode] | None = None
            if "modes" in pattern:
                modes = frozenset(ScanMode(m) for m in pattern["modes"])
            rule = _CompiledRule(
                pattern_id=pattern["id"],
                category=category,
                severity=severity,
                description=pattern["description"],
                compiled=compiled,
                raw={**pattern, "category": category},
                modes=modes,
            )
            self._compiled_rules.append(rule)
            self._raw_rules.append(rule.raw)

    @property
    def rules(self) -> list[dict[str, Any]]:
        """Return raw rule dicts for introspection and testing."""
        return self._raw_rules

    def scan(
        self,
        content: str,
        source_path: str,
        mode: ScanMode | None = None,
    ) -> ScanResult:
        """Scan content for injection patterns.

        If mode is None, auto-detect from source_path:
        - CLAUDE.md, .cursorrules, GEMINI.md, .claude/* -> STRICT
        - test/, tests/, fixtures/, __tests__/ -> LENIENT
        - everything else -> STANDARD
        """
        start = time.perf_counter()

        if mode is None:
            mode = self._detect_mode(source_path)

        if not content:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(verdict=Verdict.CLEAN, scan_time_ms=elapsed)

        # NFKC normalize to collapse homoglyphs and combining marks
        content = unicodedata.normalize("NFKC", content)

        # Build a line-start offset map for line number lookup
        line_offsets = self._build_line_offsets(content)

        matches: list[PatternMatch] = []

        for rule in self._compiled_rules:
            # Skip rules restricted to other scan modes
            if rule.modes is not None and mode not in rule.modes:
                continue
            for m in rule.compiled.finditer(content):
                line_num = self._offset_to_line(line_offsets, m.start())
                matched_text = m.group()
                # Truncate very long matches for readability
                if len(matched_text) > 200:
                    matched_text = matched_text[:200] + "..."
                matches.append(
                    PatternMatch(
                        pattern_id=rule.pattern_id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        matched_text=matched_text,
                        line_number=line_num,
                    )
                )

        # Apply mode-based filtering
        matches = self._apply_mode_filter(matches, mode)

        # Determine verdict
        verdict = self._determine_verdict(matches)

        elapsed = (time.perf_counter() - start) * 1000
        return ScanResult(verdict=verdict, matches=matches, scan_time_ms=elapsed)

    def _detect_mode(self, source_path: str) -> ScanMode:
        """Auto-detect scan mode from file path."""
        normalized = source_path.replace("\\", "/")
        basename = normalized.rsplit("/", 1)[-1].lower()

        # Check strict basenames
        if basename in _STRICT_BASENAMES:
            return ScanMode.STRICT

        # Check strict path patterns
        for pat in _STRICT_PATH_PATTERNS:
            if pat.search(normalized):
                return ScanMode.STRICT

        # Check lenient path segments
        if _LENIENT_SEGMENTS.search(normalized):
            return ScanMode.LENIENT

        return ScanMode.STANDARD

    def _apply_mode_filter(self, matches: list[PatternMatch], mode: ScanMode) -> list[PatternMatch]:
        """Filter/adjust matches based on scan mode.

        STRICT: all matches kept, severity unchanged
        STANDARD: all matches kept, severity unchanged
        LENIENT: only CRITICAL kept at original severity;
                 HIGH -> MEDIUM, MEDIUM -> LOW, LOW -> dropped
        """
        if mode in (ScanMode.STRICT, ScanMode.STANDARD):
            return matches

        # LENIENT mode
        filtered: list[PatternMatch] = []
        for m in matches:
            if m.severity == Severity.CRITICAL:
                filtered.append(m)
            elif m.severity == Severity.HIGH:
                filtered.append(
                    PatternMatch(
                        pattern_id=m.pattern_id,
                        category=m.category,
                        severity=Severity.MEDIUM,
                        description=m.description,
                        matched_text=m.matched_text,
                        line_number=m.line_number,
                    )
                )
            elif m.severity == Severity.MEDIUM:
                filtered.append(
                    PatternMatch(
                        pattern_id=m.pattern_id,
                        category=m.category,
                        severity=Severity.LOW,
                        description=m.description,
                        matched_text=m.matched_text,
                        line_number=m.line_number,
                    )
                )
            # LOW -> dropped
        return filtered

    @staticmethod
    def _determine_verdict(matches: list[PatternMatch]) -> Verdict:
        """Determine verdict from match list.

        DETECTED: any CRITICAL or HIGH severity match
        SUSPICIOUS: only MEDIUM or LOW severity matches
        CLEAN: no matches
        """
        if not matches:
            return Verdict.CLEAN

        for m in matches:
            if m.severity in (Severity.CRITICAL, Severity.HIGH):
                return Verdict.DETECTED

        return Verdict.SUSPICIOUS

    @staticmethod
    def _build_line_offsets(content: str) -> list[int]:
        """Build list of character offsets for the start of each line."""
        offsets = [0]
        idx = 0
        while idx < len(content):
            idx = content.find("\n", idx)
            if idx == -1:
                break
            idx += 1
            offsets.append(idx)
        return offsets

    @staticmethod
    def _offset_to_line(offsets: list[int], char_offset: int) -> int:
        """Convert a character offset to a 1-based line number."""
        lo, hi = 0, len(offsets) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if offsets[mid] <= char_offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo  # 1-based: offsets[0]=0, so lo after search gives correct line
