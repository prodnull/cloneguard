"""RepoScanner — orchestrates all scanners for a repository.

Tier 1: PatternEngine (regex, <50ms) + SettingsScanner + EnvScanner + DevcontainerScanner
Tier 2: SemanticClassifier (Ollama LLM, ~2s/file) — optional, for Layer 0 only

Produces a structured ScanReport with per-file status (BLOCKED / WARNING / CLEAN).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cloneguard.allowlist import Allowlist
from cloneguard.devcontainer_scanner import DevcontainerScanner, DevcontainerSeverity
from cloneguard.env_scanner import EnvScanner, EnvSeverity
from cloneguard.patterns import PatternEngine, ScanMode, Severity
from cloneguard.settings_scanner import SettingsScanner, SettingsSeverity


class Status(Enum):
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"
    CLEAN = "CLEAN"


@dataclass
class FileResult:
    path: str
    status: Status
    issues: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    repo_path: Path
    file_results: list[FileResult] = field(default_factory=list)
    yolo_mode: bool = False
    _active_tiers: str = ""

    @property
    def exit_code(self) -> int:
        if any(r.status == Status.BLOCKED for r in self.file_results):
            return 2
        if any(r.status == Status.WARNING for r in self.file_results):
            return 1
        return 0

    def format(self, color: bool = False) -> str:
        """Format the scan report as a human-readable string."""
        from cloneguard import __version__

        lines: list[str] = []
        lines.append(f"CloneGuard v{__version__} — Pre-execution scan")
        lines.append("")
        lines.append(f"Scanning {self.repo_path}...")

        # Surface active tiers so users know what's running
        if self._active_tiers:
            lines.append(f"Active tiers: {self._active_tiers}")
        lines.append("")

        if self.yolo_mode:
            lines.append("Note: Agent will auto-approve all operations. Extra scrutiny applied.")
            lines.append("")

        for fr in self.file_results:
            tag = self._format_tag(fr.status, color)
            detail = ""
            if fr.issues:
                detail = " — " + "; ".join(fr.issues)
            lines.append(f" {tag}  {fr.path}{detail}")

        # Summary
        issue_count = sum(
            1 for r in self.file_results if r.status in (Status.BLOCKED, Status.WARNING)
        )
        lines.append("")
        if issue_count:
            lines.append(f"{issue_count} issue(s) found.")
        else:
            lines.append("No issues found.")

        return "\n".join(lines)

    @staticmethod
    def _format_tag(status: Status, color: bool) -> str:
        label = status.value
        if not color:
            return label
        codes = {
            Status.BLOCKED: "\033[91m",  # red
            Status.WARNING: "\033[93m",  # yellow
            Status.CLEAN: "\033[92m",  # green
        }
        reset = "\033[0m"
        return f"{codes[status]}{label}{reset}"


# Files always scanned (high priority), relative to repo root.
_HIGH_PRIORITY_FILES = [
    "CLAUDE.md",
    "GEMINI.md",
    "AGENTS.MD",
    ".cursorrules",
    ".clinerules",
    ".junie/guidelines.md",
    "README.md",
    "CONTRIBUTING.md",
    "package.json",
    "Makefile",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
]

_HIGH_PRIORITY_GLOB_PATTERNS = [
    ".claude/rules/*.md",
    ".claude/commands/*.md",
    ".github/copilot-instructions.md",
    ".github/workflows/*.yml",
]

# Medium priority files.
_MEDIUM_PRIORITY_FILES = [
    ".gitmodules",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".devcontainer/devcontainer.json",
    ".devcontainer.json",
    ".vscode/settings.json",
    ".idea/workspace.xml",
    ".gitattributes",
    ".gitconfig",
    "Dockerfile",
    "codex.json",
    ".gemini/settings.json",
    ".npmrc",
    ".yarnrc.yml",
    ".envrc",
    ".tool-versions",
    ".mise.toml",
    ".pre-commit-config.yaml",
    "justfile",
    "Taskfile.yml",
    "flake.nix",
]

_MEDIUM_PRIORITY_GLOB_PATTERNS = [
    "*.svg",
    "*.code-workspace",
]


class RepoScanner:
    """Orchestrate scanning of a repository directory."""

    def __init__(
        self,
        yolo_mode: bool = False,
        tier2: bool = False,
        tier2_model: str | None = None,
        cache: bool = False,
    ) -> None:
        self._pattern_engine = PatternEngine()
        self._settings_scanner = SettingsScanner()
        self._env_scanner = EnvScanner()
        self._devcontainer_scanner = DevcontainerScanner()
        self._allowlist = Allowlist()
        self._yolo_mode = yolo_mode
        self._tier2 = tier2
        self._tier2_model = tier2_model
        self._trust_cache = None
        if cache:
            try:
                from cloneguard.trust_cache import TrustCache

                self._trust_cache = TrustCache()
            except ImportError:
                pass  # trust_cache module not available

    def scan(self, repo_path: Path) -> ScanReport:
        report = ScanReport(repo_path=repo_path, yolo_mode=self._yolo_mode)

        # 1. Scan .claude/settings.json
        settings_path = repo_path / ".claude" / "settings.json"
        if settings_path.exists():
            self._scan_settings(settings_path, report)

        # 2. Scan .env files
        self._scan_env_files(repo_path, report)

        # 3. Scan devcontainer.json files
        self._scan_devcontainer_files(repo_path, report)

        # 4. Collect files to scan with PatternEngine
        files_to_scan = self._collect_files(repo_path)

        # 5. Scan each file with Tier 1 (PatternEngine)
        file_contents: list[tuple[str, str]] = []
        for file_path in sorted(files_to_scan):
            content = self._scan_file(file_path, repo_path, report)
            if content is not None:
                rel = str(file_path.relative_to(repo_path))
                file_contents.append((rel, content))

        # 6. Tier 2 semantic classification (if enabled)
        if self._tier2 and file_contents:
            self._run_tier2(file_contents, report)

        return report

    def _scan_env_files(self, repo_path: Path, report: ScanReport) -> None:
        """Scan .env files for dangerous environment variable settings."""
        for name in EnvScanner.ENV_FILE_NAMES:
            env_path = repo_path / name
            if not env_path.exists():
                continue
            result = self._env_scanner.scan(env_path)
            if result.is_safe:
                report.file_results.append(FileResult(path=name, status=Status.CLEAN))
                continue

            issues: list[str] = []
            has_critical = False
            has_high = False
            for finding in result.findings:
                issues.append(f"{finding.description} ({finding.check_id})")
                if finding.severity == EnvSeverity.CRITICAL:
                    has_critical = True
                elif finding.severity == EnvSeverity.HIGH:
                    has_high = True

            if has_critical:
                status = Status.BLOCKED
            elif has_high:
                status = Status.BLOCKED
            else:
                status = Status.WARNING

            report.file_results.append(FileResult(path=name, status=status, issues=issues))

    def _scan_devcontainer_files(self, repo_path: Path, report: ScanReport) -> None:
        """Scan devcontainer.json files for dangerous configurations."""
        for rel_path in DevcontainerScanner.DEVCONTAINER_PATHS:
            dc_path = repo_path / rel_path
            if not dc_path.exists():
                continue
            result = self._devcontainer_scanner.scan(dc_path)
            if result.is_safe:
                report.file_results.append(FileResult(path=rel_path, status=Status.CLEAN))
                continue

            issues: list[str] = []
            has_critical = False
            has_high = False
            for finding in result.findings:
                issues.append(f"{finding.description} ({finding.check_id})")
                if finding.severity == DevcontainerSeverity.CRITICAL:
                    has_critical = True
                elif finding.severity == DevcontainerSeverity.HIGH:
                    has_high = True

            if has_critical:
                status = Status.BLOCKED
            elif has_high:
                status = Status.BLOCKED
            else:
                status = Status.WARNING

            report.file_results.append(FileResult(path=rel_path, status=status, issues=issues))

    def _scan_settings(self, settings_path: Path, report: ScanReport) -> None:
        result = self._settings_scanner.scan(settings_path)
        if not result.findings:
            report.file_results.append(
                FileResult(path=".claude/settings.json", status=Status.CLEAN)
            )
            return

        issues: list[str] = []
        has_critical = False
        for finding in result.findings:
            issues.append(f"{finding.description} ({finding.check_id})")
            if finding.severity in (SettingsSeverity.CRITICAL, SettingsSeverity.HIGH):
                has_critical = True

        status = Status.BLOCKED if has_critical else Status.WARNING

        report.file_results.append(
            FileResult(
                path=".claude/settings.json",
                status=status,
                issues=issues,
            )
        )

    def _collect_files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []

        for name in _HIGH_PRIORITY_FILES:
            p = repo_path / name
            if p.is_file():
                files.append(p)

        for pattern in _HIGH_PRIORITY_GLOB_PATTERNS:
            files.extend(repo_path.glob(pattern))

        for name in _MEDIUM_PRIORITY_FILES:
            p = repo_path / name
            if p.is_file():
                files.append(p)

        for pattern in _MEDIUM_PRIORITY_GLOB_PATTERNS:
            files.extend(repo_path.glob(pattern))

        # Deduplicate preserving order
        seen: set[Path] = set()
        unique: list[Path] = []
        for f in files:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return unique

    def _scan_file(self, file_path: Path, repo_path: Path, report: ScanReport) -> str | None:
        """Scan a single file with Tier 1. Returns content for Tier 2."""
        rel_path = str(file_path.relative_to(repo_path))

        # Trust cache: skip files already verified clean
        if self._trust_cache:
            require_t2 = self._tier2
            if self._trust_cache.is_trusted(repo_path, rel_path, require_tier2=require_t2):
                report.file_results.append(FileResult(path=rel_path, status=Status.CLEAN))
                return None  # No content needed — already trusted

        try:
            raw_bytes = file_path.read_bytes()
            content = raw_bytes.decode("utf-8", errors="replace")
        except OSError:
            return None

        # Skip files whose content hash is in the allowlist
        if self._allowlist.is_allowed(raw_bytes):
            report.file_results.append(FileResult(path=rel_path, status=Status.CLEAN))
            return content

        result = self._pattern_engine.scan(content, source_path=rel_path)

        # In YOLO mode, escalate MEDIUM -> HIGH
        if self._yolo_mode:
            for match in result.matches:
                if match.severity == Severity.MEDIUM:
                    match.severity = Severity.HIGH

        if not result.matches:
            report.file_results.append(FileResult(path=rel_path, status=Status.CLEAN))
            # Mark as Tier 1 clean in trust cache (tier2_clean=False for now)
            if self._trust_cache:
                self._trust_cache.mark_trusted(repo_path, rel_path, tier2_clean=False)
            return content

        issues = [f"{m.description} ({m.pattern_id})" for m in result.matches]

        has_critical = any(m.severity == Severity.CRITICAL for m in result.matches)
        has_high = any(m.severity == Severity.HIGH for m in result.matches)
        mode = self._pattern_engine._detect_mode(rel_path)

        if has_critical:
            status = Status.BLOCKED
        elif has_high and mode == ScanMode.STRICT:
            status = Status.BLOCKED
        elif has_high:
            status = Status.WARNING
        else:
            status = Status.WARNING

        report.file_results.append(FileResult(path=rel_path, status=status, issues=issues))
        # Dirty files: invalidate any stale trust entry
        if self._trust_cache:
            self._trust_cache.invalidate(repo_path, rel_path)
        return content

    def _run_tier2(
        self,
        file_contents: list[tuple[str, str]],
        report: ScanReport,
    ) -> None:
        """Run semantic classification: Tier 1.5 (mini model) then Tier 2 (Ollama)."""
        from cloneguard.semantic import SemanticVerdict

        sem_result = None

        # Try Tier 1.5 (bundled mini model) first
        try:
            from cloneguard.mini_semantic import MiniSemanticClassifier

            mini = MiniSemanticClassifier()
            if mini.available:
                # Repo-wide scans are STANDARD context — each file's path-based mode is
                # applied per-chunk inside classify_files() via the shared mode parameter.
                # Hook handlers (hooks.py) handle STRICT/LENIENT for their specific
                # single-file contexts; scanner uses STANDARD as the safe default.
                sem_result = mini.classify_files(file_contents, mode=ScanMode.STANDARD)
                report._active_tiers = "Tier 0 (regex) + Tier 1.5 (ONNX)"
            else:
                import sys

                print(
                    "WARNING: Tier 1.5 ONNX model unavailable — scanning with Tier 0 regex only"
                    " (31.9% recall). Install cloneguard[mini] for semantic detection.",
                    file=sys.stderr,
                )
        except ImportError:
            import sys

            print(
                "WARNING: Tier 1.5 dependencies not installed — scanning with Tier 0 regex only"
                " (31.9% recall). Run: pip install cloneguard[mini]",
                file=sys.stderr,
            )

        # Fall back to Tier 2 (Ollama) if mini model unavailable
        if sem_result is None:
            from cloneguard.semantic import SemanticClassifier

            kwargs = {}
            if self._tier2_model:
                kwargs["model"] = self._tier2_model
            classifier = SemanticClassifier(**kwargs)
            if not classifier.is_available():
                if not report._active_tiers:
                    report._active_tiers = "Tier 0 (regex) only — semantic scanning unavailable"
                return
            sem_result = classifier.classify_files(file_contents)
            report._active_tiers = "Tier 0 (regex) + Tier 2 (Ollama)"

        # Track which files Tier 2 flagged
        flagged_paths: set[str] = set()

        for finding in sem_result.findings:
            if finding.verdict == SemanticVerdict.SAFE:
                continue

            flagged_paths.add(finding.file_path)

            # Find existing FileResult for this path
            existing = next(
                (r for r in report.file_results if r.path == finding.file_path),
                None,
            )
            issue = f"Tier 2: {finding.reason} ({finding.verdict.value})"

            if finding.verdict == SemanticVerdict.MALICIOUS:
                if existing and existing.status == Status.CLEAN:
                    existing.status = Status.WARNING
                    existing.issues.append(issue)
                elif existing:
                    existing.issues.append(issue)
                    if finding.confidence >= 0.8:
                        existing.status = Status.BLOCKED
                else:
                    report.file_results.append(
                        FileResult(
                            path=finding.file_path,
                            status=Status.WARNING,
                            issues=[issue],
                        )
                    )
            elif finding.verdict == SemanticVerdict.SUSPICIOUS:
                if existing and existing.status == Status.CLEAN:
                    existing.status = Status.WARNING
                    existing.issues.append(issue)
                elif existing:
                    existing.issues.append(issue)

        # Upgrade trust cache entries: files that passed both Tier 1 and Tier 2
        if self._trust_cache:
            for rel_path, _ in file_contents:
                existing = next(
                    (r for r in report.file_results if r.path == rel_path),
                    None,
                )
                if existing and existing.status == Status.CLEAN and rel_path not in flagged_paths:
                    self._trust_cache.mark_trusted(report.repo_path, rel_path, tier2_clean=True)
