"""Scanner for .claude/settings.json — detects malicious project-level settings.

Runs as Layer 0 defense: before the Claude Code agent starts, so attacks via
disableAllHooks, enableAllProjectMcpServers, env overrides, or malicious hook
commands are caught pre-execution.

References:
    CVE-2025-59536 — Malicious settings.json disableAllHooks bypass
    CVE-2026-21852 — MCP server auto-enable via project settings
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SettingsSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"
    INFO = "info"


@dataclass
class SettingsFinding:
    check_id: str
    severity: SettingsSeverity
    description: str
    path: str  # JSON path within settings file, e.g. "hooks.SessionStart[0]"
    recommendation: str


@dataclass
class SettingsScanResult:
    findings: list[SettingsFinding] = field(default_factory=list)
    is_safe: bool = True  # False if any CRITICAL findings

    @property
    def has_critical(self) -> bool:
        return any(f.severity == SettingsSeverity.CRITICAL for f in self.findings)


# Compiled patterns for suspicious hook commands.
# Each tuple: (compiled regex, description for the finding).
_SUSPICIOUS_HOOK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"curl\s"), "curl command (potential data exfiltration)"),
    (re.compile(r"wget\s"), "wget command (potential payload download)"),
    (re.compile(r"\bnc\s"), "netcat command (potential reverse shell)"),
    (re.compile(r"\bnetcat\s"), "netcat command (potential reverse shell)"),
    (re.compile(r"https?://"), "URL reference (potential data exfiltration)"),
    (re.compile(r"base64"), "base64 usage (potential obfuscation)"),
    (re.compile(r"\beval\b"), "eval usage (potential code injection)"),
    (re.compile(r"\bexec\b"), "exec usage (potential code injection)"),
    (re.compile(r"\.ssh/"), "SSH directory access (credential theft)"),
    (re.compile(r"\.env\b"), ".env file access (secret theft)"),
    (re.compile(r"\.aws/"), "AWS credentials access"),
    (re.compile(r"\.gnupg/"), "GPG keyring access"),
    (re.compile(r"/etc/passwd"), "system password file access"),
    (re.compile(r"/etc/shadow"), "system shadow file access"),
]

# Environment variable name patterns that indicate sensitive overrides.
_DANGEROUS_ENV_EXACT = {"ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY"}
_DANGEROUS_ENV_SUFFIXES = ("_API_KEY", "_SECRET", "_TOKEN")

# Permission patterns considered overly broad.
_BROAD_PERMISSION_PATTERNS = [
    re.compile(r"^\*$"),  # literal wildcard
    re.compile(r"^Bash\(\*"),  # Bash(**) or Bash(*)
]


class SettingsScanner:
    """Scans .claude/settings.json for malicious or dangerous configurations."""

    def scan(self, settings_path: Path) -> SettingsScanResult:
        """Scan a .claude/settings.json file for malicious configurations.

        Returns a safe result if the file does not exist (no settings = safe).
        Returns a PARSE-001 finding if the file cannot be parsed as JSON.
        """
        if not settings_path.exists():
            return SettingsScanResult()

        raw = settings_path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            result = SettingsScanResult()
            result.findings.append(
                SettingsFinding(
                    check_id="PARSE-001",
                    severity=SettingsSeverity.HIGH,
                    description="Settings file contains invalid JSON",
                    path=str(settings_path),
                    recommendation="Remove or fix the malformed settings file",
                )
            )
            return result

        if not isinstance(data, dict):
            result = SettingsScanResult()
            result.findings.append(
                SettingsFinding(
                    check_id="PARSE-001",
                    severity=SettingsSeverity.HIGH,
                    description="Settings file root is not a JSON object",
                    path=str(settings_path),
                    recommendation="Settings must be a JSON object",
                )
            )
            return result

        return self.scan_json(data, source_path=str(settings_path))

    def scan_json(self, data: dict[str, Any], source_path: str = "<unknown>") -> SettingsScanResult:
        """Scan parsed settings data. Useful for testing."""
        result = SettingsScanResult()

        self._check_disable_hooks(data, result)
        self._check_mcp_servers(data, result)
        self._check_env_overrides(data, result)
        self._check_hook_commands(data, result)
        self._check_permissions(data, result)

        # Mark unsafe if any critical finding exists.
        if result.has_critical:
            result.is_safe = False

        return result

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_disable_hooks(self, data: dict[str, Any], result: SettingsScanResult) -> None:
        """CRITICAL: disableAllHooks: true blinds all hook-based defenses."""
        if data.get("disableAllHooks") is True:
            result.findings.append(
                SettingsFinding(
                    check_id="HOOKS-001",
                    severity=SettingsSeverity.CRITICAL,
                    description=(
                        "disableAllHooks is set to true — this disables all hook-based "
                        "security defenses (CVE-2025-59536)"
                    ),
                    path="disableAllHooks",
                    recommendation="Remove or set disableAllHooks to false",
                )
            )

    def _check_mcp_servers(self, data: dict[str, Any], result: SettingsScanResult) -> None:
        """CRITICAL: enableAllProjectMcpServers: true auto-enables untrusted MCP servers."""
        if data.get("enableAllProjectMcpServers") is True:
            result.findings.append(
                SettingsFinding(
                    check_id="MCP-001",
                    severity=SettingsSeverity.CRITICAL,
                    description=(
                        "enableAllProjectMcpServers is set to true — this auto-enables "
                        "all project-defined MCP servers without consent (CVE-2026-21852)"
                    ),
                    path="enableAllProjectMcpServers",
                    recommendation=(
                        "Remove enableAllProjectMcpServers; explicitly configure "
                        "trusted MCP servers instead"
                    ),
                )
            )

    def _check_env_overrides(self, data: dict[str, Any], result: SettingsScanResult) -> None:
        """CRITICAL: dangerous environment variable overrides."""
        env = data.get("env")
        if not isinstance(env, dict):
            return

        for var_name in env:
            is_dangerous = var_name in _DANGEROUS_ENV_EXACT or any(
                var_name.endswith(suffix) for suffix in _DANGEROUS_ENV_SUFFIXES
            )
            if is_dangerous:
                result.findings.append(
                    SettingsFinding(
                        check_id="ENV-001",
                        severity=SettingsSeverity.CRITICAL,
                        description=(
                            f"Dangerous environment override: {var_name} — "
                            "may exfiltrate credentials or redirect API traffic"
                        ),
                        path=f"env.{var_name}",
                        recommendation=f"Remove the {var_name} override from project settings",
                    )
                )

    def _check_hook_commands(self, data: dict[str, Any], result: SettingsScanResult) -> None:
        """HIGH/CRITICAL: hook definitions containing suspicious commands."""
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return

        for event_name, event_hooks in hooks.items():
            if not isinstance(event_hooks, list):
                continue
            for hook_idx, hook_group in enumerate(event_hooks):
                if not isinstance(hook_group, dict):
                    continue
                inner_hooks = hook_group.get("hooks")
                if not isinstance(inner_hooks, list):
                    continue
                for cmd_idx, hook_def in enumerate(inner_hooks):
                    if not isinstance(hook_def, dict):
                        continue
                    command = hook_def.get("command", "")
                    if not isinstance(command, str):
                        continue
                    self._check_single_command(
                        command,
                        json_path=f"hooks.{event_name}[{hook_idx}].hooks[{cmd_idx}]",
                        result=result,
                    )

    def _check_single_command(
        self, command: str, json_path: str, result: SettingsScanResult
    ) -> None:
        """Check a single hook command string against suspicious patterns."""
        for pattern, desc in _SUSPICIOUS_HOOK_PATTERNS:
            if pattern.search(command):
                result.findings.append(
                    SettingsFinding(
                        check_id="HOOK-CMD-001",
                        severity=SettingsSeverity.CRITICAL,
                        description=f"Suspicious hook command — {desc}: {command!r}",
                        path=json_path,
                        recommendation="Remove or audit this hook command before proceeding",
                    )
                )
                # One finding per command is enough; don't spam duplicates
                # for commands that match multiple patterns.
                return

    def _check_permissions(self, data: dict[str, Any], result: SettingsScanResult) -> None:
        """WARNING: overly permissive allow patterns."""
        permissions = data.get("permissions")
        if not isinstance(permissions, dict):
            return

        allow_list = permissions.get("allow")
        if not isinstance(allow_list, list):
            return

        for idx, pattern in enumerate(allow_list):
            if not isinstance(pattern, str):
                continue
            for broad_re in _BROAD_PERMISSION_PATTERNS:
                if broad_re.search(pattern):
                    result.findings.append(
                        SettingsFinding(
                            check_id="PERM-001",
                            severity=SettingsSeverity.WARNING,
                            description=(
                                f"Overly broad permission pattern: {pattern!r} — "
                                "grants excessive tool access"
                            ),
                            path=f"permissions.allow[{idx}]",
                            recommendation="Use specific tool permissions instead of wildcards",
                        )
                    )
                    break
