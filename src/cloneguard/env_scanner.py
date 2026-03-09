"""Scanner for .env files — detects dangerous environment variable settings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class EnvSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"


@dataclass
class EnvFinding:
    check_id: str
    severity: EnvSeverity
    variable: str
    value: str
    description: str
    evidence: str  # Citation for why this is dangerous


@dataclass
class EnvScanResult:
    findings: list[EnvFinding] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == EnvSeverity.CRITICAL for f in self.findings)

    @property
    def is_safe(self) -> bool:
        return len(self.findings) == 0


class EnvScanner:
    """Scan .env files for dangerous environment variable settings."""

    # CRITICAL: These can inject code into the agent's own process or redirect API calls
    CRITICAL_VARS: dict[str, tuple[str, str, str]] = {
        "NODE_OPTIONS": (
            "ENV-C01",
            "Injects flags into Node.js runtime — can --require attacker code "
            "into Claude Code's own process",
            "NV-22: Claude Code runs as Node.js; NODE_OPTIONS=--require=backdoor.js "
            "compromises agent process (Knostic research)",
        ),
        "LD_PRELOAD": (
            "ENV-C02",
            "Injects shared library into every spawned process",
            "GNV-03: LD_PRELOAD hijacking via .env auto-loading",
        ),
        "DYLD_INSERT_LIBRARIES": (
            "ENV-C03",
            "macOS dylib injection into every spawned process",
            "GNV-03 macOS variant",
        ),
        "ANTHROPIC_BASE_URL": (
            "ENV-C04",
            "Redirects Claude API calls — exfiltrates API key to attacker",
            "NV-03/CVE-2026-21852: Check Point Research demonstrated API key theft",
        ),
        "OPENAI_BASE_URL": (
            "ENV-C05",
            "Redirects OpenAI API calls to attacker server",
            "NV-03 generalized",
        ),
        "NODE_TLS_REJECT_UNAUTHORIZED": (
            "ENV-C06",
            "Value '0' disables all TLS verification",
            "Enables MITM on all HTTPS connections",
        ),
    }

    # HIGH: These hijack behavior but don't directly inject code
    HIGH_VARS: dict[str, tuple[str, str, str]] = {
        "PYTHONPATH": (
            "ENV-H01",
            "Redirects Python imports to attacker-controlled modules",
            "GNV-03: Import hijacking",
        ),
        "PYTHONSTARTUP": (
            "ENV-H02",
            "Executes attacker script on Python interpreter start",
            "Auto-executes in any Python subprocess",
        ),
        "ZDOTDIR": (
            "ENV-H03",
            "Redirects zsh initialization to attacker directory",
            "NV-11: ZDOTDIR=./.malicious → sources attacker's .zshenv in every shell",
        ),
        "BASH_ENV": (
            "ENV-H04",
            "Script sourced by every non-interactive bash instance",
            "NV-11: Shell initialization hijacking",
        ),
        "HTTP_PROXY": (
            "ENV-H05",
            "Routes all HTTP traffic through attacker proxy",
            "NV-04: .env proxy override enables MITM",
        ),
        "HTTPS_PROXY": (
            "ENV-H06",
            "Routes all HTTPS traffic through attacker proxy",
            "NV-04: Combined with NODE_TLS_REJECT_UNAUTHORIZED=0 for full interception",
        ),
        "ALL_PROXY": (
            "ENV-H07",
            "Routes all traffic through attacker proxy",
            "NV-04 catch-all variant",
        ),
        "NODE_EXTRA_CA_CERTS": (
            "ENV-H08",
            "Custom CA certs enable TLS MITM",
            "NV-04: Combined with proxy for full interception",
        ),
        "GIT_SSH_COMMAND": (
            "ENV-H09",
            "Custom SSH command for git — can intercept credentials",
            "Replaces ssh with attacker binary",
        ),
        "GIT_PROXY_COMMAND": (
            "ENV-H10",
            "Custom proxy for git protocol",
            "Routes git traffic through attacker",
        ),
        "GEMINI_API_ENDPOINT": (
            "ENV-H11",
            "Redirects Gemini API calls",
            "NV-03 Gemini variant",
        ),
    }

    # WARNING: Suspicious but might be legitimate
    WARNING_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
        (
            "ENV-W01",
            re.compile(r"(?i).*_API_KEY\s*=\s*\S+"),
            "API key in .env file — ensure not committed",
            "Standard security hygiene",
        ),
        (
            "ENV-W02",
            re.compile(r"(?i).*_SECRET\s*=\s*\S+"),
            "Secret in .env file — ensure not committed",
            "Standard security hygiene",
        ),
        (
            "ENV-W03",
            re.compile(r"(?i).*_TOKEN\s*=\s*\S+"),
            "Token in .env file — ensure not committed",
            "Standard security hygiene",
        ),
    ]

    # .env file names to scan (relative to repo root)
    ENV_FILE_NAMES: list[str] = [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".flaskenv",
    ]

    def scan(self, env_path: Path) -> EnvScanResult:
        """Scan a .env file."""
        if not env_path.exists():
            return EnvScanResult()
        try:
            content = env_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return EnvScanResult()
        return self.scan_content(content)

    def scan_content(self, content: str) -> EnvScanResult:
        """Scan .env content string."""
        result = EnvScanResult()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Parse KEY=VALUE (handle export prefix)
            match = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip('"').strip("'")

            # Check critical vars
            if key in self.CRITICAL_VARS:
                check_id, desc, evidence = self.CRITICAL_VARS[key]
                # Special case: NODE_TLS_REJECT_UNAUTHORIZED is only critical if set to 0
                if key == "NODE_TLS_REJECT_UNAUTHORIZED" and value != "0":
                    continue
                result.findings.append(
                    EnvFinding(
                        check_id=check_id,
                        severity=EnvSeverity.CRITICAL,
                        variable=key,
                        value=value,
                        description=desc,
                        evidence=evidence,
                    )
                )

            # Check high vars
            elif key in self.HIGH_VARS:
                check_id, desc, evidence = self.HIGH_VARS[key]
                result.findings.append(
                    EnvFinding(
                        check_id=check_id,
                        severity=EnvSeverity.HIGH,
                        variable=key,
                        value=value,
                        description=desc,
                        evidence=evidence,
                    )
                )

            # Check warning patterns
            else:
                for check_id, pattern, desc, evidence in self.WARNING_PATTERNS:
                    if pattern.match(line):
                        result.findings.append(
                            EnvFinding(
                                check_id=check_id,
                                severity=EnvSeverity.WARNING,
                                variable=key,
                                value="[redacted]",
                                description=desc,
                                evidence=evidence,
                            )
                        )
                        break

        return result
