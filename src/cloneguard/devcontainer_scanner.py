"""Scanner for devcontainer.json — detects dangerous container configurations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class DevcontainerSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"


@dataclass
class DevcontainerFinding:
    check_id: str
    severity: DevcontainerSeverity
    description: str
    evidence: str


@dataclass
class DevcontainerScanResult:
    findings: list[DevcontainerFinding] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == DevcontainerSeverity.CRITICAL for f in self.findings)

    @property
    def is_safe(self) -> bool:
        return len(self.findings) == 0


class DevcontainerScanner:
    """Scan devcontainer.json for dangerous container configurations."""

    # Host paths that should never be mounted
    DANGEROUS_MOUNTS: list[tuple[str, str, str, str]] = [
        (
            r"/var/run/docker\.sock",
            "DC-C01",
            "Docker socket mount — enables container escape to host",
            "NV-09: Devcontainer lifecycle hook trojan with Docker socket escape (Gemini Chain 1)",
        ),
        (
            r"~?/\.ssh\b",
            "DC-C02",
            "SSH key directory mount — exposes private keys",
            "NV-09: Host secret exposure via volume mounts",
        ),
        (
            r"~?/\.aws\b",
            "DC-C03",
            "AWS credential directory mount",
            "NV-09: Cloud credential exposure",
        ),
        (
            r"~?/\.gnupg\b",
            "DC-C04",
            "GPG key directory mount",
            "NV-09: Cryptographic key exposure",
        ),
        (
            r"~?/\.config\b",
            "DC-H01",
            "User config directory mount — broad access",
            "Host configuration exposure",
        ),
        (
            r"~?/\.kube\b",
            "DC-H02",
            "Kubernetes config mount — cluster access",
            "Kubernetes credential exposure",
        ),
    ]

    # Suspicious URL patterns in lifecycle commands
    URL_PATTERN: re.Pattern[str] = re.compile(
        r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"
    )

    # Devcontainer file paths to scan (relative to repo root)
    DEVCONTAINER_PATHS: list[str] = [
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
    ]

    def scan(self, devcontainer_path: Path) -> DevcontainerScanResult:
        """Scan a devcontainer.json file."""
        if not devcontainer_path.exists():
            return DevcontainerScanResult()
        try:
            # devcontainer.json supports JSON with comments (JSONC)
            content = devcontainer_path.read_text(encoding="utf-8")
            # Strip single-line comments for parsing
            lines = []
            for line in content.splitlines():
                stripped = line.lstrip()
                if not stripped.startswith("//"):
                    lines.append(line)
                else:
                    lines.append("")
            data = json.loads("\n".join(lines))
        except (json.JSONDecodeError, OSError):
            return DevcontainerScanResult(
                findings=[
                    DevcontainerFinding(
                        "DC-PARSE",
                        DevcontainerSeverity.WARNING,
                        "Could not parse devcontainer.json",
                        "Parse error",
                    )
                ]
            )
        return self.scan_json(data)

    def scan_json(self, data: dict[str, Any]) -> DevcontainerScanResult:
        """Scan parsed devcontainer.json data."""
        result = DevcontainerScanResult()
        self._check_mounts(data, result)
        self._check_lifecycle_hooks(data, result)
        self._check_privileged(data, result)
        self._check_run_args(data, result)
        self._check_features(data, result)
        return result

    def _check_mounts(
        self,
        data: dict[str, Any],
        result: DevcontainerScanResult,
    ) -> None:
        """Check volume mounts for dangerous host paths."""
        mounts = data.get("mounts", [])
        if isinstance(mounts, list):
            for mount in mounts:
                mount_str = mount if isinstance(mount, str) else json.dumps(mount)
                for pattern, check_id, desc, evidence in self.DANGEROUS_MOUNTS:
                    if re.search(pattern, mount_str):
                        severity = (
                            DevcontainerSeverity.CRITICAL
                            if check_id.startswith("DC-C")
                            else DevcontainerSeverity.HIGH
                        )
                        result.findings.append(
                            DevcontainerFinding(check_id, severity, desc, evidence)
                        )

    def _check_lifecycle_hooks(
        self,
        data: dict[str, Any],
        result: DevcontainerScanResult,
    ) -> None:
        """Check lifecycle hooks for suspicious content."""
        hooks = [
            "postCreateCommand",
            "postStartCommand",
            "postAttachCommand",
            "initializeCommand",
            "onCreateCommand",
            "updateContentCommand",
        ]
        for hook_name in hooks:
            cmd = data.get(hook_name)
            if cmd is None:
                continue
            cmd_str = cmd if isinstance(cmd, str) else json.dumps(cmd)
            if self.URL_PATTERN.search(cmd_str):
                result.findings.append(
                    DevcontainerFinding(
                        "DC-H03",
                        DevcontainerSeverity.HIGH,
                        f"{hook_name} contacts external URL: potential code execution",
                        "NV-09: Devcontainer lifecycle hooks execute arbitrary code during build",
                    )
                )
            # Check for pipe-to-shell
            if re.search(r"curl.*\|\s*(?:ba)?sh|wget.*\|\s*(?:ba)?sh", cmd_str):
                result.findings.append(
                    DevcontainerFinding(
                        "DC-C05",
                        DevcontainerSeverity.CRITICAL,
                        f"{hook_name} uses curl-pipe-shell pattern",
                        "NV-09: RCE via devcontainer lifecycle hook",
                    )
                )

    def _check_privileged(
        self,
        data: dict[str, Any],
        result: DevcontainerScanResult,
    ) -> None:
        """Check for privileged mode."""
        if data.get("privileged") is True:
            result.findings.append(
                DevcontainerFinding(
                    "DC-C06",
                    DevcontainerSeverity.CRITICAL,
                    "Container runs in privileged mode — full host access",
                    "Privileged containers can escape to host",
                )
            )

    def _check_run_args(
        self,
        data: dict[str, Any],
        result: DevcontainerScanResult,
    ) -> None:
        """Check runArgs for dangerous flags."""
        run_args = data.get("runArgs", [])
        for arg in run_args:
            if arg == "--privileged":
                result.findings.append(
                    DevcontainerFinding(
                        "DC-C07",
                        DevcontainerSeverity.CRITICAL,
                        "runArgs includes --privileged",
                        "Privileged containers can escape to host",
                    )
                )
            if "--cap-add" in str(arg) and "SYS_ADMIN" in str(arg):
                result.findings.append(
                    DevcontainerFinding(
                        "DC-H04",
                        DevcontainerSeverity.HIGH,
                        "runArgs adds SYS_ADMIN capability",
                        "SYS_ADMIN enables mount namespace manipulation",
                    )
                )

    def _check_features(
        self,
        data: dict[str, Any],
        result: DevcontainerScanResult,
    ) -> None:
        """Check features for non-standard sources."""
        features = data.get("features", {})
        for feature_id in features:
            # Standard features from ghcr.io/devcontainers/ are OK
            if isinstance(feature_id, str) and not feature_id.startswith("ghcr.io/devcontainers/"):
                if "://" in feature_id or feature_id.startswith("./"):
                    result.findings.append(
                        DevcontainerFinding(
                            "DC-W01",
                            DevcontainerSeverity.WARNING,
                            f"Non-standard devcontainer feature source: {feature_id}",
                            "NV-09: Feature installation runs arbitrary code during build",
                        )
                    )
