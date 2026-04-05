"""ToolCallMonitor — behavioral sequence monitoring for CloneGuard.

Observes tool call sequences within a session and fires structured alerts
when patterns consistent with prompt-injection-driven exfiltration or
lateral movement are detected.

Design contract (see docs/research/v04-direction-research-2026-03-10.md):
- record_event() is LOGGING ONLY — never blocks tool calls
- check_enforcement() returns EnforcementVerdict for blocking rules (SEQ-001/002/005)
- NEVER writes to stdout (stdout is the hook communication channel)
- NEVER raises from record_event (monitor failure must not block agents)
- Adds <0.5ms overhead per hook event (well within 25ms p95 budget)

Sequence rules implemented:
- SEQ-001: Read(sensitive file) -> WebFetch(external URL) within 10 events
- SEQ-002: Read(sensitive file) -> Bash(curl/wget external URL) within 10 events
- SEQ-003: mcp__* tool called >5 times within 10 events (frequency spike)
- SEQ-004: Write(sensitive target) -> Bash(build command) within 10 events
- SEQ-005: Agent/pkg/git config write = privilege escalation / registry hijacking
- SEQ-006: Read(sensitive file) -> MCP exfil-capable tool (advisory only)
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_SESSION_EVENTS = 50  # ring buffer depth per session
_MAX_SESSIONS = 200  # evict oldest sessions beyond this
_LOOKBACK_WINDOW = 10  # number of recent events to consider for sequence rules

# Hosts considered safe/local — WebFetch/Bash calls to these don't trigger alerts.
_SAFE_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})

# MCP tool name keywords suggesting outbound data flow (SEQ-006).
# Matched as substrings (case-insensitive) against mcp__* tool names.
_MCP_EXFIL_KEYWORDS = (
    "send",
    "post",
    "create",
    "write",
    "push",
    "upload",
    "email",
    "message",
    "comment",
    "submit",
    "publish",
    "notify",
    "share",
    "forward",
    "reply",
    "insert",
)

# Sensitive file path substrings (lowercased). Matches credential-bearing files.
# These patterns are specific enough for safe substring matching.
_SENSITIVE_FILE_PATTERNS = (
    ".env",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    # Cloud provider credential paths
    ".aws/",
    ".azure/",
    ".kube/",
    ".docker/config",
    ".netrc",
    ".pgpass",
    "kubeconfig",
    "service_account",
    "serviceaccount",
    # Key patterns (refined to avoid matching "keyboard" etc.)
    "private_key",
    "private-key",
    "api_key",
    "apikey",
    ".pem",
    "keyfile",
    "keystore",
    # GCP application default credentials
    "application_default_credentials",
    # Auth config
    "auth.json",
)

# Ambiguous patterns — match as substrings but require the file is NOT source code.
# Trajectory mining (208,127 benign trajectories) showed these patterns cause 95% of
# false positives when used as bare substrings: tokens.py, password.py, secrets.py,
# credentials.py, secretsmanager/models.py, tokenizer.py, etc.
_SENSITIVE_AMBIGUOUS_PATTERNS = ("secret", "credential", "password", "token")

# Source code extensions that are never credential files (lowercased, with dot).
_SOURCE_CODE_EXTENSIONS = frozenset(
    (
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".swift",
        ".php",
        ".scala",
        ".ex",
        ".exs",
        ".clj",
        ".lua",
        ".r",
        ".m",
        ".mm",
        ".pl",
        ".pm",
    )
)

# Build-sensitive write targets (basenames or path prefixes).
_BUILD_SENSITIVE_TARGETS = frozenset(
    {
        "package.json",
        "makefile",
        "pyproject.toml",
        "setup.py",
        "cargo.toml",
        "gemfile",
        "build.gradle",
        ".gitlab-ci.yml",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
    }
)

_BUILD_SENSITIVE_PREFIXES = (
    ".github/",
    ".claude/",
)

# Build command keywords.
_BUILD_COMMAND_PATTERNS = re.compile(
    r"\b(npm\s+(?:install|ci|run)|npx\s|yarn\s+(?:install|run)|"
    r"pip(?:3)?\s+install|cargo\s+(?:build|run)|"
    r"make(?:\s+\w+)?|cmake\s|go\s+(?:build|run)|"
    r"docker\s+build|bundle\s+install|gem\s+install)\b"
)

# Curl/wget URL extraction from Bash commands.
_CURL_URL_RE = re.compile(r"https?://[^\s'\"]+")

# Bash mv/cp to agent config path detection (SEQ-005 bypass mitigation).
_BASH_MV_CP_RE = re.compile(r"\b(mv|cp)\b")

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ToolEvent:
    """A recorded tool call event from the hook protocol."""

    session_id: str
    tool_use_id: str
    tool_name: str
    tool_input: dict[str, Any]
    hook_event_name: str  # "PreToolUse" or "PostToolUse"
    ts: float = field(default_factory=time.monotonic)


@dataclass
class SequenceAlert:
    """An alert fired when a sequence rule matches."""

    rule_id: str
    description: str
    session_id: str
    trigger_event: ToolEvent
    context_window: list[ToolEvent]


@dataclass
class MarkerEvent:
    """Lightweight persistent marker that survives beyond the lookback window.

    Tracks the most recent occurrence of a security-relevant event category
    within a session, so sequence rules can reference it even after the ring
    buffer has evicted the original ToolEvent.
    """

    file_path: str = ""
    url: str = ""
    command: str = ""
    tool_use_id: str = ""
    ts: float = field(default_factory=time.monotonic)


@dataclass
class SessionMarkers:
    """Per-session container for typed event markers.

    Each field holds the most recent MarkerEvent for its category, or None
    if no matching event has been seen in the session.
    """

    last_sensitive_read: MarkerEvent | None = None
    last_config_write: MarkerEvent | None = None
    last_external_fetch: MarkerEvent | None = None
    last_build_command: MarkerEvent | None = None


@dataclass
class EnforcementVerdict:
    """A verdict from enforcement evaluation."""

    rule_id: str
    action: str  # "block"
    description: str
    session_id: str


# Rules that enforce (block) vs advise (log-only).
_ENFORCEMENT_RULES: frozenset[str] = frozenset({"SEQ-001", "SEQ-002", "SEQ-005"})


# ---------------------------------------------------------------------------
# Agent / package / git config path helpers
# ---------------------------------------------------------------------------

_AGENT_CONFIG_PATTERNS = (
    ".vscode/settings.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/mcp.json",
    ".cursor/settings.json",
    ".continue/config.json",
    ".windsurf/settings.json",
    ".gemini/settings.json",
)

_AGENT_CONFIG_MCP_RE = re.compile(r"mcp[_-]?config.*\.json|mcp.*\.json", re.IGNORECASE)

_PKG_GIT_CONFIG_PATTERNS = (
    ".npmrc",
    ".pypirc",
    ".cargo/config.toml",
    ".cargo/config",
    ".gitconfig",
    ".git/config",
)


def _is_agent_config(file_path: str) -> bool:
    """Return True if file_path matches an agent configuration file pattern."""
    normalized = file_path.replace("\\", "/")
    for pattern in _AGENT_CONFIG_PATTERNS:
        if normalized.endswith(pattern):
            return True
    basename = normalized.rsplit("/", 1)[-1]
    return bool(_AGENT_CONFIG_MCP_RE.match(basename))


def _is_pkg_git_config(file_path: str) -> bool:
    """Return True if file_path matches a package manager or git config file."""
    normalized = file_path.replace("\\", "/")
    for pattern in _PKG_GIT_CONFIG_PATTERNS:
        if normalized.endswith(pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_sensitive_file(file_path: str) -> bool:
    """Return True if file_path may contain credentials or PII.

    Matches against well-known sensitive file name patterns. Case-insensitive.
    Ambiguous patterns (secret, credential, password, token) are excluded when
    the file has a source-code extension — trajectory mining over 208k benign
    agent sessions showed these cause 95% of false positives (e.g., tokens.py,
    secretsmanager/models.py, password.py).

    Heuristic: false negatives possible for unusual naming conventions.
    """
    fp = file_path.lower()

    # Specific patterns — safe for bare substring matching
    if any(p in fp for p in _SENSITIVE_FILE_PATTERNS):
        return True

    # .key — only as file extension, not as substring (avoids "keyboard.py" etc.)
    if fp.endswith(".key"):
        return True

    # Ambiguous patterns — exclude source-code extensions
    ext = ""
    dot_idx = fp.rfind(".")
    if dot_idx != -1:
        ext = fp[dot_idx:]

    if ext not in _SOURCE_CODE_EXTENSIONS:
        if any(p in fp for p in _SENSITIVE_AMBIGUOUS_PATTERNS):
            return True

    return False


def _is_mcp_exfil_tool(tool_name: str) -> bool:
    """Return True if an MCP tool name suggests outbound data flow."""
    if not tool_name.startswith("mcp__"):
        return False
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in _MCP_EXFIL_KEYWORDS)


def _extract_external_url(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Return the destination URL if the tool call targets an external host.

    Returns None for localhost/loopback destinations or if no URL is found.
    Uses urllib.parse.urlparse for RFC 3986-compliant host extraction.
    """
    url: str | None = None
    if tool_name == "WebFetch":
        url = (tool_input.get("url") or "") if isinstance(tool_input, dict) else ""
    elif tool_name == "Bash":
        command = (tool_input.get("command") or "") if isinstance(tool_input, dict) else ""
        m = _CURL_URL_RE.search(str(command))
        url = m.group(0) if m else None

    if not url:
        return None

    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return None

    return url if host not in _SAFE_HOSTS else None


def _is_build_sensitive_target(file_path: str) -> bool:
    """Return True if file_path is a build-configuration-sensitive write target.

    Sensitive targets: package.json, Makefile, pyproject.toml, setup.py,
    Cargo.toml, .github/workflows/, .gitlab-ci.yml, Dockerfile, etc.
    """
    normalized = file_path.replace("\\", "/").lower()
    basename = normalized.rsplit("/", 1)[-1]

    if basename in _BUILD_SENSITIVE_TARGETS:
        return True

    for prefix in _BUILD_SENSITIVE_PREFIXES:
        if prefix in normalized:
            return True

    return False


def _is_build_command(command: str) -> bool:
    """Return True if command string contains a build/install invocation."""
    return bool(_BUILD_COMMAND_PATTERNS.search(command))


def _summarize_input(event: ToolEvent) -> dict[str, Any]:
    """Return a safe summary of tool_input suitable for logging.

    Avoids logging large tool outputs or sensitive content verbatim.
    Only records structurally important fields (file_path, url, command prefix).
    """
    ti = event.tool_input if isinstance(event.tool_input, dict) else {}
    summary: dict[str, Any] = {}

    if "file_path" in ti:
        summary["file_path"] = str(ti["file_path"])
    if "url" in ti:
        summary["url"] = str(ti["url"])
    if "command" in ti:
        cmd = str(ti["command"])
        # Truncate long commands to avoid log bloat
        summary["command"] = cmd[:200] + "..." if len(cmd) > 200 else cmd
    if not summary:
        # Generic fallback: record tool_name only (no tool_input fields captured)
        summary["tool_name"] = event.tool_name

    return summary


# ---------------------------------------------------------------------------
# Sequence rules
# ---------------------------------------------------------------------------

# Rule registry — functions registered via @_rule decorator.
_RULES: list[Callable[[str, deque[ToolEvent], ToolEvent], SequenceAlert | None]] = []


def _rule(
    fn: Callable[[str, deque[ToolEvent], ToolEvent], SequenceAlert | None],
) -> Callable[[str, deque[ToolEvent], ToolEvent], SequenceAlert | None]:
    """Decorator: register a function as a sequence rule."""
    _RULES.append(fn)
    return fn


@_rule
def _file_read_then_network(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-001: Sensitive file read followed by WebFetch to external URL.

    Attack class: Log-To-Leak exfiltration via WebFetch.
    Source: arXiv:2506.01055, arXiv:2602.20720.
    """
    if trigger.tool_name != "WebFetch":
        return None
    ext_url = _extract_external_url("WebFetch", trigger.tool_input)
    if not ext_url:
        return None

    # Check typed marker first (session-wide, survives padding bypass)
    sensitive_fp: str | None = None
    markers = _get_markers_for_rule(session_id)
    if markers and markers.last_sensitive_read:
        sensitive_fp = markers.last_sensitive_read.file_path
    else:
        # Fallback: scan lookback window (backward compat for marker-less sessions)
        recent = list(buf)[-_LOOKBACK_WINDOW:]
        for event in reversed(recent[:-1]):  # exclude trigger itself
            if event.tool_name == "Read":
                fp = (
                    (event.tool_input.get("file_path") or "")
                    if isinstance(event.tool_input, dict)
                    else ""
                )
                if _is_sensitive_file(str(fp)):
                    sensitive_fp = fp
                    break

    if sensitive_fp:
        recent = list(buf)[-_LOOKBACK_WINDOW:]
        return SequenceAlert(
            rule_id="SEQ-001",
            description=(
                f"Sensitive file read ({sensitive_fp!r}) followed by"
                f" WebFetch to external URL ({ext_url!r})"
            ),
            session_id=session_id,
            trigger_event=trigger,
            context_window=recent,
        )
    return None


@_rule
def _file_read_then_curl(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-002: Sensitive file read followed by Bash curl/wget to external URL.

    Attack class: Curl-based exfiltration via Bash.
    Source: EX-001 pattern class.
    """
    if trigger.tool_name != "Bash":
        return None
    ext_url = _extract_external_url("Bash", trigger.tool_input)
    if not ext_url:
        return None

    # Check typed marker first (session-wide, survives padding bypass)
    sensitive_fp: str | None = None
    markers = _get_markers_for_rule(session_id)
    if markers and markers.last_sensitive_read:
        sensitive_fp = markers.last_sensitive_read.file_path
    else:
        # Fallback: scan lookback window (backward compat for marker-less sessions)
        recent = list(buf)[-_LOOKBACK_WINDOW:]
        for event in reversed(recent[:-1]):
            if event.tool_name == "Read":
                fp = (
                    (event.tool_input.get("file_path") or "")
                    if isinstance(event.tool_input, dict)
                    else ""
                )
                if _is_sensitive_file(str(fp)):
                    sensitive_fp = fp
                    break

    if sensitive_fp:
        recent = list(buf)[-_LOOKBACK_WINDOW:]
        return SequenceAlert(
            rule_id="SEQ-002",
            description=(
                f"Sensitive file read ({sensitive_fp!r}) followed by"
                f" Bash network exfiltration ({ext_url!r})"
            ),
            session_id=session_id,
            trigger_event=trigger,
            context_window=recent,
        )
    return None


@_rule
def _mcp_frequency_spike(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-003: Same mcp__* tool called >5 times within the last 10 events.

    Attack class: Repeated MCP tool abuse (AdapTools stealthy tool pattern).
    Source: arXiv:2602.20720 (Wang et al.).
    Threshold: >5 calls (6+) in last 10 events. Exactly 5 does NOT fire.
    """
    if not trigger.tool_name.startswith("mcp__"):
        return None

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    count = sum(1 for e in recent if e.tool_name == trigger.tool_name)

    if count > 5:  # strictly greater than 5
        return SequenceAlert(
            rule_id="SEQ-003",
            description=(
                f"MCP tool {trigger.tool_name!r} called {count} times in last {len(recent)} events"
            ),
            session_id=session_id,
            trigger_event=trigger,
            context_window=recent,
        )
    return None


@_rule
def _write_then_build(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-004: Write to build-sensitive target followed by a build command.

    Attack class: Supply chain poisoning via write-then-build sequence.
    Source: PAT-01 build script patterns.
    """
    if trigger.tool_name != "Bash":
        return None
    command = (
        (trigger.tool_input.get("command") or "") if isinstance(trigger.tool_input, dict) else ""
    )
    if not _is_build_command(str(command)):
        return None

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    for event in reversed(recent[:-1]):
        if event.tool_name in ("Write", "Edit", "NotebookEdit"):
            fp = (
                (event.tool_input.get("file_path") or "")
                if isinstance(event.tool_input, dict)
                else ""
            )
            if _is_build_sensitive_target(str(fp)):
                return SequenceAlert(
                    rule_id="SEQ-004",
                    description=(
                        f"Write to build-sensitive target ({fp!r})"
                        f" followed by build command ({command[:80]!r})"
                    ),
                    session_id=session_id,
                    trigger_event=trigger,
                    context_window=recent,
                )
    return None


@_rule
def _agent_config_write(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-005 Tier 1: Write/Edit to agent config file = privilege escalation.

    Attack class: Agent configuration hijacking — the write itself IS the
    escalation (no sequence needed).
    CVEs: CVE-2025-53773 (Copilot YOLO mode), CVE-2025-59536 (Claude hooks
    injection), CVE-2025-54135 (CurXecute), AgentHopper.
    """
    if trigger.tool_name not in ("Write", "Edit", "NotebookEdit"):
        return None

    fp = (
        str(trigger.tool_input.get("file_path") or "")
        if isinstance(trigger.tool_input, dict)
        else ""
    )
    if not _is_agent_config(fp):
        return None

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    return SequenceAlert(
        rule_id="SEQ-005",
        description=(f"Privilege escalation: agent config write to {fp!r}"),
        session_id=session_id,
        trigger_event=trigger,
        context_window=recent,
    )


@_rule
def _pkg_git_config_then_build(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-005 Tier 2: pkg/git config write followed by build command.

    Attack class: Registry hijacking via config poisoning then build/install.
    Examples: .npmrc registry swap -> npm install, .git/config hooksPath -> make.
    """
    if trigger.tool_name != "Bash":
        return None
    command = (
        str(trigger.tool_input.get("command") or "") if isinstance(trigger.tool_input, dict) else ""
    )
    if not _is_build_command(command):
        return None

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    for event in reversed(recent[:-1]):
        if event.tool_name in ("Write", "Edit", "NotebookEdit"):
            fp = (
                str(event.tool_input.get("file_path") or "")
                if isinstance(event.tool_input, dict)
                else ""
            )
            if _is_pkg_git_config(fp):
                return SequenceAlert(
                    rule_id="SEQ-005",
                    description=(
                        f"Registry hijacking: pkg/git config write ({fp!r})"
                        f" followed by build command ({command[:80]!r})"
                    ),
                    session_id=session_id,
                    trigger_event=trigger,
                    context_window=recent,
                )
    return None


@_rule
def _bash_config_move(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-005 Tier 1b: Bash mv/cp to agent config path = privilege escalation.

    Attack class: Bypass of Tier 1 Write/Edit check by staging a malicious
    config in /tmp then moving it into place via Bash mv/cp.
    Source: ADV-015 adversarial finding.
    """
    if trigger.tool_name != "Bash":
        return None

    command = (
        str(trigger.tool_input.get("command") or "") if isinstance(trigger.tool_input, dict) else ""
    )

    if not _BASH_MV_CP_RE.search(command):
        return None

    # Extract everything after the mv/cp command to check for agent config targets.
    # Check against agent config patterns and MCP config regex.
    normalized = command.replace("\\", "/")
    for pattern in _AGENT_CONFIG_PATTERNS:
        if pattern in normalized:
            recent = list(buf)[-_LOOKBACK_WINDOW:]
            return SequenceAlert(
                rule_id="SEQ-005",
                description=(
                    f"Privilege escalation: Bash mv/cp to agent config"
                    f" ({pattern!r}) in command: {command[:80]!r}"
                ),
                session_id=session_id,
                trigger_event=trigger,
                context_window=recent,
            )

    # Check MCP config pattern against all words in the command
    for word in normalized.split():
        basename = word.rsplit("/", 1)[-1]
        if _AGENT_CONFIG_MCP_RE.match(basename):
            recent = list(buf)[-_LOOKBACK_WINDOW:]
            return SequenceAlert(
                rule_id="SEQ-005",
                description=(
                    f"Privilege escalation: Bash mv/cp to MCP config"
                    f" ({basename!r}) in command: {command[:80]!r}"
                ),
                session_id=session_id,
                trigger_event=trigger,
                context_window=recent,
            )

    return None


@_rule
def _sensitive_read_then_mcp_exfil(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-006: Sensitive file read followed by MCP tool with exfil-capable name.

    Attack class: Data exfiltration via MCP tool calls (email, messaging, PR
    comments, API posts) that bypass WebFetch/curl-based detection.
    Source: Invariant GitHub MCP, AgentFlayer (Zenity/Jira), Supabase MCP
    confused deputy. 46/89 InjecAgent+AgentDojo cases use this pattern.

    Advisory only -- not in _ENFORCEMENT_RULES until FPR validated.
    Uses typed markers -- survives arbitrary padding.
    """
    if not _is_mcp_exfil_tool(trigger.tool_name):
        return None

    # Check typed marker for prior sensitive file read
    sensitive_fp: str | None = None
    markers = _get_markers_for_rule(session_id)
    if markers and markers.last_sensitive_read:
        sensitive_fp = markers.last_sensitive_read.file_path
    else:
        # Fallback: lookback window
        recent = list(buf)[-_LOOKBACK_WINDOW:]
        for event in reversed(recent[:-1]):
            if event.tool_name == "Read":
                fp = str(
                    (event.tool_input.get("file_path") or "")
                    if isinstance(event.tool_input, dict)
                    else ""
                )
                if _is_sensitive_file(fp):
                    sensitive_fp = fp
                    break

    if sensitive_fp:
        return SequenceAlert(
            rule_id="SEQ-006",
            description=(
                f"Sensitive file read ({sensitive_fp!r}) followed by"
                f" MCP exfil-capable tool ({trigger.tool_name!r})"
            ),
            session_id=session_id,
            trigger_event=trigger,
            context_window=list(buf)[-_LOOKBACK_WINDOW:],
        )
    return None


# ---------------------------------------------------------------------------
# ToolCallMonitor
# ---------------------------------------------------------------------------


class ToolCallMonitor:
    """Behavioral sequence monitor for CloneGuard hook layer.

    Maintains a per-session ring buffer of recent tool events. On each new
    event, evaluates all registered sequence rules and writes JSONL alerts
    to ~/.cloneguard/monitor.log.

    Contract:
    - record_event() never raises (wrapped in try/except)
    - record_event() never writes to stdout
    - record_event() adds <0.5ms overhead per call
    - Log entries are JSONL with fields: ts, rule_id, description,
      session_id, trigger, context_window
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        if log_dir is None:
            log_dir = Path("~/.cloneguard").expanduser()

        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "monitor.log"

        # Open once in append+line-buffered mode. Never close until process exit
        # or explicit close() (for tests). Line buffering (buffering=1) ensures
        # each \n-terminated write flushes automatically without blocking on I/O.
        self._log_fh = open(log_path, "a", buffering=1, encoding="utf-8")  # noqa: SIM115

        # Per-session ring buffers, keyed by session_id.
        # OrderedDict provides O(1) oldest-entry eviction for LRU cap.
        self._sessions: OrderedDict[str, deque[ToolEvent]] = OrderedDict()

        # Per-session typed event markers (survive beyond lookback window).
        self._markers: dict[str, SessionMarkers] = {}

        # Defensive lock for thread safety (hooks may be called from multiple threads
        # in some agent configurations).
        self._lock = threading.Lock()

        # Sequence allowlist for enforcement escape hatch.
        self._sequence_allowlist: Any = None
        try:
            from cloneguard.sequence_allowlist import SequenceAllowlist  # noqa: F811

            self._sequence_allowlist = SequenceAllowlist()
        except Exception:
            pass

    def record_event(self, data: dict[str, Any]) -> None:
        """Record a hook event. Never raises; never writes to stdout.

        Args:
            data: Hook payload dict from Claude Code (JSON stdin).
        """
        try:
            self._record_event_inner(data)
        except Exception:
            pass  # Monitor MUST NOT raise into the hot path

    def _record_event_inner(self, data: dict[str, Any]) -> None:
        """Inner implementation, called within try/except in record_event."""
        alerts = self._process_event(data)
        for alert in alerts:
            self._log_alert(alert)

    def check_enforcement(self, data: dict[str, Any]) -> EnforcementVerdict | None:
        """Check if a tool call should be blocked by enforcement rules.

        Returns EnforcementVerdict if blocked, None if allowed.
        Also records the event and logs alerts (same as record_event).
        Never raises. Never writes to stdout.
        """
        try:
            return self._check_enforcement_inner(data)
        except Exception:
            return None

    def _check_enforcement_inner(self, data: dict[str, Any]) -> EnforcementVerdict | None:
        """Inner enforcement check — process event, log alerts, check for blocking."""
        alerts = self._process_event(data)
        verdict: EnforcementVerdict | None = None
        for alert in alerts:
            self._log_alert(alert)
            if alert.rule_id in _ENFORCEMENT_RULES and not self._is_sequence_allowed(alert):
                # First enforcement-eligible, non-allowlisted alert wins.
                if verdict is None:
                    verdict = EnforcementVerdict(
                        rule_id=alert.rule_id,
                        action="block",
                        description=alert.description,
                        session_id=alert.session_id,
                    )
        return verdict

    def _is_sequence_allowed(self, alert: SequenceAlert) -> bool:
        """Check if an alert is suppressed by the sequence allowlist."""
        if self._sequence_allowlist is None:
            return False
        if alert.rule_id in ("SEQ-001", "SEQ-002"):
            url = _extract_external_url(
                alert.trigger_event.tool_name, alert.trigger_event.tool_input
            )
            if url:
                try:
                    domain = urlparse(url).hostname or ""
                    return bool(self._sequence_allowlist.is_allowed(alert.rule_id, domain=domain))
                except Exception:
                    pass
        if alert.rule_id == "SEQ-005":
            fp = str(
                (alert.trigger_event.tool_input.get("file_path") or "")
                if isinstance(alert.trigger_event.tool_input, dict)
                else ""
            )
            if fp:
                return bool(self._sequence_allowlist.is_allowed(alert.rule_id, path=fp))
        return False

    def _process_event(self, data: dict[str, Any]) -> list[SequenceAlert]:
        """Parse event data, manage buffers/markers, evaluate rules. Returns alerts.

        Shared logic for both record_event and check_enforcement.
        """
        session_id = str(data.get("session_id") or "<unknown>")
        tool_use_id = str(data.get("tool_use_id") or "")
        tool_name = str(data.get("tool_name") or "")
        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}

        # Support both hook_event_name (official spec) and hook_type (legacy CloneGuard field).
        hook_event_name = str(data.get("hook_event_name") or data.get("hook_type") or "")

        event = ToolEvent(
            session_id=session_id,
            tool_use_id=tool_use_id,
            tool_name=tool_name,
            tool_input=tool_input,
            hook_event_name=hook_event_name,
        )

        alerts: list[SequenceAlert] = []

        with self._lock:
            # Get or create ring buffer for this session
            if session_id in self._sessions:
                # Move to end (most recently accessed) for LRU eviction order
                self._sessions.move_to_end(session_id)
                buf = self._sessions[session_id]
            else:
                buf = deque(maxlen=_MAX_SESSION_EVENTS)
                self._sessions[session_id] = buf
                # Evict oldest session if over cap
                if len(self._sessions) > _MAX_SESSIONS:
                    self._sessions.popitem(last=False)

            buf.append(event)

            # --- Typed marker updates (before rule evaluation) ---
            global _current_monitor  # noqa: PLW0603
            _current_monitor = self

            if session_id not in self._markers:
                self._markers[session_id] = SessionMarkers()
            markers = self._markers[session_id]

            # Sensitive file read marker
            if tool_name == "Read":
                fp = str(tool_input.get("file_path") or "")
                if _is_sensitive_file(fp):
                    markers.last_sensitive_read = MarkerEvent(
                        file_path=fp,
                        tool_use_id=event.tool_use_id,
                        ts=event.ts,
                    )

            # Config write marker (agent config or pkg/git config)
            if tool_name in ("Write", "Edit", "NotebookEdit"):
                fp = str(tool_input.get("file_path") or "")
                if _is_agent_config(fp) or _is_pkg_git_config(fp):
                    markers.last_config_write = MarkerEvent(
                        file_path=fp,
                        tool_use_id=event.tool_use_id,
                        ts=event.ts,
                    )

            # External fetch marker
            ext_url = _extract_external_url(tool_name, tool_input)
            if ext_url:
                markers.last_external_fetch = MarkerEvent(
                    url=ext_url,
                    tool_use_id=event.tool_use_id,
                    ts=event.ts,
                )

            # Build command marker
            if tool_name == "Bash":
                cmd = str(tool_input.get("command") or "")
                if _is_build_command(cmd):
                    markers.last_build_command = MarkerEvent(
                        command=cmd,
                        tool_use_id=event.tool_use_id,
                        ts=event.ts,
                    )

            # Evaluate sequence rules against updated buffer
            for rule_fn in _RULES:
                try:
                    alert = rule_fn(session_id, buf, event)
                    if alert is not None:
                        alerts.append(alert)
                except Exception:
                    pass  # Rule evaluation failure must not affect others

        return alerts

    def _log_alert(self, alert: SequenceAlert) -> None:
        """Write a JSONL log entry for the alert.

        Format: one JSON object per line, append-only to monitor.log.
        Log file is held open with line buffering — no per-call open/close.

        Note: This method runs inside _lock from _record_event_inner.
        The log write itself is non-blocking (OS kernel buffers the I/O).
        """
        entry = {
            "ts": _dt.datetime.now(_dt.UTC).isoformat(),
            "rule_id": alert.rule_id,
            "description": alert.description,
            "session_id": alert.session_id,
            "trigger": {
                "tool_name": alert.trigger_event.tool_name,
                "tool_use_id": alert.trigger_event.tool_use_id,
                "tool_input_summary": _summarize_input(alert.trigger_event),
            },
            "context_window": [
                {
                    "tool_name": e.tool_name,
                    "tool_use_id": e.tool_use_id,
                    "tool_input_summary": _summarize_input(e),
                }
                for e in alert.context_window
            ],
        }
        self._log_fh.write(json.dumps(entry) + "\n")
        # line-buffered mode: \n triggers automatic flush at OS level

    def get_session_markers(self, session_id: str) -> SessionMarkers | None:
        """Return typed markers for the given session, or None if not tracked."""
        with self._lock:
            return self._markers.get(session_id)

    def close(self) -> None:
        """Flush and close the log file handle. Primarily for test cleanup."""
        try:
            self._log_fh.flush()
            self._log_fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level marker accessor (for rules to use during evaluation)
# ---------------------------------------------------------------------------

_current_monitor: ToolCallMonitor | None = None


def _get_markers_for_rule(session_id: str) -> SessionMarkers | None:
    """Return session markers from the active monitor, if available.

    Used by sequence rules during evaluation to access persistent markers
    that survive beyond the lookback window.
    """
    if _current_monitor is None:
        return None
    return _current_monitor._markers.get(session_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_monitor: ToolCallMonitor | None = None
_monitor_lock = threading.Lock()


def get_monitor(log_dir: Path | None = None) -> ToolCallMonitor:
    """Return the module-level singleton ToolCallMonitor.

    Creates the monitor on first call. Subsequent calls return the same
    instance regardless of log_dir argument (log_dir only applies on init).

    Thread-safe.
    """
    global _monitor  # noqa: PLW0603
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = ToolCallMonitor(log_dir=log_dir)
    return _monitor
