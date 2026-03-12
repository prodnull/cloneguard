"""ToolCallMonitor — behavioral sequence monitoring for CloneGuard.

Observes tool call sequences within a session and fires structured alerts
when patterns consistent with prompt-injection-driven exfiltration or
lateral movement are detected.

Design contract (see docs/research/v04-direction-research-2026-03-10.md):
- LOGGING ONLY — never blocks tool calls (blocking is Tier 0/1.5's job)
- NEVER writes to stdout (stdout is the hook communication channel)
- NEVER raises from record_event (monitor failure must not block agents)
- Adds <0.5ms overhead per hook event (well within 25ms p95 budget)

Sequence rules implemented:
- SEQ-001: Read(sensitive file) -> WebFetch(external URL) within 10 events
- SEQ-002: Read(sensitive file) -> Bash(curl/wget external URL) within 10 events
- SEQ-003: mcp__* tool called >5 times within 10 events (frequency spike)
- SEQ-004: Write(sensitive target) -> Bash(build command) within 10 events
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

# Sensitive file path substrings (lowercased). Matches credential-bearing files.
_SENSITIVE_FILE_PATTERNS = (
    ".env",
    "secret",
    "credential",
    "password",
    "token",
    "key",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
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


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_sensitive_file(file_path: str) -> bool:
    """Return True if file_path may contain credentials or PII.

    Matches against well-known sensitive file name patterns. Case-insensitive.
    Heuristic: false negatives possible for unusual naming conventions.
    """
    fp = file_path.lower()
    return any(p in fp for p in _SENSITIVE_FILE_PATTERNS)


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

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    for event in reversed(recent[:-1]):  # exclude trigger itself
        if event.tool_name == "Read":
            fp = (
                (event.tool_input.get("file_path") or "")
                if isinstance(event.tool_input, dict)
                else ""
            )
            if _is_sensitive_file(str(fp)):
                return SequenceAlert(
                    rule_id="SEQ-001",
                    description=(
                        f"Sensitive file read ({fp!r}) followed by"
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

    recent = list(buf)[-_LOOKBACK_WINDOW:]
    for event in reversed(recent[:-1]):
        if event.tool_name == "Read":
            fp = (
                (event.tool_input.get("file_path") or "")
                if isinstance(event.tool_input, dict)
                else ""
            )
            if _is_sensitive_file(str(fp)):
                return SequenceAlert(
                    rule_id="SEQ-002",
                    description=(
                        f"Sensitive file read ({fp!r}) followed by"
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

        # Defensive lock for thread safety (hooks may be called from multiple threads
        # in some agent configurations).
        self._lock = threading.Lock()

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

            # Evaluate sequence rules against updated buffer
            for rule_fn in _RULES:
                try:
                    alert = rule_fn(session_id, buf, event)
                    if alert is not None:
                        self._log_alert(alert)
                except Exception:
                    pass  # Rule evaluation failure must not affect others

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

    def close(self) -> None:
        """Flush and close the log file handle. Primarily for test cleanup."""
        try:
            self._log_fh.flush()
            self._log_fh.close()
        except Exception:
            pass


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
