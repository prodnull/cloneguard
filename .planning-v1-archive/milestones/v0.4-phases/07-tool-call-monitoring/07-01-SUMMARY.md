---
phase: 07-tool-call-monitoring
plan: 01
subsystem: monitoring
tags: [behavioral-monitoring, tool-call-sequence, camel-lite, jsonl-logging, deque, stdlib, prompt-injection]

# Dependency graph
requires:
  - phase: 06-pattern-expansion
    provides: "hooks.py handler structure — PreToolUse/PostToolUse dispatch pattern used as integration model"
provides:
  - "ToolCallMonitor class with SEQ-001 through SEQ-004 sequence rules"
  - "JSONL alert log at ~/.cloneguard/monitor.log"
  - "get_monitor() singleton for hook integration in Plan 02"
affects:
  - "07-02 (hook integration): get_monitor().record_event(data) call points in hooks.py"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Module-level singleton with lazy init (same pattern as _engine in hooks.py)"
    - "OrderedDict for LRU session eviction without external dependencies"
    - "Rule registry via @_rule decorator — adds new rules by defining a function"
    - "JSONL append-only log opened once at init with line buffering (buffering=1)"
    - "try/except wrap on entire record_event — monitor failure never surfaces to hot path"

key-files:
  created:
    - src/cloneguard/monitor.py
    - tests/test_monitor.py
  modified: []

key-decisions:
  - "SEQ-003 threshold is >5 (strictly greater than 5); exactly 5 calls does NOT fire — chosen to avoid FPR on MCP tools with standard polling patterns"
  - "record_event uses try/except at outer and inner rule level — double containment ensures zero propagation even from rule bugs"
  - "Log file opened once in __init__ with buffering=1 (line-buffered) — avoids per-event open/close latency that would violate 5ms constraint"
  - "datetime.UTC alias used (Python 3.11+) per ruff UP017 — project targets Python 3.14"
  - "Callable imported from collections.abc not typing per ruff UP035 — correct for Python 3.9+"

patterns-established:
  - "Rule pattern: each sequence rule is a typed function registered via @_rule decorator — add rules by adding functions"
  - "Stdout cleanliness: monitor writes exclusively to file handle, never to sys.stdout"
  - "Session isolation: sequence rules operate over single-session buffers — cross-session contamination is structurally impossible"

requirements-completed:
  - TCM-01

# Metrics
duration: 9min
completed: 2026-03-12
---

# Phase 07 Plan 01: Tool Call Monitor Summary

**Stdlib-only ToolCallMonitor with four sequence rules (SEQ-001 through SEQ-004) detecting Log-To-Leak exfiltration, curl-based exfiltration, MCP frequency spikes, and write-then-build supply chain patterns — JSONL-logged, non-blocking, <0.5ms overhead.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-12T19:03:31Z
- **Completed:** 2026-03-12T19:12:03Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- ToolCallMonitor with per-session ring buffers (deque maxlen=50, OrderedDict cap=200) observing all tool call sequences
- Four sequence rules covering the highest-value attack classes from 07-RESEARCH.md: SEQ-001 (Log-To-Leak via WebFetch), SEQ-002 (curl/wget exfiltration), SEQ-003 (MCP frequency spike per AdapTools pattern), SEQ-004 (write-then-build supply chain)
- JSONL alert log with analyst-readable structure (ts, rule_id, description, session_id, trigger, context_window) written to ~/.cloneguard/monitor.log
- 37 unit tests: all 4 rules fire/no-fire, latency (<5ms), stdout cleanliness, log structure validation, session isolation, LRU eviction
- Zero new dependencies — pure stdlib (collections, json, datetime, threading, re, urllib.parse)

## Task Commits

1. **Task 1: ToolCallMonitor + tests (TDD RED+GREEN)** — `70e3d57` (feat)
2. **Task 2: Lint/typecheck/isolation verification** — `76a8649` (chore)

## Files Created/Modified

- `src/cloneguard/monitor.py` — ToolCallMonitor class, ToolEvent/SequenceAlert dataclasses, SEQ-001 through SEQ-004 rules, get_monitor() singleton, JSONL log
- `tests/test_monitor.py` — 37 unit tests covering all sequence rules, latency, stdout safety, log structure, session management, helper functions

## Decisions Made

- SEQ-003 fires at >5 calls (strictly greater), not >=5 — avoids FPR on MCP tools that legitimately poll 5 times
- Double try/except containment in record_event: outer wraps entire method, inner wraps each rule evaluation individually
- datetime.UTC alias used per ruff UP017 (Python 3.11+ feature, project is Python 3.14)
- Log opened once in __init__ with buffering=1 (line-buffered text mode) — no per-event open/close, no explicit flush needed

## Deviations from Plan

None — plan executed exactly as written. TDD RED/GREEN/LINT flow followed in order. Lint issues (import ordering, line length, unused imports) surfaced by pre-commit hook and fixed inline during Task 1 before final commit.

## Issues Encountered

Pre-commit ruff hook caught 42 lint issues on first commit attempt (import ordering, E501 line lengths, unused imports, E741 ambiguous variable names). All fixed inline without requiring a deviation rule — standard lint-before-commit workflow. No functional issues.

## User Setup Required

None — monitor.py creates ~/.cloneguard/ at first init if not present. No external services, no env vars, no credentials.

## Next Phase Readiness

- `get_monitor()` singleton exported and ready for Plan 02 hook integration
- `record_event(data)` interface matches Claude Code hook payload schema (supports both `hook_event_name` and legacy `hook_type` fields)
- Plan 02 integration: add `get_monitor().record_event(data)` at top of `handle_pre_tool_use` and `handle_post_tool_use` in hooks.py
- No blockers

---
*Phase: 07-tool-call-monitoring*
*Completed: 2026-03-12*
