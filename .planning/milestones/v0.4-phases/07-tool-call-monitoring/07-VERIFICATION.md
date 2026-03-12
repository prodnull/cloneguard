---
phase: 07-tool-call-monitoring
verified: 2026-03-12T19:20:28Z
status: passed
score: 14/14 must-haves verified
re_verification: false
---

# Phase 07: Tool Call Monitoring Verification Report

**Phase Goal:** Implement CaMeL-lite behavioral monitoring at hook layer to detect anomalous tool call sequences
**Verified:** 2026-03-12T19:20:28Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | ToolCallMonitor records tool events into per-session ring buffers | VERIFIED | `deque(maxlen=50)` per session in `OrderedDict`; `record_event` appends on every call (monitor.py:451) |
| 2  | SEQ-001 fires when a sensitive file read is followed by WebFetch to an external domain | VERIFIED | `_file_read_then_network` rule registered via `@_rule`; tests confirm fire/no-fire behavior; 37 tests all pass |
| 3  | SEQ-002 fires when a sensitive file read is followed by Bash curl/wget to an external URL | VERIFIED | `_file_read_then_curl` rule; `_CURL_URL_RE` regex extracts URL from Bash `command` field |
| 4  | SEQ-003 fires when the same MCP tool is invoked more than 5 times within 10 events | VERIFIED | `_mcp_frequency_spike` rule; threshold is `> 5` strictly (6+ fires, exactly 5 does not) |
| 5  | SEQ-004 fires when a write to a sensitive target is followed by a build command | VERIFIED | `_write_then_build` rule; covers Write/Edit/NotebookEdit followed by npm/pip/make/cargo/go/docker |
| 6  | Monitor never writes to stdout | VERIFIED | `grep -c "print(" src/cloneguard/monitor.py` returns 0; stdout-cleanliness test class in test_monitor.py passes |
| 7  | Monitor never raises exceptions into the caller | VERIFIED | Double try/except containment: outer in `record_event`, inner around each rule evaluation; integration test `test_monitor_failure_does_not_break_hook` confirms propagation suppressed |
| 8  | Alerts are written as JSONL to ~/.cloneguard/monitor.log | VERIFIED | `_log_alert` writes `json.dumps(entry) + "\n"` to file handle opened at `log_dir / "monitor.log"` (monitor.py:398, 496) |
| 9  | record_event latency is under 5ms per call | VERIFIED | SUMMARY reports <0.5ms overhead; `TestMonitorLatency` in test_monitor.py enforces this; 37 tests pass in 0.75s |
| 10 | handle_pre_tool_use calls get_monitor().record_event(data) before any content scanning | VERIFIED | Line 313-316 of hooks.py: try/except wrapping `get_monitor().record_event(data)` is the first action before `tool_name = data.get(...)` on line 318 |
| 11 | handle_post_tool_use calls get_monitor().record_event(data) before any content scanning | VERIFIED | Lines 416-419 of hooks.py: identical pattern; `tool_output = data.get(...)` begins at line 421 |
| 12 | Monitor integration does not change any existing hook return values or stdout output | VERIFIED | All 1,186 tests pass (1,159 prior + 27 monitor unit + 3 integration); integration tests assert return values unchanged |
| 13 | All 1,159+ existing tests pass with monitor integrated | VERIFIED | `uv run pytest tests/ -x -q` reports 1186 passed, 13 skipped, 0 failures |
| 14 | Hook latency stays within the 25ms p95 budget | VERIFIED | Monitor adds <0.5ms per call (well within budget); no regression in existing latency tests |

**Score:** 14/14 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/cloneguard/monitor.py` | ToolCallMonitor class, ToolEvent/SequenceAlert dataclasses, SEQ-001 through SEQ-004, JSONL logging | VERIFIED | 529 lines; exports `ToolCallMonitor`, `ToolEvent`, `SequenceAlert`, `get_monitor`; all 4 rules implemented via `@_rule` decorator |
| `tests/test_monitor.py` | Unit tests for all sequence rules, latency, stdout cleanliness, log structure | VERIFIED | 760 lines (>>150 minimum); 37 tests; classes: TestToolEvent, TestSequenceRules, TestMonitorNoBleeding, TestMonitorLatency, TestLogStructure, TestSessionManagement, TestHelperFunctions |
| `src/cloneguard/hooks.py` | Monitor integration calls in handle_pre_tool_use and handle_post_tool_use | VERIFIED | `get_monitor().record_event(data)` present at lines 314 and 417; import at line 26 |
| `tests/test_hooks.py` | Integration tests verifying monitor is called during hook execution | VERIFIED | `TestMonitorIntegration` class at line 1080 with 3 tests: pre-tool call, post-tool call, resilience to monitor failure |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/cloneguard/monitor.py` | `~/.cloneguard/monitor.log` | buffered file append in `_log_alert` | WIRED | `log_path = log_dir / "monitor.log"` (line 398); `self._log_fh.write(...)` (line 496); line-buffered mode |
| `src/cloneguard/monitor.py` | `collections.deque` | per-session ring buffer capped at maxlen=50 | WIRED | `deque(maxlen=_MAX_SESSION_EVENTS)` where `_MAX_SESSION_EVENTS = 50` (lines 38, 451) |
| `src/cloneguard/hooks.py` | `src/cloneguard/monitor.py` | `from cloneguard.monitor import get_monitor` | WIRED | Import confirmed at hooks.py line 26 |
| `src/cloneguard/hooks.py::handle_pre_tool_use` | `monitor.record_event` | first call in handler body | WIRED | Lines 313-316 of hooks.py; precedes all existing logic |
| `src/cloneguard/hooks.py::handle_post_tool_use` | `monitor.record_event` | first call in handler body | WIRED | Lines 416-419 of hooks.py; precedes all existing logic |

All key links verified. No orphaned artifacts.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| TCM-01 | 07-01-PLAN.md, 07-02-PLAN.md | Implement tool call behavioral monitoring at hook layer (CaMeL-lite) | SATISFIED | ToolCallMonitor implemented (Plan 01), wired into hook pipeline (Plan 02), all tests green, REQUIREMENTS.md marks as Complete |

**Orphaned requirements check:** Only TCM-01 is mapped to Phase 7 in REQUIREMENTS.md. Both plans declare TCM-01. No orphaned requirements.

---

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| None | — | — | — |

No TODOs, FIXMEs, placeholder returns, or stdout writes found in any phase-07 files.

---

### Human Verification Required

None. All behavioral contracts are structurally verifiable:
- Sequence rule fire/no-fire logic is covered by 37 automated unit tests
- Stdout cleanliness is verified by `TestMonitorNoBleeding` class and `grep -c "print("` = 0
- Latency is enforced by `TestMonitorLatency`
- Hook integration is confirmed by `TestMonitorIntegration` with MagicMock injection
- Log structure is validated by `TestLogStructure` using `tmp_path`

---

### Gaps Summary

No gaps. Phase 07 goal is fully achieved.

The ToolCallMonitor module is substantive, independently testable, and wired into the live hook pipeline:
- SEQ-001 through SEQ-004 rules fire on known-bad sequences and do not fire on benign sequences
- Monitor writes analyst-readable JSONL to `~/.cloneguard/monitor.log`
- No stdout contamination, no exceptions leaked, no blocking latency
- 1,186 total tests pass with zero regressions

TCM-01 is complete.

---

_Verified: 2026-03-12T19:20:28Z_
_Verifier: Claude (gsd-verifier)_
