---
phase: 7
slug: tool-call-monitoring
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-12
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | `pyproject.toml` — `[tool.pytest.ini_options]` |
| **Quick run command** | `uv run pytest tests/test_monitor.py -x -q` |
| **Full suite command** | `uv run pytest tests/ -x -q` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/test_monitor.py -x -q`
- **After every plan wave:** Run `uv run pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 07-01-01 | 01 | 0 | TCM-01 | unit | `uv run pytest tests/test_monitor.py -x -q` | ✅ | ✅ green |
| 07-01-02 | 01 | 1 | TCM-01a | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq001_fires -x` | ✅ | ✅ green |
| 07-01-03 | 01 | 1 | TCM-01b | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq002_fires -x` | ✅ | ✅ green |
| 07-01-04 | 01 | 1 | TCM-01c | unit | `uv run pytest tests/test_monitor.py::TestSequenceRules::test_seq003_mcp_frequency -x` | ✅ | ✅ green |
| 07-01-05 | 01 | 1 | TCM-01d | unit | `uv run pytest tests/test_monitor.py::TestMonitorLatency -x` | ✅ | ✅ green |
| 07-01-06 | 01 | 1 | TCM-01e | unit | `uv run pytest tests/test_monitor.py::TestMonitorNoBleeding -x` | ✅ | ✅ green |
| 07-01-07 | 01 | 1 | TCM-01f | unit | `uv run pytest tests/test_monitor.py::TestLogStructure -x` | ✅ | ✅ green |
| 07-02-01 | 02 | 2 | TCM-01g | integration | `uv run pytest tests/test_hooks.py -x -q` | ✅ | ✅ green |
| 07-02-02 | 02 | 2 | TCM-01h | regression | `uv run pytest tests/ -q --ignore=tests/test_latency.py` | ✅ | ✅ green |
| NYQ-001 | 01 | — | SEQ-004 Edit/NotebookEdit | unit | `uv run pytest tests/test_monitor_nyquist.py::TestSeq004EditVariants -x` | ✅ | ✅ green |
| NYQ-002 | 01 | — | Build target coverage | unit | `uv run pytest tests/test_monitor_nyquist.py::TestBuildSensitiveTargets -x` | ✅ | ✅ green |
| NYQ-003 | 01 | — | Build command coverage | unit | `uv run pytest tests/test_monitor_nyquist.py::TestBuildCommands -x` | ✅ | ✅ green |
| NYQ-004 | 01 | — | Summarize input truncation | unit | `uv run pytest tests/test_monitor_nyquist.py::TestSummarizeInput -x` | ✅ | ✅ green |
| NYQ-005 | 01 | — | Lookback window boundary | unit | `uv run pytest tests/test_monitor_nyquist.py::TestLookbackWindowBoundary -x` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_monitor.py` — stubs for TCM-01a through TCM-01f
- [ ] `src/cloneguard/monitor.py` — new module scaffold (ToolCallMonitor class, ToolEvent, SequenceAlert dataclasses)

*Wave 0 creates the test file and module scaffold before implementation.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Monitor log readable by `jq` | TCM-01 | Requires human inspection of log format | Run monitor against test sequence, then `jq . ~/.cloneguard/monitor.log` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated (Nyquist auditor, 2026-03-12)
