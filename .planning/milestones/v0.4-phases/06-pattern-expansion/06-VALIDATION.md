---
phase: 6
slug: pattern-expansion
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-11
validated: 2026-03-12
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest (existing) |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `.venv/bin/python -m pytest tests/test_new_patterns.py tests/test_log_to_leak.py -x -q` |
| **Full suite command** | `.venv/bin/python -m pytest tests/ -q --tb=short` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `.venv/bin/python -m pytest tests/test_new_patterns.py tests/test_log_to_leak.py -x -q`
- **After every plan wave:** Run `.venv/bin/python -m pytest tests/ -q --tb=short`
- **Before `/gsd:verify-work`:** Full suite must be green + `calibrate_thresholds.py --verify`
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 06-01-01 | 01 | 1 | PAT-02 | unit | `.venv/bin/python -m pytest tests/test_log_to_leak.py -x -q` | ✅ | ✅ green (18/18 passed) |
| 06-01-02 | 01 | 1 | PAT-01 | unit | `.venv/bin/python -m pytest tests/test_new_patterns.py -x -q` | ✅ | ✅ green (74/74 passed) |
| 06-01-03 | 01 | 1 | PAT-01 | regression | `.venv/bin/python -m pytest tests/ -q --tb=short` | ✅ | ✅ green (1186 passed, 13 skipped) |
| 06-02-01 | 02 | 2 | FPR | integration | `.venv/bin/python scripts/calibrate_thresholds.py --verify` | ✅ | ✅ green (workflow 18.9% < 24%) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `tests/test_log_to_leak.py` — 18 tests for PAT-02 (LTL-001 through LTL-004, benign TN)
- [x] `src/cloneguard/rules/log_to_leak.yaml` — Log-To-Leak category with 4 patterns

*All other test infrastructure exists. No new framework installation required.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s (full suite ~56s, pattern tests ~4s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-03-12 by Nyquist auditor
