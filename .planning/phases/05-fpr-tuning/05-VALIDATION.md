---
phase: 5
slug: fpr-tuning
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-11
validated: 2026-03-12
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | `pyproject.toml` — `[tool.pytest.ini_options]` |
| **Quick run command** | `.venv/bin/python -m pytest tests/test_mini_semantic.py tests/test_hooks.py -x -q` |
| **Full suite command** | `.venv/bin/python -m pytest tests/ -x -q` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `.venv/bin/python -m pytest tests/test_mini_semantic.py tests/test_hooks.py -x -q`
- **After every plan wave:** Run `.venv/bin/python -m pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 05-01-T1a | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "mode" -x` | tests/test_mini_semantic.py | green |
| 05-01-T1b | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "sliding_window" -x` | tests/test_mini_semantic.py | green |
| 05-01-T1c | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "env_var" -x` | tests/test_mini_semantic.py | green |
| 05-01-T1d | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "strict_threshold" -x` | tests/test_mini_semantic.py | green |
| 05-01-T1e | 01 | 1 | FPR-02 | unit | `.venv/bin/python -m pytest tests/test_phase5_validation.py::TestCalibrationScriptExists -x` | tests/test_phase5_validation.py | green |
| 05-02-T1a | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_hooks.py -k "ModeDetection" -x` | tests/test_hooks.py | green |
| 05-02-T1b | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_hooks.py -k "ModeThreading" -x` | tests/test_hooks.py | green |
| 05-02-T2a | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_phase5_validation.py::TestScannerThreadsMode -x` | tests/test_phase5_validation.py | green |
| 05-02-T2b | 02 | 2 | FPR-02 | integration | `.venv/bin/python scripts/calibrate_thresholds.py --verify` | scripts/calibrate_thresholds.py | manual |
| 05-02-T2c | 02 | 2 | FPR-01/02 | regression | `.venv/bin/python -m pytest tests/ -x -q --ignore=tests/test_latency.py` | tests/ | green |
| 05-W0-G1 | W0 | 0 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_phase5_validation.py::TestScanLinesThreadsMode -x` | tests/test_phase5_validation.py | green |
| 05-W0-G2 | W0 | 0 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_phase5_validation.py::TestClassifyFilesModePropagation -x` | tests/test_phase5_validation.py | green |

*Status: pending / green / red / flaky / manual*

---

## Wave 0 Requirements

- [x] `tests/test_mini_semantic.py` — mode-aware classify() tests, sliding window mode tests, env var override tests, strict threshold guard tests (22 tests added during Phase 5 execution)
- [x] `tests/test_hooks.py` — mode threading tests for _classify_with_tier15() (16 tests in TestModeDetectionEnhanced + TestModeThreadingHooks)
- [x] `scripts/calibrate_thresholds.py` — calibration script exists and is valid Python
- [x] `tests/test_phase5_validation.py` — Nyquist gap-fill: _scan_lines mode threading, scanner mode threading, classify_files mode propagation, calibration script validation (8 tests)

*Existing test infrastructure (pytest, conftest.py) covers framework requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Combined pipeline FPR meets roadmap targets | FPR-02 | Requires full benign corpus + both tiers | Run `scripts/calibrate_thresholds.py --verify` and verify combined FPR table |
| Honest per-tier reporting if targets unmet | FPR-02 | Judgment call on Tier 0 floor | Review calibration output; confirm per-tier breakdown is documented |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 45s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated (2026-03-12, Nyquist auditor)
