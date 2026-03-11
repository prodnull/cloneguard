---
phase: 5
slug: fpr-tuning
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-11
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
| 05-01-T1a | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "mode" -x` | ❌ W0 | ⬜ pending |
| 05-01-T1b | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "sliding_window_mode" -x` | ❌ W0 | ⬜ pending |
| 05-01-T1c | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "env_var" -x` | ❌ W0 | ⬜ pending |
| 05-01-T1d | 01 | 1 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "strict_threshold_unchanged" -x` | ❌ W0 | ⬜ pending |
| 05-01-T1e | 01 | 1 | FPR-02 | integration | `.venv/bin/python scripts/calibrate_thresholds.py --verify` | ❌ W0 | ⬜ pending |
| 05-02-T1a | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_hooks.py -k "mode" -x` | ❌ W0 | ⬜ pending |
| 05-02-T1b | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/test_hooks.py -k "mode_threading" -x` | ❌ W0 | ⬜ pending |
| 05-02-T2a | 02 | 2 | FPR-01 | unit | `.venv/bin/python -m pytest tests/ -k "scanner" -x` | ❌ W0 | ⬜ pending |
| 05-02-T2b | 02 | 2 | FPR-02 | integration | `.venv/bin/python scripts/calibrate_thresholds.py` | ❌ W0 | ⬜ pending |
| 05-02-T2c | 02 | 2 | FPR-01/02 | regression | `.venv/bin/python -m pytest tests/ -x -q` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_mini_semantic.py` — add mode-aware classify() tests, sliding window mode tests, env var override tests, strict threshold guard tests
- [ ] `tests/test_hooks.py` — add mode threading tests for _classify_with_tier15()
- [ ] `scripts/calibrate_thresholds.py` — new calibration script (does not exist)

*Existing test infrastructure (pytest, conftest.py) covers framework requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Combined pipeline FPR meets roadmap targets | FPR-02 | Requires full benign corpus + both tiers | Run `scripts/calibrate_thresholds.py` and verify combined FPR table |
| Honest per-tier reporting if targets unmet | FPR-02 | Judgment call on Tier 0 floor | Review calibration output; confirm per-tier breakdown is documented |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
