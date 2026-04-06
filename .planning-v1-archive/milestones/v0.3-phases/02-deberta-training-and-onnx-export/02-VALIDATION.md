---
phase: 2
slug: deberta-training-and-onnx-export
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-10
audited: 2026-03-10
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.0.2 |
| **Config file** | `pyproject.toml` `[tool.pytest.ini_options]` |
| **Quick run command** | `uv run pytest tests/test_augmentation.py tests/test_train_freelb.py tests/test_mahalanobis.py tests/test_hardened_benchmark.py tests/test_latency.py -x -q` |
| **Full suite command** | `uv run pytest tests/ -x -q` |
| **Estimated runtime** | ~5 seconds (phase 2 tests only) |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/test_mini_semantic.py tests/test_mahalanobis.py -x -q`
- **After every plan wave:** Run `uv run pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 0 | HARD-01 | unit | `pytest tests/test_augmentation.py -x` | ✅ | ✅ green |
| 02-01-02 | 01 | 0 | HARD-02 | integration | `pytest tests/test_train_freelb.py -x` | ✅ | ✅ green |
| 02-01-03 | 01 | 0 | HARD-03 | unit | `pytest tests/test_mahalanobis.py -x` | ✅ | ✅ green |
| 02-01-04 | 01 | 0 | HARD-04 | integration | `pytest tests/test_hardened_benchmark.py -x` | ✅ | ✅ green |
| 02-01-05 | 01 | 0 | HARD-05 | integration | `pytest tests/test_latency.py -x` | ✅ | ✅ green |
| 02-02-01 | 02 | 1 | HARD-01 | unit | `pytest tests/test_augmentation.py::test_jsonl_schema_has_required_fields -x` | ✅ | ✅ green |
| 02-02-02 | 02 | 1 | HARD-02 | unit | `pytest tests/test_train_freelb.py::test_freelb_optimizer_stepped_once -x` | ✅ | ✅ green |
| 02-03-01 | 03 | 2 | HARD-03 | integration | `pytest tests/test_mahalanobis.py::TestMahalanobisThreshold::test_fpr_at_most_5pct -x` | ✅ | ✅ green |
| 02-03-02 | 03 | 2 | HARD-03 | unit | `pytest tests/test_latency.py::TestDualOutputOnnxShape -x` | ✅ | ✅ green |
| 02-03-03 | 03 | 3 | HARD-05 | unit | `pytest tests/test_latency.py::TestTier15MahalanobisLatency -x` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `tests/test_augmentation.py` — 6 tests for HARD-01 augmentation schema and provenance tracking
- [x] `tests/test_train_freelb.py` — 7 tests for HARD-02 FreeLB integration (smoke + gradient + ONNX output)
- [x] `tests/test_mahalanobis.py` — 9 tests for HARD-03 Mahalanobis module (fit, threshold, score, save/load)
- [x] `tests/test_hardened_benchmark.py` — 11 tests for HARD-04 benchmark output schema and values
- [x] `tests/test_latency.py` — 4 tests for HARD-05 latency gate and dual-output ONNX shape

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| PWWS attack rounds produce meaningful adversarial examples | HARD-01 | Requires TextAttack in `.venv-transfer` + subjective quality review | Completed 2026-03-10: 88 r1 + 44 r2 adversarial examples with provenance |
| FreeLB full training convergence | HARD-02 | Multi-hour GPU run, loss curve inspection | Completed 2026-03-10: 2 rounds, loss decreased, 5-fold CV 94.51% |
| Mahalanobis threshold calibration on real data | HARD-03 | Requires fitted model + real embeddings | Completed 2026-03-10: threshold=20.78, FPR 1.19%, detection rate 2.7% (honestly disclosed) |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s (phase tests: ~5s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** complete

---

## Validation Audit 2026-03-10

| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |

All 5 requirements (HARD-01 through HARD-05) already had automated test coverage:
- `test_augmentation.py`: 6 tests (HARD-01)
- `test_train_freelb.py`: 7 tests (HARD-02)
- `test_mahalanobis.py`: 9 tests (HARD-03)
- `test_hardened_benchmark.py`: 11 tests (HARD-04)
- `test_latency.py`: 4 tests (HARD-05)

Total: 37 tests, all green. No new tests needed.
