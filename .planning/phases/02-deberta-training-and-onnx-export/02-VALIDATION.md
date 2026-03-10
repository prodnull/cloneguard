---
phase: 2
slug: deberta-training-and-onnx-export
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x |
| **Config file** | `pyproject.toml` `[tool.pytest.ini_options]` |
| **Quick run command** | `uv run pytest tests/test_mini_semantic.py tests/test_mahalanobis.py -x -q` |
| **Full suite command** | `uv run pytest tests/ -x -q` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/test_mini_semantic.py tests/test_mahalanobis.py -x -q`
- **After every plan wave:** Run `uv run pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 0 | HARD-01 | unit | `pytest tests/test_augmentation.py -x` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 0 | HARD-02 | integration | `pytest tests/test_train_freelb.py -x` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 0 | HARD-03 | unit | `pytest tests/test_mahalanobis.py -x` | ❌ W0 | ⬜ pending |
| 02-01-04 | 01 | 0 | HARD-04 | integration | `pytest tests/test_hardened_benchmark.py -x` | ❌ W0 | ⬜ pending |
| 02-01-05 | 01 | 0 | HARD-05 | integration | `pytest tests/test_latency.py -x` | ❌ W0 | ⬜ pending |
| 02-xx-xx | TBD | 1 | HARD-01 | unit | `pytest tests/test_augmentation.py::test_augmentation_schema -x` | ❌ W0 | ⬜ pending |
| 02-xx-xx | TBD | 1 | HARD-02 | unit | `pytest tests/test_train_freelb.py::test_freelb_gradient_accumulation -x` | ❌ W0 | ⬜ pending |
| 02-xx-xx | TBD | 2 | HARD-03 | integration | `pytest tests/test_mahalanobis.py::test_threshold_fpr -x` | ❌ W0 | ⬜ pending |
| 02-xx-xx | TBD | 2 | HARD-03 | unit | `pytest tests/test_mini_semantic.py::test_anomaly_fields -x` | ❌ W0 | ⬜ pending |
| 02-xx-xx | TBD | 3 | HARD-05 | unit | `pytest tests/test_mini_semantic.py::test_onnx_output_order -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_augmentation.py` — stubs for HARD-01 augmentation schema and provenance tracking
- [ ] `tests/test_train_freelb.py` — stubs for HARD-02 FreeLB integration (smoke + gradient test)
- [ ] `tests/test_mahalanobis.py` — stubs for HARD-03 Mahalanobis module (fit, threshold, score)
- [ ] `tests/test_hardened_benchmark.py` — stubs for HARD-04 benchmark output schema
- [ ] `tests/test_latency.py` — stubs for HARD-05 latency gate

*All five test files are new. Existing `tests/test_mini_semantic.py` must be extended with `test_anomaly_fields` and `test_onnx_output_order` tests when v4 ONNX is available.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| PWWS attack rounds produce meaningful adversarial examples | HARD-01 | Requires TextAttack in `.venv-transfer` + subjective quality review | Run `scripts/run_pwws_augmentation.py`, inspect 10 random outputs |
| FreeLB full training convergence | HARD-02 | Multi-hour GPU run, loss curve inspection | Monitor training logs, verify loss decreases monotonically |
| Mahalanobis threshold calibration on real data | HARD-03 | Requires fitted model + real embeddings | Run calibration script, verify FPR at threshold |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
