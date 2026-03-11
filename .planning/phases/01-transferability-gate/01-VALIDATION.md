---
phase: 1
slug: transferability-gate
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-10
audited: 2026-03-10
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.0.2 |
| **Config file** | pyproject.toml |
| **Quick run command** | `pytest tests/test_transfer_experiment.py -x -q` |
| **Full suite command** | `pytest tests/ -x -q` |
| **Estimated runtime** | ~1 second (validation tests); experiment script ~5-30 min depending on corpus size |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -x -q` (existing suite — no regressions)
- **After every plan wave:** Run experiment script dry-run: `python scripts/transfer_experiment.py --dry-run --limit 5`
- **Before `/gsd:verify-work`:** Full experiment run must complete with results JSON written
- **Max feedback latency:** 1 second (validation tests); experiment is long-running by nature

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 0 | XFER-01 | setup | `source .venv-transfer/bin/activate && python -c "import textattack"` | N/A (env) | ✅ green |
| 01-01-02 | 01 | 1 | XFER-01 | unit | `pytest tests/test_transfer_experiment.py -v -k "script or cli or wrapper"` | ✅ | ✅ green |
| 01-01-03 | 01 | 1 | XFER-02 | unit | `pytest tests/test_transfer_experiment.py -v -k "wilson or schema"` | ✅ | ✅ green |
| 01-01-04 | 01 | 2 | XFER-01,02 | integration | Full experiment run (manual — 30-90 min) | N/A | ✅ green (completed) |
| 01-01-05 | 01 | 2 | XFER-03 | unit | `pytest tests/test_transfer_experiment.py -v -k "gate or threshold"` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `.venv-transfer/` — isolated venv with `textattack==0.3.10`, `transformers<5.0`, `torch`
- [x] NLTK data: `wordnet`, `averaged_perceptron_tagger`, `omw-1.4`
- [x] ProtectAI DeBERTa model prefetched to HuggingFace cache
- [x] `scripts/transfer_experiment.py` — experiment script (986 lines)

*Existing test infrastructure (`pytest`, `tests/`) covers regression checking.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Gate decision is intellectually honest | XFER-03 | Requires human judgement on framing | Review results doc for honest disclosure of limitations, proxy-vs-fine-tuned caveat |
| Results published with full methodology | XFER-03 | Publication quality check | Verify transfer rate, attack method, proxy identity, and limitations are all disclosed |
| Full experiment execution (185 samples) | XFER-01, XFER-02 | 30-90 min runtime, requires .venv-transfer | Run `.venv-transfer/bin/python scripts/transfer_experiment.py` — completed 2026-03-10 |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s (validation tests: 0.75s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** complete

---

## Validation Audit 2026-03-10

| Metric | Count |
|--------|-------|
| Gaps found | 3 |
| Resolved | 3 |
| Escalated | 0 |

**Tests added:** `tests/test_transfer_experiment.py` (25 tests)
- XFER-01: 9 tests (script structure, CLI flags, wrapper output shape)
- XFER-02: 9 tests (wilson_ci_95 pure function, output schema validation)
- XFER-03: 7 tests (gate decision logic, threshold constant, boundary semantics)

All 25 tests pass in main venv without requiring .venv-transfer dependencies.
