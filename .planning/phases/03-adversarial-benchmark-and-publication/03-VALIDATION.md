---
phase: 3
slug: adversarial-benchmark-and-publication
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-10
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | pyproject.toml |
| **Quick run command** | `.venv/bin/python -m pytest tests/test_hardened_benchmark.py tests/test_latency.py -x -q` |
| **Full suite command** | `.venv/bin/python -m pytest tests/ -x -q` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `.venv/bin/python -m pytest tests/ -x -q`
- **After every plan wave:** Run `.venv/bin/python -m pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | BENCH-02 | schema validation (TDD) | `.venv/bin/python -m pytest tests/test_adaptive_benchmark.py -x -q` | Created in task (TDD) | pending |
| 03-01-02 | 01 | 1 | BENCH-02 | integration | `.venv/bin/python -m pytest tests/test_adaptive_benchmark.py -x -q && python3 -c "import json; d=json.load(open('docs/results/adaptive-pwws-benchmark-2026-03-10.json')); assert d['adaptive_asr'] != 0.20"` | depends on 03-01-01 | pending |
| 03-02-01 | 02 | 1 | BENCH-01, BENCH-03 | schema validation (TDD) | `.venv/bin/python -m pytest tests/test_correlated_failures.py tests/test_hardened_benchmark.py -x -q` | Created in task (TDD) | pending |
| 03-02-02 | 02 | 1 | BENCH-01, BENCH-03 | integration | `.venv/bin/python -m pytest tests/test_correlated_failures.py tests/test_hardened_benchmark.py -x -q` | depends on 03-02-01 | pending |
| 03-03-01 | 03 | 2 | BENCH-04 | framing audit (TDD) | `.venv/bin/python -m pytest tests/test_framing.py -x -q` | Created in task (TDD) | pending |
| 03-03-02 | 03 | 2 | BENCH-04 | framing audit | `.venv/bin/python -m pytest tests/test_framing.py -x -q` | depends on 03-03-01 | pending |
| 03-03-03 | 03 | 2 | BENCH-04 | manual | Human review of all publication outputs | N/A (checkpoint) | pending |

*Status: pending -- green -- red -- flaky*

---

## Wave 0 Requirements

All three missing test files are created within their respective plan's TDD tasks (RED-first):

- `tests/test_adaptive_benchmark.py` — created in Plan 03-01 Task 1 (TDD), covers BENCH-02 adaptive benchmark output schema
- `tests/test_correlated_failures.py` — created in Plan 03-02 Task 1 (TDD), covers BENCH-03 both-miss sample list schema
- `tests/test_framing.py` — created in Plan 03-03 Task 1 (TDD), covers BENCH-04 prohibited word check across markdown files

Existing `tests/test_hardened_benchmark.py` (15 tests) and `tests/test_latency.py` (6 tests) cover BENCH-01 output schema — no gap.

*Wave 0 is satisfied: each TDD task creates its test file before implementation.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Framing language audit | BENCH-04 | Requires human judgment on tone/framing beyond prohibited words | `grep -rni "prevents\|blocks\|secure" docs/SECURITY.md docs/MINI-SEMANTIC-MODEL.md docs/publications/` — must return 0 matches in benchmark sections |
| Publication venue assessment | User request | Subjective editorial judgment | Review claims against methodology, assess conference fit |
| LinkedIn/Medium content | User request | Creative writing + editorial | Review drafts for accuracy, tone, honest framing |
| HuggingFace model card draft | BENCH-04 | Requires human approval before HF push | Review `docs/publications/hf-model-card-v4-draft.md` for v4 numbers and framing |
| v0.3.0 release notes | BENCH-04 | Requires human approval before tagging | Review `docs/publications/v0.3.0-release-notes.md` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (TDD tasks create test files)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated
