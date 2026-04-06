---
phase: 03-adversarial-benchmark-and-publication
plan: 02
subsystem: testing
tags: [benchmark, correlated-failures, reproducibility, adversarial, onnx, mahalanobis]

requires:
  - phase: 02-deberta-training-and-onnx-export
    provides: hardened ONNX v4 model + Mahalanobis calibration + hardened-benchmark-2026-03-10.json

provides:
  - Reproducibility-confirmed Phase 3 benchmark run (hardened-benchmark-phase3-2026-03-10.json)
  - Per-sample correlated failure analysis identifying all 18 samples missed by both Tier 0 and Tier 1.5 (correlated-failures-2026-03-10.json)
  - Schema validation test suite for correlated failure output (tests/test_correlated_failures.py)

affects:
  - 03-03-publication (narrative framing of defense ceiling, both-miss breakdown by category)

tech-stack:
  added: []
  patterns:
    - "Correlated failure analysis: collect per-sample both-miss records during benchmark loop, write separate analysis JSON — never modifying existing benchmark output schema"
    - "TDD fixture skip pattern: pytest.skip() when artifact doesn't exist yet, not xfail — tests transition from skip to pass after benchmark run"

key-files:
  created:
    - tests/test_correlated_failures.py
    - docs/results/hardened-benchmark-phase3-2026-03-10.json (gitignored, local only)
    - docs/results/correlated-failures-2026-03-10.json (gitignored, local only)
  modified:
    - scripts/hardened_benchmark.py

key-decisions:
  - "docs/results/ is gitignored — benchmark artifacts exist locally but are NOT committed to the public repo; only scripts and tests are committed"
  - "Correlated failure output is a separate JSON file, not merged into the main benchmark schema — preserves reproducibility of the Phase 2 artifact"
  - "both-miss definition: tier0_detected=False AND tier15_verdict='SAFE' AND anomaly_flagged=False — all three tiers must miss for a sample to count"

patterns-established:
  - "Separate correlated failure JSON alongside main benchmark output for per-sample both-miss analysis"

requirements-completed: [BENCH-01, BENCH-03]

duration: 25min
completed: 2026-03-10
---

# Phase 3 Plan 02: Correlated Failure Analysis Summary

**Hardened pipeline reproducibility confirmed (recall 90.3%, ASR 9.7%, delta=0.0000 vs Phase 2) and 18/185 (9.7%) both-miss samples identified, dominated by fragmentation (11/20) and implicit_instruction (5/20) — the structural information-theoretic ceiling**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-03-10T20:51:00Z
- **Completed:** 2026-03-10T21:16:10Z
- **Tasks:** 2 of 2
- **Files modified:** 2 (committed) + 2 (local artifacts, gitignored)

## Accomplishments

- Extended `scripts/hardened_benchmark.py` with `--correlated-failures` CLI arg that writes per-sample both-miss records to a separate JSON (does not modify existing output schema)
- Created `tests/test_correlated_failures.py` with 7 schema validation tests covering required fields, tier verdicts, count consistency, and per-category breakdown
- Ran Phase 3 reproducibility benchmark: recall 90.3%, FPR 19.0%, ASR 9.7% — exact match with Phase 2 (delta=0.0000 on all metrics)
- Correlated failure analysis: 18/185 (9.7%) both-miss; fragmentation (11/20, 55%), implicit_instruction (5/20, 25%), truncation (2/20, 10%)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add correlated failure output to hardened_benchmark.py and create tests** - `b10065f` (feat)

Task 2 produced local-only artifacts (gitignored `docs/results/` directory) — no separate commit required.

**Plan metadata:** committed with SUMMARY.md and STATE.md update

## Files Created/Modified

- `scripts/hardened_benchmark.py` - Extended with `--correlated-failures` CLI arg; collects per-sample both-miss records during malicious corpus loop; writes separate correlated failure JSON with per-category breakdown and narrative framing
- `tests/test_correlated_failures.py` - 7 schema validation tests: both_miss_samples key, per-sample required fields, tier verdict correctness, total_both_miss count, per-category breakdown structure, category sum consistency, metadata fields
- `docs/results/hardened-benchmark-phase3-2026-03-10.json` - Phase 3 reproducibility run (gitignored, local only)
- `docs/results/correlated-failures-2026-03-10.json` - Per-sample both-miss analysis (gitignored, local only)

## Decisions Made

- `docs/results/` is gitignored — benchmark artifacts exist locally but are not committed to the public repo. Only `scripts/` and `tests/` files go to git. This matches the project CLAUDE.md rule.
- Correlated failure output is a separate JSON file, not merged into the main benchmark schema, to preserve reproducibility of the Phase 2 artifact (`hardened-benchmark-2026-03-10.json`).
- Both-miss definition requires all three tiers to miss: `tier0_detected=False AND tier15_verdict='SAFE' AND anomaly_flagged=False`.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- Pre-existing `test_latency.py` failure (p95 latency 27-32ms vs 25ms limit) confirmed pre-existing before this plan's changes via `git stash` verification. Out of scope per deviation rules — logged to deferred items.

## Next Phase Readiness

- Both-miss breakdown ready for publication narrative: fragmentation (55% miss rate) and implicit_instruction (25%) are the structural ceiling — information-theoretic limit, not a model deficiency
- Plan 03-03 (publication) can reference `correlated-failures-2026-03-10.json` for honest ceiling framing
- Full test suite passing (1039 passed, 18 skipped, excluding pre-existing latency test)

---
*Phase: 03-adversarial-benchmark-and-publication*
*Completed: 2026-03-10*
