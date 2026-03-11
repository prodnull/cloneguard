---
phase: 05-fpr-tuning
plan: 01
subsystem: classifier
tags: [mini_semantic, ScanMode, thresholds, FPR, calibration, onnx]

requires:
  - phase: 04-fpr-investigation
    provides: "Phase 4 empirical FPR data (benign_eval_751.json, per-content-type Tier 1.5 FPR)"

provides:
  - "_DEFAULT_THRESHOLDS dict in mini_semantic.py: STRICT=(0.5,0.8) LENIENT, STANDARD=(0.65,0.88), LENIENT=(0.75,0.92)"
  - "_get_thresholds(mode) function with env var overrides at call time"
  - "mode: ScanMode parameter on classify(), _classify_sliding_window(), _scan_lines(), classify_files()"
  - "scripts/calibrate_thresholds.py: sweep script producing FPR recommendation table"
  - "22 new tests covering per-mode thresholds, env var overrides, and mode threading"

affects:
  - "05-02-PLAN.md: hooks.py mode threading depends on this threshold table"
  - "Phase 6: Tier 0 pattern tuning — per-tier FPR baseline is now established"

tech-stack:
  added: []
  patterns:
    - "_get_thresholds(mode) pattern: per-ScanMode threshold lookup with env var overrides at call time"
    - "mode: ScanMode = ScanMode.STANDARD default on all Tier 1.5 classify methods (backward-compatible)"
    - "Threshold calibration via raw ONNX probability sweep (not model retraining)"

key-files:
  created:
    - "scripts/calibrate_thresholds.py"
  modified:
    - "src/cloneguard/mini_semantic.py"
    - "tests/test_mini_semantic.py"

key-decisions:
  - "STANDARD=(0.65, 0.88) and LENIENT=(0.75, 0.92) confirmed by calibration sweep: Tier 1.5 FPR drops from 8.5% to 7.3% (STANDARD) and 5.5% (LENIENT) overall"
  - "Default mode=ScanMode.STANDARD on classify() for backward-compatibility: existing callers that don't pass mode get slightly more lenient thresholds (intended behavior)"
  - "Combined pipeline FPR improvement is honest but modest: workflow stays at 30.2% (STANDARD) due to Tier 0 CI-001 floor at ~23.9% — Tier 0 fixes deferred to Phase 6"
  - "Sliding window uses same per-mode thresholds as single-chunk (no offset needed): calibration confirms model is consistent across chunk lengths"

patterns-established:
  - "_get_thresholds(mode): reads os.environ at call time (not module load) — pattern for all future threshold-related env vars"
  - "LOCKED comment on STRICT threshold: 'LOCKED: Do not modify — per Phase 5 CONTEXT.md'"
  - "Calibration sweep as empirical evidence: threshold values in code are backed by scripts/calibrate_thresholds.py output, not estimates"

requirements-completed: [FPR-01, FPR-02]

duration: 45min
completed: 2026-03-11
---

# Phase 5 Plan 01: FPR Tuning — Threshold Calibration Summary

**Per-ScanMode threshold table in mini_semantic.py with STRICT locked at (0.5, 0.8), STANDARD=(0.65, 0.88) and LENIENT=(0.75, 0.92) derived from calibration sweep — reduces Tier 1.5 FPR from 8.5% to 7.3%/5.5% overall**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-03-11T05:00:00Z
- **Completed:** 2026-03-11T05:45:00Z
- **Tasks:** 1 (TDD: 3 commits — test/feat/calibration)
- **Files modified:** 3

## Accomplishments

- Implemented `_DEFAULT_THRESHOLDS` dict with empirically-derived values for all three ScanModes
- Added `_get_thresholds(mode)` reading env var overrides at call time (not module load) — supports test patching and zero-restart runtime config
- Threaded `mode: ScanMode` through `classify()`, `_classify_sliding_window()`, `_scan_lines()`, and `classify_files()` — 4 call sites updated
- Wrote `scripts/calibrate_thresholds.py` that sweeps 7x7=49 threshold pairs across 757 benign samples, extracts raw ONNX probabilities, and produces per-content-type FPR table with `--verify` flag for combined pipeline check
- 22 new tests (from 1,089 to 1,111 passing, zero regressions)

## Calibration Results

Tier 1.5 FPR from calibration sweep (`data/benchmark/benign_eval_751.json`, n=757):

| Mode | Suspicious Thresh | Malicious Thresh | Overall FPR | Workflow | Agent_Instructions | Test_File |
|------|-----------------|-----------------|-------------|---------|-------------------|-----------|
| STRICT (locked) | 0.50 | 0.80 | 8.5% | 14% | 8% | 16% |
| STANDARD (chosen) | 0.65 | 0.88 | 7.3% | 11% | 6% | 14% |
| LENIENT (chosen) | 0.75 | 0.92 | 5.5% | 9% | 4% | 11% |

Combined Tier 0 + Tier 1.5 FPR at STANDARD thresholds (--verify output):
- agent_instructions: 18.4% | workflow: 30.2% | test_file: 19.5% | overall: 18.4%

**Honest reporting (per CONTEXT.md):** Tier 0 FPR on workflows is ~23.9% (CI-001 GitHub Actions expressions — a structural floor). Phase 5 Tier 1.5 tuning reduces the Tier 1.5 contribution but cannot reach the combined 24% roadmap target for workflows. Tier 0 fixes are deferred to Phase 6.

## Task Commits

TDD execution — three commits for the single task:

1. **RED — Failing tests** - `a296417` (test): 22 new tests for per-mode thresholds, env var overrides, mode parameter threading
2. **GREEN — Implementation** - `74e34e1` (feat): _DEFAULT_THRESHOLDS, _get_thresholds(), mode parameter on all 4 classify methods
3. **Calibration script** - `f852ce7` (feat): scripts/calibrate_thresholds.py with threshold sweep and --verify flag

## Files Created/Modified

- `src/cloneguard/mini_semantic.py` — Added `_DEFAULT_THRESHOLDS`, `_get_thresholds()`, `mode` parameter on `classify()`, `_classify_sliding_window()`, `_scan_lines()`, `classify_files()`
- `tests/test_mini_semantic.py` — 22 new test functions covering all threshold behaviors, env var overrides, mode threading, boundary conditions (mocked ONNX)
- `scripts/calibrate_thresholds.py` — New calibration script: threshold sweep, probability distribution by content type, combined pipeline FPR with `--verify`

## Decisions Made

- **STANDARD=(0.65, 0.88):** Calibration confirms this eliminates ~15% of benign samples from Tier 1.5 flagging (those in the 0.50-0.65 probability bucket) while preserving sensitivity to clear attacks. The `0.5-0.65` band contains 2% of agent_instructions, 3.1% of workflow, and 1.8% of test_file samples — all benign noise.
- **LENIENT=(0.75, 0.92):** Additional 2% improvement for test/fixture contexts where attack surface is low. Appropriate for content that Tier 0 already de-prioritizes.
- **mode=STANDARD as default:** Backward-compatible for existing callers (hooks.py, scanner.py) that don't yet pass mode — they'll get the improved thresholds automatically. Plan 02 will add explicit mode threading for precise per-file control.
- **No sliding window threshold offset:** Calibration probability distribution is consistent across chunk lengths — worst-chunk probabilities for benign content don't systematically exceed the single-chunk probability. Same thresholds apply to both paths.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None. Calibration script ran cleanly on first attempt. The pre-commit hook caught two style issues in the test file (unsorted import, unused import) — fixed inline before commit.

## Next Phase Readiness

- Per-mode threshold system is live and tested
- Plan 02 (`05-02-PLAN.md`) can now wire ScanMode from hooks.py (`_classify_with_tier15()`) and scanner.py (`_run_tier2()`) into `classify()` and `classify_files()` — the receiving signatures are ready
- Calibration results are the empirical basis for Phase 6 Tier 0 pattern tuning scope decisions

---
*Phase: 05-fpr-tuning*
*Completed: 2026-03-11*
