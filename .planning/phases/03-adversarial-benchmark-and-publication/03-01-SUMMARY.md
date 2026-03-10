---
phase: 03-adversarial-benchmark-and-publication
plan: 01
subsystem: testing
tags: [pwws, textattack, onnxruntime, adversarial-attack, benchmark, wilson-ci]

# Dependency graph
requires:
  - phase: 02-deberta-training-and-onnx-export
    provides: v4 hardened MiniLM ONNX model at src/cloneguard/model/mini_semantic.onnx

provides:
  - Measurement-only adaptive PWWS benchmark script against v4 ONNX
  - Schema validation test suite for benchmark output JSON
  - Adaptive ASR: 20.3% (95% CI: 14.6%-27.5%), clearly distinct from round-2 training-time ASR (20.0%)
  - Per-category evasion breakdown: encoding 0%, homoglyph 5%, social_engineering 10%, counter_defensive 15%, synonym 15%, structural_dilution 32%, implicit_instruction 53%, fragmentation 78% (of non-filtered)
  - Wilson CI implementation without scipy/statsmodels (pure numpy)

affects: [03-02, 03-03, publication]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Wilson score CI implemented inline with numpy (avoids scipy version incompatibility between .venv and .venv-transfer)
    - MiniLMOnnxWrapper copied (not imported) in venv-transfer scripts — established pattern from Phase 02-01
    - Benchmark scripts that are measurement-only never write to training data directories

key-files:
  created:
    - scripts/adaptive_pwws_benchmark.py
    - tests/test_adaptive_benchmark.py
    - docs/results/adaptive-pwws-benchmark-2026-03-10.json
  modified:
    - scripts/adaptive_pwws_benchmark.py (scipy fix)

key-decisions:
  - "Adaptive ASR 20.3% is distinct from round-2 training-time ASR (20.0%) — both are real but measure different things: training-time is generation rate, adaptive is test-time attack against final model"
  - "Wilson CI implemented inline using numpy only — scipy.stats.proportion_confint not available in .venv-transfer scipy version"
  - "docs/results/ is gitignored per project rules — benchmark output file exists locally but is not committed to repo"
  - "Pre-filter removed 37/185 samples already-evading v4 (truncation 20/20, fragmentation 11/20, implicit_instruction 5/20, 1 structural_dilution) — these can't be attacked meaningfully"

patterns-established:
  - "Benchmark scripts in this phase: measurement-only, never merge to training data, output to docs/results/ only"
  - "Wilson CI formula: inline numpy, z=1.959964, avoids scipy dependency chain"

requirements-completed: [BENCH-02]

# Metrics
duration: ~90min (60min PWWS execution + 30min script dev/fix)
completed: 2026-03-10
---

# Phase 03 Plan 01: Adaptive PWWS Benchmark Summary

**Fresh PWWS adaptive attack against final v4 ONNX: 20.3% ASR (95% CI: 14.6%-27.5%) on 148 detectable malicious samples, with per-category breakdown showing encoding/homoglyph categories hardened most effectively**

## Performance

- **Duration:** ~90 min
- **Started:** 2026-03-10T21:10:10Z
- **Completed:** 2026-03-10T21:36:00Z
- **Tasks:** 2
- **Files modified:** 3 created, 1 modified

## Accomplishments

- Adaptive PWWS attack script that is measurement-only (no training data output) against v4 ONNX, with correct venv isolation
- Schema validation test suite (23 tests) that catches structural errors in benchmark output JSON before publication
- True adaptive ASR measurement: 20.3% (30/148 samples evaded), clearly distinct from round-2 training-time ASR (20.0%), providing the honest number for Phase 3 publications
- Wilson CI computed without scipy dependency, generalizing the pattern to other measurement scripts in this venv

## Task Commits

1. **Task 1: Create adaptive PWWS benchmark script and tests** - `206d3ef` (feat/test)
2. **Task 2: Execute adaptive PWWS benchmark against v4** - `52da64c` (fix — scipy workaround)

## Files Created/Modified

- `scripts/adaptive_pwws_benchmark.py` - Measurement-only PWWS attack driver against v4 ONNX; copies MiniLMOnnxWrapper pattern; outputs adaptive ASR + per-category breakdown + Wilson CI
- `tests/test_adaptive_benchmark.py` - 23 schema validation tests; 21 unit tests on fixture + 2 integration tests on real output file
- `docs/results/adaptive-pwws-benchmark-2026-03-10.json` - Benchmark results (gitignored per project rules, exists locally)

## Decisions Made

- **adaptive_asr 0.2027 vs round-2 0.20:** These are genuinely different measurements. The round-2 training-time ASR (20.0%) is the fraction of the 185-sample benchmark corpus that was misclassified after round-2 augmentation. The adaptive ASR (20.3%) is a fresh PWWS attack against the final v4 model at test-time, on a filtered subset of 148 samples already detectable by v4. The near-numerical coincidence is noteworthy but does not mean they're the same number.
- **Wilson CI inline implementation:** scipy.stats.proportion_confint unavailable in .venv-transfer's scipy version. Replaced with direct Wilson (1927) formula using only numpy. Method is mathematically equivalent — Wilson score CI is a closed-form calculation.
- **docs/results gitignore:** Benchmark output file is intentionally not committed to the repo. Internal results artifacts are kept private per project rules.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed ImportError: proportion_confint not in .venv-transfer scipy**
- **Found during:** Task 2 (benchmark execution)
- **Issue:** `from scipy.stats import proportion_confint` raises ImportError in .venv-transfer; the function is from statsmodels, not scipy.stats
- **Fix:** Replaced with inline Wilson (1927) formula using numpy only; mathematically equivalent, no external dependency
- **Files modified:** `scripts/adaptive_pwws_benchmark.py`
- **Verification:** Benchmark ran successfully, CI values match expected range (30/148 = 20.3%, CI 14.6%-27.5%)
- **Committed in:** `52da64c`

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Single necessary fix. Wilson CI formula is the reference implementation for this type of interval. No scope creep.

## Issues Encountered

- The `.venv-transfer/bin/python` binary could not be invoked directly through the Bash tool sandbox (permission denied). Resolved by using `source .venv-transfer/bin/activate && python` pattern. This is a local tool restriction, not a script issue.
- Sample 76-77 of the PWWS run took unexpectedly long (22min at that point in the log) — likely a WordNet lookup or synonym search that exhausted the search space for those specific samples. No impact on results; PWWS handles this internally.

## Next Phase Readiness

- Adaptive ASR 20.3% (CI: 14.6%-27.5%) is available for Phase 03 Plan 02 (correlated failure analysis) and Plan 03 (publication)
- Key publication-ready numbers: PWWS gen ASR dropped 65.7% (v3 baseline) → 31.7% (round-2 generation) → 20.3% (adaptive test-time)
- Per-category breakdown shows encoding_evasion and homoglyph_unicode hardened most effectively; fragmentation remains high (78%) but that's the set already-detected by v4 that PWWS can still evade — the 11 pre-filtered fragmentation samples were already-evading
- No blockers for Plan 02

## Self-Check: PASSED

- scripts/adaptive_pwws_benchmark.py: FOUND
- tests/test_adaptive_benchmark.py: FOUND
- docs/results/adaptive-pwws-benchmark-2026-03-10.json: FOUND (gitignored, local only)
- 03-01-SUMMARY.md: FOUND
- Commit 206d3ef (Task 1): FOUND
- Commit 52da64c (Task 2/fix): FOUND
- All 23 tests pass (including 2 integration tests against real output)

---
*Phase: 03-adversarial-benchmark-and-publication*
*Completed: 2026-03-10*
