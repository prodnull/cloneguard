---
phase: 05-fpr-tuning
plan: 02
subsystem: classifier
tags: [hooks, scanner, ScanMode, mode-detection, FPR, three-signal, content-markers]

requires:
  - phase: 05-fpr-tuning-plan-01
    provides: "Per-ScanMode threshold table in mini_semantic.py: STRICT=(0.5,0.8), STANDARD=(0.65,0.88), LENIENT=(0.75,0.92) with mode param on all classify() methods"

provides:
  - "_detect_mode_for_tier15(): three-signal mode detection (path primary + hook_default + content markers) in hooks.py"
  - "_classify_with_tier15() mode: ScanMode parameter threading to classifier.classify()"
  - "InstructionsLoaded hook: hook_default=STRICT minimum; PostToolUse/PreToolUse: path-derived mode"
  - "scanner.py _run_tier2(): explicit ScanMode.STANDARD passed to classify_files()"
  - "Content marker rules: agent instruction marker upgrades to STRICT; workflow/CI markers confirm STANDARD (no upgrade); no downgrade ever"
  - "Combined pipeline FPR measured and reported: STANDARD agent_instructions=18.4%, workflow=30.2%"

affects:
  - "Phase 6: Tier 0 pattern tuning — workflow 30.2% FPR floor is confirmed Tier 0 CI-001 structural issue"

tech-stack:
  added: []
  patterns:
    - "_detect_mode_for_tier15(): path is primary signal; hook_default is fallback when path returns STANDARD; content markers upgrade toward STRICT only"
    - "Three-signal mode detection: hook_default (floor for InstructionsLoaded), path (primary), content markers (upgrade only)"
    - "ScanMode threading end-to-end: hooks -> _classify_with_tier15() -> classify(mode=mode)"

key-files:
  created: []
  modified:
    - "src/cloneguard/hooks.py"
    - "src/cloneguard/scanner.py"
    - "tests/test_hooks.py"

key-decisions:
  - "Path is primary signal for mode detection: LENIENT (test/) and STRICT (CLAUDE.md) from path win over hook_default. Hook_default applies only when path returns STANDARD (no strong path signal)"
  - "Content markers upgrade only, never downgrade: agent instruction marker (# Instructions) -> STRICT upgrade; workflow/CI markers confirm STANDARD, do not upgrade or downgrade"
  - "Scanner repo-wide scans use ScanMode.STANDARD: hook handlers address per-file STRICT/LENIENT; scanner batch context is STANDARD"
  - "Combined FPR 30.2% on workflows is the honest result: Tier 0 CI-001 structural floor (23.9%) prevents reaching 24% target. Deferred to Phase 6"

patterns-established:
  - "_detect_mode_for_tier15(source_path, content, hook_default): canonical three-signal pattern for future hook additions"
  - "Mock test setup: configure mock_engine._detect_mode.return_value explicitly when testing mode threading through _get_engine()"

requirements-completed: [FPR-01, FPR-02]

duration: 9min
completed: 2026-03-11
---

# Phase 5 Plan 02: FPR Tuning — Mode Threading Summary

**ScanMode threaded end-to-end through hooks.py and scanner.py with three-signal mode detection (path primary + hook_default + content markers), completing the per-context threshold pipeline; combined pipeline FPR confirmed at 18.4% (agent_instructions) and 30.2% (workflow, Tier 0 floor)**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-03-11T05:31:17Z
- **Completed:** 2026-03-11T05:40:21Z
- **Tasks:** 2 (Task 1: TDD with 3 commits; Task 2: feat + verification)
- **Files modified:** 3

## Accomplishments

- Implemented `_detect_mode_for_tier15()` with three-signal mode detection: path (primary), hook_default (fallback when path=STANDARD), content markers (upgrade only)
- Updated `_classify_with_tier15()` to accept and forward `mode: ScanMode` to `classifier.classify()`
- All three hook handlers (InstructionsLoaded, PostToolUse, PreToolUse) now derive and pass ScanMode; InstructionsLoaded enforces STRICT as hook_default minimum
- Updated `scanner.py _run_tier2()` to pass `mode=ScanMode.STANDARD` to `classify_files()` explicitly
- 16 new tests (5 mode detection, 5 threading mock tests + 1 helper); all 1,124 tests pass (16 skipped)
- Combined pipeline FPR verified via `--verify`: agent_instructions 18.4%, workflow 30.2%

## Calibration Results

Combined Tier 0 + Tier 1.5 FPR (benign_eval_751.json, n=757):

| Mode | agent_instructions | workflow | test_file | overall |
|------|-------------------|---------|-----------|---------|
| STANDARD | 18.4% | 30.2% | 19.5% | 18.4% |
| LENIENT | 16.3% | 27.7% | 17.2% | 16.8% |

**Honest reporting:** Workflow 30.2% at STANDARD reflects the Tier 0 CI-001 structural floor (~23.9% from GitHub Actions expression patterns). Phase 5 Tier 1.5 tuning reduces the Tier 1.5 contribution but cannot reach the combined 24% roadmap target for workflows. Tier 0 fixes are deferred to Phase 6.

agent_instructions at 18.4% is below the 33% roadmap target — that target is met.

## Task Commits

TDD execution for Task 1 (3 commits) + Task 2 (1 commit):

1. **RED — Failing tests** - `4a1b53b` (test): 16 new tests for _detect_mode_for_tier15() and mode threading in all three hook handlers
2. **GREEN — Implementation** - `e1fecf8` (feat): _detect_mode_for_tier15(), updated _classify_with_tier15() signature, three hook handler call sites updated
3. **Task 2 — scanner.py** - `1fb221d` (feat): ScanMode.STANDARD threaded to classify_files() in _run_tier2()

## Files Created/Modified

- `src/cloneguard/hooks.py` — Added `_detect_mode_for_tier15()`, `_WORKFLOW_MARKER`/`_AGENT_INSTRUCTION_MARKER`/`_CI_CONFIG_MARKER` regexes, updated `_classify_with_tier15()` signature, updated all three hook handlers to derive and pass ScanMode
- `src/cloneguard/scanner.py` — Pass `mode=ScanMode.STANDARD` to `mini.classify_files()` in `_run_tier2()`
- `tests/test_hooks.py` — 16 new test functions: 5 in `TestModeDetectionEnhanced`, 5 in `TestModeThreadingHooks` (with helper `_make_engine_mock()`), plus updated mock setup to configure `_detect_mode.return_value`

## Decisions Made

- **Path is primary signal:** When path says LENIENT (test/) or STRICT (CLAUDE.md), path wins over hook_default. Hook_default applies only when path returns STANDARD. This preserves accurate LENIENT detection for test fixtures in PostToolUse.
- **Content markers upgrade only:** Agent instruction marker (`# Instructions`) upgrades to STRICT; workflow/CI markers (`on:`, `jobs:`, `stages:`) confirm STANDARD but do not upgrade or downgrade.
- **Scanner uses STANDARD explicitly:** Repo-wide batch scans are STANDARD context by definition. Hook handlers address the per-file STRICT/LENIENT cases; passing explicit `mode=ScanMode.STANDARD` makes intent clear.
- **Honest FPR reporting for workflows:** 30.2% combined FPR on workflows is a correct outcome given the Tier 0 CI-001 floor. Per CONTEXT.md Pitfall 4 guidance, this is documented as a structural limit to be addressed in Phase 6.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] RED tests used un-mocked _get_engine() in threading tests**
- **Found during:** Task 1 GREEN phase
- **Issue:** The mock tests patching `_get_engine` configured `mock_engine` but did not set `mock_engine._detect_mode.return_value`. When `_detect_mode_for_tier15()` called `_get_engine()._detect_mode()`, it received a MagicMock instead of a ScanMode, causing a `KeyError` in the rank lookup dict.
- **Fix:** Added `_make_engine_mock(detect_mode_return)` helper to `TestModeThreadingHooks` that properly configures `mock_engine._detect_mode.return_value` and `mock_engine.scan.return_value`. Updated all 5 threading tests to use this helper.
- **Files modified:** `tests/test_hooks.py`
- **Committed in:** `e1fecf8` (Task 1 GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug in test mock setup)
**Impact on plan:** Minor test infrastructure fix required during GREEN phase. No scope creep; no production code changes beyond plan.

## Issues Encountered

- Pre-commit hook caught two long lines in test file during RED phase (>100 chars). Fixed inline before commit — standard lint compliance.
- Initial `_detect_mode_for_tier15()` implementation used `max(hook_default, path_mode, content_mode)` across all three signals, which caused STANDARD hook_default to dominate LENIENT path results. Fixed by making path the primary signal and applying hook_default only when path returns STANDARD (the ambiguous case).

## Next Phase Readiness

- Per-context threshold system is now live end-to-end in production code paths
- Phase 6 (Tier 0 pattern tuning) should target CI-001 to address workflow FPR floor (~23.9%)
- Calibration results from `scripts/calibrate_thresholds.py --verify` provide the Phase 6 baseline: workflow combined FPR 30.2% at STANDARD

## Self-Check: PASSED

- FOUND: src/cloneguard/hooks.py (contains _detect_mode_for_tier15)
- FOUND: src/cloneguard/scanner.py (contains classify_files.*mode)
- FOUND: tests/test_hooks.py (contains TestModeDetectionEnhanced, TestModeThreadingHooks)
- FOUND: commit 4a1b53b (test RED)
- FOUND: commit e1fecf8 (feat GREEN)
- FOUND: commit 1fb221d (feat scanner)

---
*Phase: 05-fpr-tuning*
*Completed: 2026-03-11*
