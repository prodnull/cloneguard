---
phase: 06-pattern-expansion
plan: 01
subsystem: patterns
tags: [regex, yaml, log-to-leak, cicd, fpr-tuning, pattern-engine]

# Dependency graph
requires:
  - phase: 05-fpr-tuning
    provides: ScanMode threading through scanner/hooks, CI-001 FPR floor identified as deferred Phase 6 work
provides:
  - Log-To-Leak exfiltration category (logToLeak) with 4 patterns (LTL-001 through LTL-004)
  - CI-001 restricted to strict mode — workflow FPR floor eliminated from STANDARD mode
  - 65 gap-category patterns confirmed correct (PAT-01 met at 65 > 51 target)
  - Full test suite green at 1143 tests
affects: [06-02, fpr-benchmark, v0.4-release]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "modes: [strict] on patterns with >10% FPR on benign content in non-agent files"
    - "LTL triple-conjunction regex (verb + scope-qualifier + data-noun) for exfiltration framing"
    - "localhost/127.0.0.1 exemption in URL-matching patterns"

key-files:
  created:
    - src/cloneguard/rules/log_to_leak.yaml
    - tests/test_log_to_leak.py
  modified:
    - src/cloneguard/rules/cicd_poisoning.yaml
    - tests/test_new_patterns.py
    - tests/test_integration_all_patterns.py
    - README.md
    - docs/SECURITY.md
    - docs/MINI-SEMANTIC-MODEL.md
    - docs/TESTING-AND-VALIDATION.md

key-decisions:
  - "CI-001 moved to modes: [strict] — Option B from RESEARCH.md — consistent with CI-004/CI-006 convention; CI-002 owns the run-context case in all modes"
  - "LTL-004 compliance-framed exfiltration is strict-only — high FPR risk on legitimate compliance documentation in STANDARD mode"
  - "Pattern count updated to 197 (193 + 4 LTL) across 25 categories in all public docs"

patterns-established:
  - "Deviation Rule 3: doc consistency pre-commit hook is a gate — update pattern count claims in all docs before committing new YAML patterns"
  - "Integration test PAYLOADS registry: strict-only patterns must use STRICT-mode file paths (CLAUDE.md), not workflow paths"

requirements-completed: [PAT-01, PAT-02]

# Metrics
duration: 6min
completed: 2026-03-11
---

# Phase 6 Plan 01: Pattern Expansion — Log-To-Leak and CI-001 FPR Fix Summary

**Log-To-Leak exfiltration category (4 patterns, LTL-001 through LTL-004) added; CI-001 restricted to strict mode eliminating the 23.9% workflow Tier 0 FPR floor; 65 gap-category patterns confirmed; test suite green at 1143 tests**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-11T05:41:50Z
- **Completed:** 2026-03-11T05:48:10Z
- **Tasks:** 2 of 2
- **Files modified:** 9

## Accomplishments

- Created `log_to_leak.yaml` with 4 patterns covering logging-framed exfiltration, session forwarding to external URLs, MCP per-call invocation instructions, and compliance-framed exfiltration
- Added `modes: [strict]` to CI-001 in `cicd_poisoning.yaml` — CI-001 is now the 5th strict-only pattern, eliminating the 23.9% Tier 0 FPR floor on STANDARD-mode workflow file scans
- 65 gap-category patterns (10 files) confirmed correct — PAT-01 met at 65 > 51 target
- 18 new tests in `test_log_to_leak.py` covering TP and TN for all 4 LTL patterns
- Full test suite passes at 1143 tests (90 new tests added across both tasks)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Log-To-Leak category and tests (TDD)** — `e16bd81` (feat)
2. **Task 2: Restrict CI-001 to strict mode and audit gap patterns** — `a98f27c` (feat)

## Files Created/Modified

- `src/cloneguard/rules/log_to_leak.yaml` — New logToLeak category: LTL-001 through LTL-004
- `tests/test_log_to_leak.py` — 18 TP/TN tests for all LTL patterns
- `src/cloneguard/rules/cicd_poisoning.yaml` — CI-001 now has `modes: [strict]`; false_positive_hint updated to document CI-002 division
- `tests/test_new_patterns.py` — `test_ci001_expression_injection` updated to CLAUDE.md path; `test_ci001_suppressed_in_standard_mode` added
- `tests/test_integration_all_patterns.py` — CI-001 payload updated to use CLAUDE.md (STRICT mode path)
- `README.md` — Pattern count 193->197, category count 24->25 (3 occurrences)
- `docs/SECURITY.md` — Pattern count 193->197, category count 24->25 (2 occurrences)
- `docs/MINI-SEMANTIC-MODEL.md` — Pattern count 193->197
- `docs/TESTING-AND-VALIDATION.md` — Pattern count 193->197 (3 occurrences)

## Decisions Made

- **CI-001 Option B (modes: [strict])** chosen over Option A (run: context narrowing) — consistent with the established CI-004/CI-006 convention; CI-002 already owns the run-context execution case in all modes, so this avoids overlap and is architecturally clean
- **LTL-004 strict-only** — compliance-framing patterns have high FPR risk on legitimate audit documentation in non-agent contexts; strict restriction confines them to agent instruction files where they signal real threats
- **Pattern count documentation updated inline** — the pre-commit consistency check gate requires all docs claiming a pattern count to match the actual YAML count before any commit passes

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated 8 documentation occurrences of "193 patterns" and "24 categories" to match new 197/25 counts**
- **Found during:** Task 1 commit (after creating log_to_leak.yaml)
- **Issue:** Pre-commit consistency check hook blocked the commit: README.md, docs/SECURITY.md, docs/MINI-SEMANTIC-MODEL.md, docs/TESTING-AND-VALIDATION.md all claimed 193 patterns while YAML count was now 197
- **Fix:** Updated all 8 occurrences across 4 files to 197 patterns / 25 categories
- **Files modified:** README.md, docs/SECURITY.md, docs/MINI-SEMANTIC-MODEL.md, docs/TESTING-AND-VALIDATION.md
- **Verification:** Pre-commit consistency check passed
- **Committed in:** e16bd81 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed test_integration_all_patterns.py CI-001 payload path after mode restriction**
- **Found during:** Task 2 full regression run
- **Issue:** `test_pattern_fires_through_full_scanner[CI-001]` failed because the PAYLOADS registry scanned CI-001 via `.github/workflows/ci.yml` (STANDARD mode), which no longer fires CI-001 after the strict restriction
- **Fix:** Changed CI-001 payload path from `.github/workflows/ci.yml` to `CLAUDE.md` so the scanner operates in STRICT mode, matching the pattern's new scope
- **Files modified:** tests/test_integration_all_patterns.py
- **Verification:** Full suite 1143 passed, 0 failed
- **Committed in:** a98f27c (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both auto-fixes were necessary for correctness. No scope creep.

## Issues Encountered

None — both deviations were clean fixes with immediate verification.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- PAT-01 and PAT-02 requirements met — pattern expansion phase deliverables complete
- 197 patterns across 25 categories, full test coverage
- CI-001 strict restriction reduces workflow FPR floor; calibration benchmark (`scripts/calibrate_thresholds.py --verify`) should now show combined workflow FPR below the 24% target (not run in this plan per task scope)
- Plan 06-02 can proceed (if exists) or phase gate can be run

## Self-Check: PASSED

- `src/cloneguard/rules/log_to_leak.yaml` — FOUND
- `tests/test_log_to_leak.py` — FOUND
- Commit `e16bd81` (Task 1) — FOUND
- Commit `a98f27c` (Task 2) — FOUND
- CI-001 `modes: [strict]` in cicd_poisoning.yaml — CONFIRMED (3 strict patterns in file)

---
*Phase: 06-pattern-expansion*
*Completed: 2026-03-11*
