---
phase: 01-foundation
plan: 01
subsystem: detection
tags: [protocol, dataclass, pattern-engine, semantic-classifier, sequence-monitor, refactoring]

# Dependency graph
requires: []
provides:
  - "cloneguard.detection package with typed Protocol interfaces and frozen dataclass contracts"
  - "DetectionEngine orchestrator with scan/scan_instructions_loaded/scan_pre_tool_use/scan_post_tool_use"
  - "Backward-compatible re-export shims for cloneguard.patterns, cloneguard.mini_semantic, cloneguard.monitor"
  - "13 unit tests for DetectionEngine covering all handler-specific scan methods"
affects: [01-02, 01-03, 02-adapter-layer, 03-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Protocol-based interfaces (PEP 544 structural subtyping) for detection engine"
    - "Frozen dataclasses for immutable data contracts on hot path"
    - "Re-export shim pattern for backward-compatible module moves"
    - "Lazy-loaded singleton pattern for expensive resources (ONNX model, PatternEngine)"

key-files:
  created:
    - src/cloneguard/detection/__init__.py
    - src/cloneguard/detection/types.py
    - src/cloneguard/detection/engine.py
    - src/cloneguard/detection/patterns.py
    - src/cloneguard/detection/semantic.py
    - src/cloneguard/detection/sequence.py
    - tests/test_detection_engine.py
  modified:
    - src/cloneguard/patterns.py
    - src/cloneguard/mini_semantic.py
    - src/cloneguard/monitor.py

key-decisions:
  - "Fixed relative Path references in moved modules (rules_dir and MODEL_DIR) to traverse up one level to parent package"
  - "Re-exported private names (_is_sensitive_file, _MAX_SESSIONS, etc.) in shims since tests import them"

patterns-established:
  - "Re-export shim: original module becomes thin import-and-re-export, preserving all existing import paths"
  - "Detection types use frozen=True dataclasses; mutable collections use standard dataclasses"
  - "DetectionEngine uses lazy-loaded singletons for PatternEngine and MiniSemanticClassifier"

requirements-completed: [FNDN-01]

# Metrics
duration: 8min
completed: 2026-04-05
---

# Phase 01 Plan 01: Detection Package Extraction Summary

**Modular cloneguard.detection package with typed Protocol contracts, DetectionEngine orchestrator replicating all hooks.py detection logic, and backward-compatible re-export shims preserving 80+ existing import paths**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-05T22:44:45Z
- **Completed:** 2026-04-05T22:52:38Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments
- Extracted PatternEngine, MiniSemanticClassifier, and ToolCallMonitor into `cloneguard.detection` subpackage with clean module boundaries
- Created typed contracts: `ToolCallEvent`, `SignalResult`, `DetectionResult` (frozen dataclasses) and `DetectionEngineProtocol` (PEP 544 Protocol)
- Implemented `DetectionEngine` orchestrator with handler-specific scan methods that replicate hooks.py detection logic exactly (protected paths, content scanning, build gating, mode detection, Tier 1.5 classification, session trust cache)
- All 1269 tests pass (1256 existing + 13 new), ruff clean, mypy --strict clean on all detection modules

## Task Commits

Each task was committed atomically:

1. **Task 1: Create detection package with typed contracts and move existing modules** - `70a2160` (feat)
2. **Task 2: Implement DetectionEngine orchestrator (TDD RED)** - `ae45a4a` (test)
3. **Task 2: Implement DetectionEngine orchestrator (TDD GREEN)** - `fdbcdcd` (feat)

## Files Created/Modified
- `src/cloneguard/detection/__init__.py` - Public re-exports for detection package (DetectionEngine, types)
- `src/cloneguard/detection/types.py` - Protocol interfaces and frozen dataclass contracts (ToolCallEvent, DetectionResult, SignalResult, DetectionEngineProtocol)
- `src/cloneguard/detection/engine.py` - DetectionEngine orchestrator with scan/scan_instructions_loaded/scan_pre_tool_use/scan_post_tool_use
- `src/cloneguard/detection/patterns.py` - PatternEngine moved from patterns.py (rules_dir path fixed for new location)
- `src/cloneguard/detection/semantic.py` - MiniSemanticClassifier moved from mini_semantic.py (MODEL_DIR and ScanMode import fixed)
- `src/cloneguard/detection/sequence.py` - ToolCallMonitor moved from monitor.py (sequence_allowlist import preserved)
- `src/cloneguard/patterns.py` - Re-export shim forwarding to detection/patterns.py
- `src/cloneguard/mini_semantic.py` - Re-export shim forwarding to detection/semantic.py
- `src/cloneguard/monitor.py` - Re-export shim forwarding to detection/sequence.py
- `tests/test_detection_engine.py` - 13 unit tests across 8 test classes

## Decisions Made
- Fixed `Path(__file__).parent / "rules"` to `Path(__file__).parent.parent / "rules"` in detection/patterns.py since the file moved one directory deeper
- Fixed `Path(__file__).parent / "model"` to `Path(__file__).parent.parent / "model"` in detection/semantic.py for the same reason
- Re-exported private names (`_is_sensitive_file`, `_MAX_SESSIONS`, `_DEFAULT_THRESHOLDS`, etc.) in shims because existing tests import them directly -- removing these would break 30+ test files
- Used ruff auto-fix for import sort order (underscore-prefixed names sort differently in isort rules)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed relative path for rules directory in detection/patterns.py**
- **Found during:** Task 1 (moving PatternEngine)
- **Issue:** `Path(__file__).parent / "rules"` would resolve to `detection/rules/` which doesn't exist
- **Fix:** Changed to `Path(__file__).parent.parent / "rules"` to reach `src/cloneguard/rules/`
- **Files modified:** src/cloneguard/detection/patterns.py
- **Verification:** All 1256 tests pass, PatternEngine loads rules correctly
- **Committed in:** 70a2160

**2. [Rule 3 - Blocking] Fixed relative path for model directory in detection/semantic.py**
- **Found during:** Task 1 (moving MiniSemanticClassifier)
- **Issue:** `Path(__file__).parent / "model"` would resolve to `detection/model/` which doesn't exist
- **Fix:** Changed to `Path(__file__).parent.parent / "model"` to reach `src/cloneguard/model/`
- **Files modified:** src/cloneguard/detection/semantic.py
- **Verification:** All tests pass, model loading works correctly
- **Committed in:** 70a2160

**3. [Rule 2 - Missing Critical] Re-exported private names in backward-compat shims**
- **Found during:** Task 1 (creating re-export shims)
- **Issue:** Tests import private names like `_is_sensitive_file`, `_MAX_SESSIONS`, `_extract_external_url` from original module paths
- **Fix:** Added all private names used by tests to the re-export shims
- **Files modified:** src/cloneguard/patterns.py, src/cloneguard/mini_semantic.py, src/cloneguard/monitor.py
- **Verification:** All 1256 existing tests pass without modification
- **Committed in:** 70a2160

---

**Total deviations:** 3 auto-fixed (2 blocking path issues, 1 missing re-exports)
**Impact on plan:** All auto-fixes were necessary for correctness. No scope creep. The plan anticipated the need for path fixes and re-exports but didn't enumerate private names.

## Issues Encountered
None -- all tasks executed smoothly after the path fixes.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Detection package complete with all typed contracts and engine orchestrator
- Plans 02 and 03 can now import from `cloneguard.detection` to build thin hook shims and audit/CLI integration
- hooks.py still contains its own detection logic (to be replaced by thin shims in Plan 02)

## Self-Check: PASSED

All 8 created files verified present. All 3 task commits verified in git log.

---
*Phase: 01-foundation*
*Completed: 2026-04-05*
