---
phase: 01-foundation
plan: 02
subsystem: audit
tags: [pydantic, ndjson, audit-events, hooks-shim, detection-engine, backward-compat]

# Dependency graph
requires:
  - "01-01: DetectionEngine with typed contracts (ToolCallEvent, DetectionResult, SignalResult)"
provides:
  - "cloneguard.audit package with Pydantic v2 frozen AuditEvent model (cloneguard/event/v1 schema)"
  - "NDJSONEmitter writing to file/stderr, never stdout (CLONEGUARD_NDJSON_OUTPUT env var)"
  - "hooks.py thin shim delegating detection to cloneguard.detection.engine"
  - "scanner.py importing from cloneguard.detection.patterns"
  - "_emit_audit_event() helper with lazy Pydantic import for every detection event"
affects: [01-03, 02-adapter-layer, 03-integration]

# Tech tracking
tech-stack:
  added: ["pydantic>=2.0 (core dependency)"]
  patterns:
    - "Lazy Pydantic import: audit emission happens AFTER exit code, never on hot path (Pitfall 6)"
    - "Backward-compatible function wrapper: _detect_mode_for_tier15 accepts 3 or 4 args"
    - "NDJSON emitter defaults to stderr, uses env var for file output (T-02-01)"

key-files:
  created:
    - src/cloneguard/audit/__init__.py
    - src/cloneguard/audit/types.py
    - src/cloneguard/audit/ndjson.py
    - tests/test_audit_ndjson.py
  modified:
    - src/cloneguard/hooks.py
    - src/cloneguard/scanner.py
    - pyproject.toml

key-decisions:
  - "Kept hooks-level singletons (_get_engine, _get_mini_classifier, _session_trust) for backward compat -- tests monkeypatch these"
  - "Added backward-compat _detect_mode_for_tier15 wrapper with optional engine arg (tests call with 3 args, engine callers with 4)"
  - "Pydantic >=2.0 added as core dependency (audit layer is not optional)"
  - "_classify_with_tier15 imported from engine, not defined in hooks.py (acceptance criteria)"

patterns-established:
  - "Audit emission pattern: _emit_audit_event() wraps in try/except, lazy-imports Pydantic, never raises"
  - "NDJSON output: event.to_ndjson() returns model_dump_json() + newline"
  - "NDJSONEmitter.from_env() factory for CLONEGUARD_NDJSON_OUTPUT configuration"

requirements-completed: [FNDN-02, FNDN-06]

# Metrics
duration: 13min
completed: 2026-04-05
---

# Phase 01 Plan 02: Audit Layer and Hook Shim Conversion Summary

**Pydantic v2 audit event schema (cloneguard/event/v1) with NDJSON emitter, hooks.py detection logic delegated to DetectionEngine, scanner.py importing from detection package**

## Performance

- **Duration:** 13 min
- **Started:** 2026-04-05T22:58:45Z
- **Completed:** 2026-04-05T23:11:44Z
- **Tasks:** 2 (Task 1 TDD: RED + GREEN)
- **Files modified:** 7

## Accomplishments
- Created `cloneguard.audit` package with Pydantic v2 frozen AuditEvent model conforming to cloneguard/event/v1 schema (D-05, D-07)
- NDJSONEmitter writes structured events to file (via CLONEGUARD_NDJSON_OUTPUT) or stderr, never stdout (T-02-01)
- hooks.py detection functions (`_classify_with_tier15`) moved to engine; handlers add audit emission via `_emit_audit_event()` 
- scanner.py imports PatternEngine from `cloneguard.detection.patterns` (D-03)
- All 1278 tests pass (1269 existing + 9 new audit tests), ruff clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Create audit package (TDD RED)** - `731e8f0` (test)
2. **Task 1: Create audit package (TDD GREEN)** - `1f564b7` (feat)
3. **Task 2: Convert hooks.py and scanner.py to thin shims** - `c2d4aa3` (feat)

## Files Created/Modified
- `src/cloneguard/audit/__init__.py` - Public re-exports: AuditEvent, EventType, SignalDetails, NDJSONEmitter
- `src/cloneguard/audit/types.py` - Pydantic v2 frozen AuditEvent model with cloneguard/event/v1 schema, SignalDetails nested sub-object
- `src/cloneguard/audit/ndjson.py` - NDJSONEmitter with from_env() factory (CLONEGUARD_NDJSON_OUTPUT), to_file(), default stderr
- `tests/test_audit_ndjson.py` - 9 tests covering construction, immutability, NDJSON serialization, schema version, enforcement default, emitter stream/file output, SignalDetails
- `src/cloneguard/hooks.py` - Detection functions imported from engine; _emit_audit_event() added; backward-compat wrappers for test API
- `src/cloneguard/scanner.py` - PatternEngine imported from cloneguard.detection.patterns instead of cloneguard.patterns
- `pyproject.toml` - Added pydantic>=2.0 to core dependencies

## Decisions Made
- **Kept hooks-level singletons for test backward compat:** Tests monkeypatch `cloneguard.hooks._get_engine`, `_get_mini_classifier`, `_session_trust`, and `get_monitor` directly. Moving these to the engine would break 21+ tests. Kept them as the authoritative singletons at the hooks level, with detection logic imported from the engine.
- **Backward-compat `_detect_mode_for_tier15` wrapper:** Tests call with 3 args (no engine param). Engine function requires 4 args. Added a wrapper that defaults the engine parameter to `_get_engine()`.
- **Pydantic as core dependency:** Added `pydantic>=2.0` to `dependencies` in pyproject.toml (not optional). The audit layer is core functionality -- every detection emits an audit event. It's lazy-imported to avoid Pitfall 6 cold-start cost.
- **StrEnum for EventType:** Ruff UP042 flagged `str, Enum` inheritance; used Python 3.11+ `StrEnum` instead.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Backward-compat wrapper for _detect_mode_for_tier15 signature change**
- **Found during:** Task 2 (hooks.py conversion)
- **Issue:** Engine's `_detect_mode_for_tier15` takes 4 args (includes `engine` param), but 8 tests call it from hooks with 3 args
- **Fix:** Added wrapper function in hooks.py with `engine: PatternEngine | None = None` defaulting to `_get_engine()`
- **Files modified:** src/cloneguard/hooks.py
- **Verification:** All 64 hooks tests pass, including all 8 TestModeDetectionEnhanced tests
- **Committed in:** c2d4aa3

**2. [Rule 1 - Bug] Fixed StrEnum inheritance for Python 3.11+ lint compliance**
- **Found during:** Task 1 (audit types)
- **Issue:** Ruff UP042 flagged `class EventType(str, Enum)` as deprecated pattern
- **Fix:** Changed to `class EventType(StrEnum)` using Python 3.11+ stdlib
- **Files modified:** src/cloneguard/audit/types.py
- **Verification:** Ruff clean, all 9 audit tests pass
- **Committed in:** 1f564b7

**3. [Rule 1 - Bug] Fixed datetime.UTC alias for Python 3.11+ lint compliance**
- **Found during:** Task 1 (audit types)
- **Issue:** Ruff UP017 flagged `datetime.timezone.utc` as deprecated pattern
- **Fix:** Changed to `datetime.UTC` alias
- **Files modified:** src/cloneguard/audit/types.py
- **Verification:** Ruff clean, all tests pass
- **Committed in:** 1f564b7

---

**Total deviations:** 3 auto-fixed (1 blocking signature compat, 2 lint compliance)
**Impact on plan:** All auto-fixes necessary for correctness and lint compliance. No scope creep.

## Issues Encountered
None -- all tasks executed after the backward-compat fixes.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Audit layer complete: every detection can now emit structured NDJSON events
- hooks.py delegates detection to engine; audit emission is lazy and never blocks
- scanner.py imports from detection package
- Plan 03 can add SARIF output, CLI enhancements, and packaging fixes
- All 1278 tests pass without modification to existing tests

## Self-Check: PASSED

All 4 created files verified present. All 3 task commits verified in git log.

---
*Phase: 01-foundation*
*Completed: 2026-04-05*
