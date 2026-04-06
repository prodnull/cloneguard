---
phase: 02-adaptive-enforcement
plan: 01
subsystem: enforcement
tags: [protocol, dataclass, enum, sandbox, adapter, noop]

# Dependency graph
requires: []
provides:
  - "Verdict enum with SAFE/SUSPICIOUS/MALICIOUS canonical names + CLEAN/DETECTED backward aliases"
  - "PolicyDecision, Constraints, EnforcementOutcome frozen dataclasses"
  - "SandboxAdapter Protocol (PEP 544 runtime_checkable)"
  - "NoopAdapter (detection-only fallback)"
  - "get_sandbox_adapter() auto-selection with Landlock/Seatbelt probes"
  - "cloneguard.enforcement package with public API"
affects: [02-02-policy-engine, 02-03-os-sandbox-adapters, 02-04-audit-pipeline, 02-05-pipeline-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Frozen dataclasses for enforcement hot path types (never Pydantic)"
    - "runtime_checkable Protocol for adapter structural subtyping"
    - "Enum aliases for backward-compatible name evolution"
    - "ctypes probing for OS-level sandbox capability detection"

key-files:
  created:
    - src/cloneguard/enforcement/__init__.py
    - src/cloneguard/enforcement/types.py
    - src/cloneguard/enforcement/adapter.py
    - tests/test_enforcement_types.py
    - tests/test_enforcement_adapter.py
  modified:
    - src/cloneguard/detection/patterns.py

key-decisions:
  - "Verdict enum aliases: CLEAN=SAFE, DETECTED=MALICIOUS via same .value strings -- zero backward compat breakage"
  - "Tuples (not lists) for Constraints fields -- immutable sequences in frozen dataclass"
  - "dry_run=True default on PolicyDecision -- safe-by-default enforcement (D-13)"
  - "Adapter auto-selection probes Landlock via syscall 444 and Seatbelt via libSystem symbol"

patterns-established:
  - "Frozen dataclass pattern: all enforcement types use @dataclass(frozen=True) with tuple fields"
  - "Adapter Protocol pattern: SandboxAdapter defines core + deferred methods, NoopAdapter as fallback"
  - "Auto-selection pattern: probe strongest adapter first, fall back to NoopAdapter on any failure"

requirements-completed: [ENFC-01, ENFC-02, ENFC-03]

# Metrics
duration: 5min
completed: 2026-04-06
---

# Phase 02 Plan 01: Enforcement Foundation Summary

**Verdict enum SAFE/MALICIOUS aliases, frozen PolicyDecision/Constraints/EnforcementOutcome types, SandboxAdapter Protocol with NoopAdapter fallback and Landlock/Seatbelt auto-selection**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-06T01:22:51Z
- **Completed:** 2026-04-06T01:27:34Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Verdict enum evolved with SAFE/SUSPICIOUS/MALICIOUS names while preserving backward-compatible string values ("clean", "suspicious", "detected") -- all 203 existing tests pass unmodified
- Enforcement type system established: PolicyDecision (action/constraints/dry_run), Constraints (tuple-based immutable filesystem/network restrictions), EnforcementOutcome (adapter result recording)
- SandboxAdapter Protocol with core methods (restrict_filesystem, restrict_network) and deferred methods (snapshot, rollback, restrict_syscalls, get_audit_log)
- NoopAdapter as default fallback preserving v0.5.0 detection-only behavior
- Auto-selection probes Landlock (Linux 5.13+ syscall 444) and Seatbelt (macOS libSystem symbol), falls back to NoopAdapter on any failure

## Task Commits

Each task was committed atomically (TDD: test then feat):

1. **Task 1: Verdict enum transition and enforcement types** - `91a7297` (test), `8601c48` (feat)
2. **Task 2: SandboxAdapter Protocol, NoopAdapter, and auto-selection** - `d4d6db8` (test), `798cec0` (feat)

_TDD workflow: RED (failing tests) then GREEN (implementation) for each task_

## Files Created/Modified
- `src/cloneguard/detection/patterns.py` - Verdict enum updated with SAFE/MALICIOUS canonical names and CLEAN/DETECTED aliases
- `src/cloneguard/enforcement/__init__.py` - Package exports for types and adapter public API
- `src/cloneguard/enforcement/types.py` - PolicyDecision, Constraints, EnforcementOutcome frozen dataclasses
- `src/cloneguard/enforcement/adapter.py` - SandboxAdapter Protocol, NoopAdapter, Landlock/Seatbelt probes, get_sandbox_adapter()
- `tests/test_enforcement_types.py` - 23 tests covering Verdict aliases, frozen types, defaults, immutability
- `tests/test_enforcement_adapter.py` - 19 tests covering Protocol checks, NoopAdapter no-ops, auto-selection, fallback

## Decisions Made
- Verdict enum aliases via same string values (PEP 435 behavior) -- zero-risk backward compat
- Tuples for Constraints fields rather than frozenset -- preserves ordering for path lists
- dry_run=True default on PolicyDecision -- operator must explicitly enable enforcement
- ctypes probing for Landlock/Seatbelt rather than subprocess -- lower overhead, no shell injection

## Deviations from Plan

None -- plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Enforcement type contracts ready for PolicyEngine (Plan 02) to evaluate DetectionResult -> PolicyDecision
- SandboxAdapter Protocol ready for Landlock/Seatbelt implementations (Plan 03)
- EnforcementOutcome ready for audit pipeline integration (Plan 04)
- All types importable from cloneguard.enforcement for pipeline integration (Plan 05)

## Self-Check: PASSED

All 5 created files verified on disk. All 4 commit hashes found in git log.

---
*Phase: 02-adaptive-enforcement*
*Completed: 2026-04-06*
