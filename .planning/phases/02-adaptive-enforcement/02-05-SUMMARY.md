---
phase: 02-adaptive-enforcement
plan: 05
subsystem: enforcement
tags: [hooks, policy-engine, audit, enforcement-pipeline, dry-run, constraint-spec, sandbox-exec]

# Dependency graph
requires:
  - phase: 02-01
    provides: "SandboxAdapter Protocol, NoopAdapter, Constraints/PolicyDecision/EnforcementOutcome types"
  - phase: 02-02
    provides: "YAMLPolicyEngine with evaluate(), PolicyConfig, get_policy_engine singleton"
  - phase: 02-03
    provides: "LandlockAdapter, SeatbeltAdapter, cloneguard-sandbox-exec wrapper, write_constraint_spec()"
  - phase: 02-04
    provides: "PackageRegistryClient for hallucination detection in DetectionEngine"
provides:
  - "Full enforcement pipeline wired into hooks.py: detection -> policy -> constraint spec -> audit"
  - "AuditEvent.would_apply field for dry-run constraint visibility (D-14)"
  - "YAMLPolicyEngine.sandbox_preferred public property"
  - "Updated enforcement/__init__.py exports (PolicyConfig, YAMLPolicyEngine, get_policy_engine)"
  - "25 enforcement-specific tests covering the full pipeline"
affects: [03-governance, audit-compliance, operator-tooling]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Policy evaluation in hook handlers with try/except graceful degradation"
    - "Constraint spec file pattern: hook writes spec, sandbox-exec reads and applies"
    - "DRY_RUN/CONSTRAIN/BLOCK/ALLOW enforcement action states in audit events"
    - "would_apply vs constraints_applied for dry-run vs active enforcement"

key-files:
  created:
    - tests/test_enforcement_hooks_integration.py
    - tests/test_enforcement_integration.py
  modified:
    - src/cloneguard/hooks.py
    - src/cloneguard/audit/types.py
    - src/cloneguard/enforcement/__init__.py
    - src/cloneguard/enforcement/policy.py

key-decisions:
  - "Exit code contract preserved exactly: SAFE/SUSPICIOUS -> 0, MALICIOUS -> 2 (Pitfall 5)"
  - "Only PreToolUse writes constraint spec files (InstructionsLoaded/PostToolUse have no subprocess)"
  - "Enforcement import failure degrades to detection-only mode (never breaks hook pipeline)"
  - "os.environ['CLONEGUARD_ENFORCE_SPEC'] passes spec file path to sandbox-exec wrapper"

patterns-established:
  - "Enforcement try/except: all enforcement imports and calls wrapped, failure never propagates to exit code"
  - "Policy decision threading: policy_decision parameter flows through _emit_audit_event to AuditEvent"
  - "Constraint spec file lifecycle: hook writes via write_constraint_spec(), sandbox-exec reads and deletes"

requirements-completed: [ENFC-01, ENFC-07]

# Metrics
duration: 7min
completed: 2026-04-06
---

# Phase 02 Plan 05: Enforcement Pipeline Integration Summary

**Full enforcement pipeline wired into hooks.py: detection -> policy evaluation -> constraint spec writing -> NDJSON audit with DRY_RUN/CONSTRAIN/BLOCK actions and would_apply dry-run visibility**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-04-06T02:41:39Z
- **Completed:** 2026-04-06T02:48:00Z
- **Tasks:** 3 (2 auto + 1 checkpoint auto-approved)
- **Files modified:** 6

## Accomplishments
- Wired PolicyEngine.evaluate() into all three hook handlers (PreToolUse, PostToolUse, InstructionsLoaded)
- PreToolUse writes constraint spec files via write_constraint_spec() for sandbox-exec wrapper when enforcement is active (not dry-run)
- AuditEvent extended with would_apply field for dry-run constraint visibility (D-14)
- Added sandbox_preferred public property on YAMLPolicyEngine to avoid private _config access
- Exported PolicyConfig, YAMLPolicyEngine, get_policy_engine from enforcement __init__.py
- Exit code contract preserved exactly: SAFE/SUSPICIOUS -> 0, MALICIOUS -> 2
- 25 new enforcement-specific tests, 1476 total tests passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Update AuditEvent, add sandbox_preferred property, and wire hooks pipeline**
   - `83873a5` (test: failing tests for enforcement hooks integration)
   - `cb83227` (feat: wire enforcement pipeline into hooks and update audit types)
2. **Task 2: End-to-end integration tests** - `83e8426` (test: e2e integration tests)
3. **Task 3: Verify complete Phase 2 enforcement pipeline** - Auto-approved checkpoint

## Files Created/Modified
- `src/cloneguard/hooks.py` - Added enforcement pipeline to all three hook handlers
- `src/cloneguard/audit/types.py` - Added would_apply field to AuditEvent for dry-run visibility
- `src/cloneguard/enforcement/policy.py` - Added sandbox_preferred property to YAMLPolicyEngine
- `src/cloneguard/enforcement/__init__.py` - Exported PolicyConfig, YAMLPolicyEngine, get_policy_engine
- `tests/test_enforcement_hooks_integration.py` - 13 tests for hooks enforcement integration
- `tests/test_enforcement_integration.py` - 12 end-to-end pipeline integration tests

## Decisions Made
- Exit code contract unchanged (Pitfall 5): enforcement happens outside the exit code channel via constraint spec files
- Only PreToolUse writes constraint spec files -- InstructionsLoaded and PostToolUse pass policy_decision to audit only (no subprocess to sandbox)
- os.environ["CLONEGUARD_ENFORCE_SPEC"] communicates spec file path to sandbox-exec wrapper
- All enforcement imports wrapped in try/except -- import failure silently degrades to detection-only mode

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 2 complete: all 5 plans executed, full enforcement pipeline wired
- Detection -> Policy -> Constraint Spec -> Audit pipeline is live (dry-run default)
- Ready for Phase 3 governance features (OPA/Cedar backends, fleet management)
- Operators can enable active enforcement by setting `dry_run: false` in `~/.cloneguard/policy.yaml`

## Self-Check: PASSED

All 7 files verified present. All 3 commits verified in git log.

---
*Phase: 02-adaptive-enforcement*
*Completed: 2026-04-06*
