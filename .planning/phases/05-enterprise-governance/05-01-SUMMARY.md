---
phase: 05-enterprise-governance
plan: 01
subsystem: enforcement
tags: [opa, rego, cedar, cedarpy, regopy, policy-backend, protocol, pep544]

# Dependency graph
requires:
  - phase: 02-adaptive-enforcement
    provides: PolicyConfig Pydantic model, YAMLPolicyEngine, PolicyDecision types
provides:
  - PolicyBackend Protocol (runtime_checkable, PEP 544)
  - OPAPolicyBackend -- Rego to PolicyConfig compiler via regopy
  - CedarPolicyBackend -- Cedar-wrapped YAML to PolicyConfig via cedarpy
  - YAMLPolicyBackend -- thin wrapper around PolicyConfig.from_yaml
  - get_policy_backend() factory function
  - Optional dependencies: cloneguard[opa], cloneguard[cedar], cloneguard[governance]
affects: [05-02, 05-03, enforcement, policy-loading, cli]

# Tech tracking
tech-stack:
  added: [regopy>=1.3, cedarpy>=4.8]
  patterns: [PolicyBackend Protocol, compiler pattern, YAML-wrapper for Cedar]

key-files:
  created:
    - src/cloneguard/enforcement/backends/__init__.py
    - src/cloneguard/enforcement/backends/yaml_backend.py
    - src/cloneguard/enforcement/backends/opa.py
    - src/cloneguard/enforcement/backends/cedar.py
    - tests/test_policy_backends.py
  modified:
    - src/cloneguard/enforcement/__init__.py
    - pyproject.toml

key-decisions:
  - "regopy output parsed via JSON from Output.__str__() -> expressions[0] dict"
  - "Cedar uses YAML-wrapper document (cedar_policies + config fields) not raw Cedar syntax"
  - "Cedar syntax validated via cedarpy.format_policies, not is_authorized"
  - "Both OPA and Cedar backends raise ImportError at construction time, not compile time"

patterns-established:
  - "PolicyBackend Protocol: name property + compile(source) -> PolicyConfig + validate(source) -> list[str]"
  - "Compiler pattern: policy language is DATA source for config values on cold path, not runtime evaluator"
  - "YAML-wrapper for non-YAML policy languages: wrap native syntax in YAML with config section"

requirements-completed: [GOVN-01, GOVN-02, GOVN-03]

# Metrics
duration: 9min
completed: 2026-04-06
---

# Phase 5 Plan 1: Policy Backends Summary

**PolicyBackend Protocol with OPA/Rego and Cedar compilers to PolicyConfig IR via regopy and cedarpy in-process evaluation**

## Performance

- **Duration:** 9 min
- **Started:** 2026-04-06T23:27:30Z
- **Completed:** 2026-04-06T23:36:16Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments
- PolicyBackend Protocol (runtime_checkable PEP 544) with compile/validate/name contract
- OPA/Rego backend compiling Rego modules to PolicyConfig via regopy in-process query of data.cloneguard.policy
- Cedar backend using YAML-wrapper document pattern (cedar_policies text + config dict) with cedarpy syntax validation
- YAMLPolicyBackend as thin wrapper, get_policy_backend() factory with lazy imports
- 29 passing tests covering all three backends with round-trip verification through YAMLPolicyEngine
- Optional dependencies declared: cloneguard[opa], cloneguard[cedar], cloneguard[governance]

## Task Commits

Each task was committed atomically (TDD: RED -> GREEN for each):

1. **Task 1: PolicyBackend Protocol and YAMLPolicyBackend wrapper** - `d1b8bf8` (test)
2. **Task 2: OPA/Rego policy backend via regopy** - `2ca7a8c` (feat)
3. **Task 3: Cedar policy backend via cedarpy** - `202eb26` (feat)
4. **mypy override for untyped libraries** - `870985b` (chore)

## Files Created/Modified
- `src/cloneguard/enforcement/backends/__init__.py` - PolicyBackend Protocol and get_policy_backend() factory
- `src/cloneguard/enforcement/backends/yaml_backend.py` - YAML backend delegating to PolicyConfig.from_yaml
- `src/cloneguard/enforcement/backends/opa.py` - OPA backend: Rego -> regopy.Interpreter -> PolicyConfig
- `src/cloneguard/enforcement/backends/cedar.py` - Cedar backend: YAML wrapper -> cedarpy validation -> PolicyConfig
- `src/cloneguard/enforcement/__init__.py` - Added PolicyBackend and get_policy_backend exports
- `pyproject.toml` - Added opa, cedar, governance optional-dependencies; mypy overrides for regopy/cedarpy
- `tests/test_policy_backends.py` - 29 tests across YAML (9), OPA (9), Cedar (11)

## Decisions Made
- **regopy Output parsing:** The regopy Output object wraps results in `{"expressions": [...]}`. Parse via `json.loads(str(output))` then extract `expressions[0]` as the policy dict for PolicyConfig.model_validate().
- **Cedar YAML-wrapper pattern:** Cedar's permit/forbid model does not map to PolicyConfig's threshold model. Instead of complex Cedar-to-threshold translation, the Cedar backend uses a YAML document with `cedar_policies` (validated Cedar text) and `config` (PolicyConfig-compatible dict). This matches the D-02 decision that YAML is the canonical IR.
- **cedarpy.format_policies for validation:** cedarpy.is_authorized does not raise on invalid syntax (prints to stderr). format_policies raises ValueError on parse errors -- used for syntax validation.
- **Construction-time ImportError:** Both OPA and Cedar backends raise ImportError in `__init__` if their library is missing, not at compile time. This follows the plan requirement and gives operators immediate feedback.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Cedar test fixture used unsupported syntax**
- **Found during:** Task 3 (Cedar backend GREEN phase)
- **Issue:** Test fixture CEDAR_WITH_CONSTRAINTS used `resource.confidence >= 0.7` in a when clause, but cedarpy requires proper entity type references for attribute access on resource
- **Fix:** Simplified Cedar fixture to `forbid(principal, action, resource) when { context.score > 0 };` which is valid Cedar syntax
- **Files modified:** tests/test_policy_backends.py
- **Verification:** All 11 Cedar tests pass
- **Committed in:** 202eb26 (Task 3 commit)

**2. [Rule 3 - Blocking] mypy strict failed on untyped regopy/cedarpy**
- **Found during:** Task 3 verification (mypy --strict)
- **Issue:** regopy and cedarpy do not ship type stubs or py.typed markers, causing mypy strict import-untyped errors
- **Fix:** Added regopy.* and cedarpy.* to mypy overrides in pyproject.toml
- **Files modified:** pyproject.toml
- **Verification:** mypy --strict passes with 0 errors
- **Committed in:** 870985b

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered
None beyond the auto-fixed deviations above.

## Threat Surface Scan

No new threat surface beyond what the plan's threat model already covers. Policy files are compiled on the cold path only. No new network endpoints, auth paths, or file access patterns introduced.

## User Setup Required
None - no external service configuration required. Optional dependencies installed via pip extras.

## Next Phase Readiness
- PolicyBackend Protocol ready for use by policy loading path
- SIEM connectors (Plan 02) and fleet deployment (Plan 03) can proceed independently
- get_policy_backend() factory ready for CLI integration (e.g., `cloneguard --policy-backend opa`)

---
*Phase: 05-enterprise-governance*
*Completed: 2026-04-06*
