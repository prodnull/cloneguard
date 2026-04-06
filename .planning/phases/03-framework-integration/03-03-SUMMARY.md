---
phase: 03-framework-integration
plan: 03
subsystem: cicd, observability
tags: [github-actions, sarif, opentelemetry, otel, cicd, composite-action, genai-semconv]

# Dependency graph
requires:
  - phase: 03-01
    provides: InputAdapter Protocol, adapter registry, ToolCallEvent dataclass
provides:
  - GitHub Actions composite action for CI/CD CloneGuard scanning with SARIF upload
  - CICDAdapter normalizing webhook events to ToolCallEvent
  - OTelEmitter with zero-cost no-op for enterprise observability
  - pyproject.toml otel extras (opentelemetry-api>=1.40)
affects: [ci-cd-deployment, enterprise-observability, audit-pipeline]

# Tech tracking
tech-stack:
  added: [opentelemetry-api>=1.40, astral-sh/setup-uv@v5, github/codeql-action/upload-sarif@v4]
  patterns: [zero-cost-optional-dep, genai-semantic-conventions, composite-action]

key-files:
  created:
    - .github/actions/cloneguard-scan/action.yml
    - src/cloneguard/adapters/cicd.py
    - src/cloneguard/audit/otel.py
    - tests/test_cicd_adapter.py
    - tests/test_otel_emitter.py
  modified:
    - src/cloneguard/adapters/__init__.py
    - src/cloneguard/audit/__init__.py
    - pyproject.toml

key-decisions:
  - "Used CLONEGUARD_SARIF_OUTPUT env var in action.yml instead of --output CLI flag to avoid adding new CLI args"
  - "OTelEmitter uses module-level _tracer singleton with try/except ImportError guard for zero-cost no-op"
  - "CICDAdapter concatenates all file patches as content, comma-separates filenames for multi-file PRs"

patterns-established:
  - "Zero-cost optional dependency: try/except ImportError at module level, _AVAILABLE flag, no-op methods"
  - "Composite action pattern: setup-uv -> uv tool install -> scan -> upload-sarif with always() condition"

requirements-completed: [INTG-04, INTG-05]

# Metrics
duration: 6min
completed: 2026-04-06
---

# Phase 3 Plan 3: CI/CD Action + OTel Emitter Summary

**GitHub Actions composite action with SARIF upload to Security tab, CI/CD webhook adapter, and OTel span emitter with GenAI semantic conventions and zero-cost no-op**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-06T14:07:53Z
- **Completed:** 2026-04-06T14:14:18Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- GitHub Actions composite action installs CloneGuard via uv, runs scan with SARIF output, uploads to Security tab via codeql-action/upload-sarif@v4
- CICDAdapter normalizes GitHub Actions webhook events (PR opened, synchronize) into ToolCallEvent for scanning
- OTelEmitter creates spans with GenAI semantic convention attributes (gen_ai.system, gen_ai.operation.name, gen_ai.tool.name) plus CloneGuard custom namespace
- OTel emitter is zero-cost when opentelemetry-api not installed -- no import errors, no runtime overhead
- T-03-12 enforced: no raw tool_input or gen_ai.tool.call.arguments in span attributes
- T-03-14 enforced: no force_flush() calls on hot path

## Task Commits

Each task was committed atomically (TDD: RED then GREEN):

1. **Task 1: CI/CD adapter + action.yml (RED)** - `6d6632f` (test)
2. **Task 1: CI/CD adapter + action.yml (GREEN)** - `871dec3` (feat)
3. **Task 2: OTel span emitter (RED)** - `1b48349` (test)
4. **Task 2: OTel span emitter (GREEN)** - `db790e1` (feat)

## Files Created/Modified
- `.github/actions/cloneguard-scan/action.yml` - Composite action: uv install, cloneguard scan --sarif, upload-sarif with always() condition
- `src/cloneguard/adapters/cicd.py` - CICDAdapter: normalize webhook payloads to ToolCallEvent, format_response for CI output
- `src/cloneguard/audit/otel.py` - OTelEmitter: GenAI semantic convention spans, zero-cost no-op, exception resilience
- `src/cloneguard/adapters/__init__.py` - Registered cicd adapter import
- `src/cloneguard/audit/__init__.py` - Exported OTelEmitter
- `pyproject.toml` - Added otel extras, updated all extras with opentelemetry-api>=1.40
- `tests/test_cicd_adapter.py` - 17 tests: normalize, format_response, Protocol conformance, action.yml structure
- `tests/test_otel_emitter.py` - 12 tests: no-op, attributes, info disclosure, resilience, pipeline compat

## Decisions Made
- Used `CLONEGUARD_SARIF_OUTPUT` env var in the composite action instead of adding a new `--output` CLI flag -- leverages existing CLI capability without expanding the CLI surface area
- OTelEmitter uses module-level `_tracer` singleton initialized via try/except ImportError guard -- matches existing patterns (PatternEngine, MiniSemanticClassifier)
- CICDAdapter concatenates all file patches into a single content string with newlines, and comma-separates filenames for source_path when multiple files are changed

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] action.yml uses env var instead of --output flag**
- **Found during:** Task 1
- **Issue:** Plan specified `--output cloneguard-results.sarif` CLI flag but no `--output` flag exists in the scan command. Adding it would expand CLI scope beyond this plan.
- **Fix:** Used existing `CLONEGUARD_SARIF_OUTPUT` env var to write SARIF to file, keeping `--sarif` flag for SARIF mode activation
- **Files modified:** `.github/actions/cloneguard-scan/action.yml`
- **Verification:** action.yml produces SARIF file via env var; all acceptance criteria met

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Minimal -- achieves identical outcome using existing CLI capability rather than adding new flag.

## Issues Encountered
- Pre-existing test failure in `test_agt_adapter.py::test_agt_available_flag_false_without_sdk` (from plan 03-02) -- the test expects `_AGT_AVAILABLE=False` but agent-os-kernel is installed via `--all-extras`. Not caused by this plan's changes. Logged as out-of-scope.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- CI/CD deployment ready: any GitHub repo can use the composite action for PR scanning
- OTel integration ready: enterprise SOC teams can consume CloneGuard signals via standard OTEL_EXPORTER_* configuration
- All framework integration adapters complete (Claude Code, Gemini CLI, Cursor, AGT, MCP, CI/CD, OTel)

## Self-Check: PASSED

- All 6 created files verified present on disk
- All 4 task commits verified in git log (6d6632f, 871dec3, 1b48349, db790e1)
- 29 new tests pass (17 cicd + 12 otel)
- 1627 existing tests pass with 0 regressions
- Lint clean on all new source files

---
*Phase: 03-framework-integration*
*Completed: 2026-04-06*
