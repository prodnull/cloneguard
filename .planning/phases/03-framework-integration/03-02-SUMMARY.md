---
phase: 03-framework-integration
plan: 02
subsystem: adapters
tags: [agt, mcp, microsoft, tool-call-interceptor, rade, protocol-adapter, backward-compat]

# Dependency graph
requires:
  - phase: 03-framework-integration
    plan: 01
    provides: InputAdapter Protocol, adapter registry, register_adapter decorator
  - phase: 01-foundation
    provides: DetectionEngine.scan(), ToolCallEvent, DetectionResult
  - phase: 02-adaptive-enforcement
    provides: PolicyEngine.evaluate(), PolicyDecision types
provides:
  - CloneGuardInterceptor AGT plugin (verdict mapping to DENY/CONSTRAIN/ALLOW)
  - MCPAdapter with request normalization and response scanning
  - CloneGuardMCPPlugin backward-compat wrapper for mcp-gateway
  - mcp_plugin.py deprecation shim re-exporting from adapters.mcp
  - pyproject.toml agt and mcp optional dependency extras
affects: [03-03, 03-04, 03-05]

# Tech tracking
tech-stack:
  added: [agent-os-kernel (optional), mcp (optional)]
  patterns: [import-guard graceful degradation, verdict-to-decision mapping, deprecation shim with re-export]

key-files:
  created:
    - src/cloneguard/adapters/agt.py
    - src/cloneguard/adapters/mcp.py
    - tests/test_agt_adapter.py
    - tests/test_mcp_adapter.py
  modified:
    - src/cloneguard/mcp_plugin.py
    - tests/test_mcp_plugin.py
    - pyproject.toml

key-decisions:
  - "AGT interceptor uses module-level imports for DetectionEngine (not lazy) to enable clean test mocking"
  - "AGT verdict mapping is stateless function (_verdict_to_decision) for exhaustive testability per T-03-06"
  - "MCP adapter registered via @register_adapter('mcp') in adapter registry for auto-detection"
  - "mcp_plugin.py replaced with thin shim emitting DeprecationWarning, re-exporting CloneGuardMCPPlugin as CloneGuardPlugin"
  - "test_mcp_plugin.py rewritten to test shim behavior instead of old implementation (old tests tested removed code)"

patterns-established:
  - "Import-guard pattern for optional SDKs: try/except at module top, _AVAILABLE flag, .available property"
  - "Verdict-to-decision mapping: stateless function with exhaustive test matrix (T-03-06)"
  - "Deprecation shim: warnings.warn at module level, re-export with noqa comments"

requirements-completed: [INTG-02, INTG-03]

# Metrics
duration: 7min
completed: 2026-04-06
---

# Phase 3 Plan 2: AGT + MCP Adapter Summary

**Microsoft AGT ToolCallInterceptor plugin and MCP middleware adapter with RADE detection, response scanning, and backward-compatible deprecation shim**

## Performance

- **Duration:** 7 min
- **Started:** 2026-04-06T13:57:49Z
- **Completed:** 2026-04-06T14:05:03Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- AGT ToolCallInterceptor wraps DetectionEngine.scan() with exhaustive verdict mapping (DENY/CONSTRAIN/ALLOW), importable without agent-os-kernel
- MCP adapter normalizes CallToolRequest JSON, scans tool descriptions for RADE attacks (D-11), and scans response content (D-10)
- Backward-compatible mcp_plugin.py shim emits DeprecationWarning and re-exports from adapters.mcp
- 33 new tests (14 AGT + 19 MCP), 1585 total tests passing with 0 regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement Microsoft AGT ToolCallInterceptor plugin** - `3902f33` (feat)
2. **Task 2: Refactor MCP middleware adapter and create mcp_plugin.py backward-compat shim** - `276a3a6` (feat)

_Both tasks used TDD: RED (failing tests) then GREEN (implementation)_

## Files Created/Modified
- `src/cloneguard/adapters/agt.py` - AGT ToolCallInterceptor with verdict mapping and fail-open error handling
- `src/cloneguard/adapters/mcp.py` - MCP adapter with request normalization, response scanning, RADE detection
- `src/cloneguard/mcp_plugin.py` - Deprecation shim re-exporting from adapters.mcp
- `tests/test_agt_adapter.py` - 14 tests: verdict mapping, error handling, content extraction, D-08 compliance
- `tests/test_mcp_adapter.py` - 19 tests: normalization, response scanning, format response, shim import
- `tests/test_mcp_plugin.py` - Updated 7 tests for shim behavior (was testing removed old implementation)
- `pyproject.toml` - Added agt and mcp optional dependency extras

## Decisions Made
- **Module-level imports for DetectionEngine in AGT adapter**: Chose module-level over lazy imports inside try blocks. Enables clean test mocking via `patch("cloneguard.adapters.agt.get_detection_engine")`. Lazy imports would require patching at `cloneguard.detection.engine` level.
- **test_mcp_plugin.py rewrite**: Old tests tested the removed mcp_plugin.py implementation directly (private attributes like `_MCP_GATEWAY_AVAILABLE`, `_extract_text_values`, `_semantic_available`). Replaced with tests that validate the shim's re-export and deprecation behavior. Full MCP functionality tested in test_mcp_adapter.py.
- **MCPAdapter registered in adapter registry**: Used `@register_adapter("mcp")` so MCP events can be auto-detected and routed through the standard adapter pipeline.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed test mock patching for lazy imports**
- **Found during:** Task 1 (AGT adapter GREEN phase)
- **Issue:** Tests patched `cloneguard.adapters.agt.get_detection_engine` but the function was imported lazily inside try blocks, making the module-level patch target nonexistent
- **Fix:** Moved `get_detection_engine` and `ToolCallEvent` to module-level imports; removed redundant lazy imports inside methods
- **Files modified:** src/cloneguard/adapters/agt.py
- **Verification:** All 14 AGT tests pass
- **Committed in:** 3902f33

**2. [Rule 1 - Bug] Updated test_mcp_plugin.py for shim compatibility**
- **Found during:** Task 2 (full regression run)
- **Issue:** Old test_mcp_plugin.py tested private attributes (`_MCP_GATEWAY_AVAILABLE`, `_extract_text_values`, `_semantic_available`) that no longer exist after mcp_plugin.py was replaced with a shim
- **Fix:** Rewrote test_mcp_plugin.py to validate shim behavior (imports work, DeprecationWarning emitted, re-exported classes function correctly)
- **Files modified:** tests/test_mcp_plugin.py
- **Verification:** 1585 tests pass, 0 failures
- **Committed in:** 276a3a6

---

**Total deviations:** 2 auto-fixed (2 bugs)
**Impact on plan:** Both fixes necessary for test correctness. No scope creep.

## Issues Encountered
- Pre-existing numpy ImportError in test_mahalanobis.py, test_train_freelb.py, test_transfer_experiment.py, test_augmentation.py (numpy not in dev deps). Not related to this plan's changes; all 4 files excluded from regression run. Out of scope.

## User Setup Required
None - no external service configuration required.

## Threat Model Verification

| Threat ID | Status | Verification |
|-----------|--------|--------------|
| T-03-06 | Mitigated | `test_detected_never_maps_to_allow` exhaustively tests all confidence levels |
| T-03-07 | Mitigated | AGT decisions include `tool_input_hash` (SHA-256), never raw content |
| T-03-08 | Mitigated | `test_scan_response_text_content` + `test_scan_response_multiple_text_items` verify ALL text scanned |
| T-03-09 | Mitigated | `test_normalize_extracts_description_rade_surface` verifies description extraction |
| T-03-10 | Accepted | mcp_plugin.py is read-only re-import shim |
| T-03-11 | Accepted | `test_before_tool_call_handles_engine_error_gracefully` verifies fail-open |

## Next Phase Readiness
- AGT and MCP adapters ready for integration with CI/CD runner (Plan 03) and OTel emitter (Plan 04)
- Adapter registry now has 6 registered adapters: claude-code, gemini-cli, cursor, generic, mcp, and agt (not auto-registered, instantiated directly)
- No blockers for remaining Phase 3 plans

## Self-Check: PASSED

All 8 files verified present. Both commit hashes (3902f33, 276a3a6) confirmed in git log.

---
*Phase: 03-framework-integration*
*Completed: 2026-04-06*
