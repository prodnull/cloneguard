---
phase: 03-framework-integration
plan: 01
subsystem: adapters
tags: [protocol, pep544, adapter-pattern, multi-agent, claude-code, gemini-cli, cursor]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: ToolCallEvent and DetectionResult dataclasses, DetectionEngine.scan()
  - phase: 02-adaptive-enforcement
    provides: PolicyEngine.evaluate(), SandboxAdapter Protocol pattern
provides:
  - InputAdapter Protocol (PEP 544 runtime_checkable) for agent-agnostic normalization
  - Adapter registry with auto-detection from JSON structure
  - ClaudeCodeAdapter, GeminiCLIAdapter, CursorAdapter, GenericAdapter implementations
  - hooks.py multi-agent dispatch via get_adapter()
affects: [03-02, 03-03, 03-04, 03-05]

# Tech tracking
tech-stack:
  added: []
  patterns: [InputAdapter Protocol, register_adapter decorator, adapter registry auto-detection]

key-files:
  created:
    - src/cloneguard/adapters/__init__.py
    - src/cloneguard/adapters/claude_code.py
    - src/cloneguard/adapters/gemini_cli.py
    - src/cloneguard/adapters/cursor.py
    - src/cloneguard/adapters/generic.py
    - tests/test_adapters.py
  modified:
    - src/cloneguard/hooks.py

key-decisions:
  - "Claude Code backward compat: hooks.py handler methods still accept raw dicts for existing 64 test compat"
  - "Non-Claude agents route through engine.scan(ToolCallEvent) generic path"
  - "GenericAdapter dumps entire JSON as content for scanning -- unknown agents get full coverage, never bypass (T-03-05)"
  - "detect_agent_type uses hook_type vs hook_event_name+workspace_roots as definitive discriminators"

patterns-established:
  - "InputAdapter Protocol: @runtime_checkable Protocol with normalize(), format_response(), agent_type"
  - "register_adapter decorator: adds adapter classes to _ADAPTERS registry dict at import time"
  - "Auto-detection: probe JSON keys (hook_type, hook_event_name, workspace_roots) to identify platform"

requirements-completed: [INTG-01]

# Metrics
duration: 8min
completed: 2026-04-06
---

# Phase 3 Plan 1: Input Adapter Abstraction Summary

**InputAdapter Protocol (PEP 544) with adapter registry auto-detecting Claude Code, Gemini CLI, and Cursor from hook JSON structure, plus GenericAdapter fallback for unknown agents**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-06T13:46:22Z
- **Completed:** 2026-04-06T13:54:32Z
- **Tasks:** 2 (TDD for Task 1: RED-GREEN, standard for Task 2)
- **Files modified:** 7

## Accomplishments

- InputAdapter Protocol with normalize(), format_response(), agent_type -- follows SandboxAdapter pattern from Phase 2
- Four adapter implementations: ClaudeCodeAdapter extracts from hook_type/tool_input/tool_output; GeminiCLIAdapter maps BeforeTool/AfterTool; CursorAdapter handles JSON-string tool_input with graceful fallback; GenericAdapter dumps entire JSON for full scanning coverage
- Adapter registry with register_adapter() decorator and get_adapter() auto-detection from JSON structure
- hooks.py refactored: main() auto-detects agent, Claude Code uses existing handlers for backward compat, non-Claude agents normalize via adapter then scan via generic engine path
- 51 adapter tests + 1613 full regression tests pass (0 failures)

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Failing adapter tests** - `82e0911` (test)
2. **Task 1 (GREEN): InputAdapter Protocol, registry, and four adapters** - `6cd6a37` (feat)
3. **Task 2: Refactor hooks.py to delegate to adapter registry** - `eb9c56e` (feat)

_TDD task had RED (failing tests) and GREEN (implementation) commits._

## Files Created/Modified

- `src/cloneguard/adapters/__init__.py` - InputAdapter Protocol, register_adapter(), detect_agent_type(), get_adapter()
- `src/cloneguard/adapters/claude_code.py` - ClaudeCodeAdapter: Claude Code hook JSON normalization
- `src/cloneguard/adapters/gemini_cli.py` - GeminiCLIAdapter: Gemini CLI BeforeTool/AfterTool mapping
- `src/cloneguard/adapters/cursor.py` - CursorAdapter: Cursor shell/MCP normalization with JSON-string parsing
- `src/cloneguard/adapters/generic.py` - GenericAdapter: best-effort fallback, scans all content
- `tests/test_adapters.py` - 51 tests: protocol conformance, normalization, response formatting, registry, hooks integration
- `src/cloneguard/hooks.py` - Multi-agent dispatch via get_adapter(), agent_type in audit events

## Decisions Made

- **Claude Code backward compatibility preserved**: The engine's scan_instructions_loaded/scan_pre_tool_use/scan_post_tool_use methods still accept raw dicts. Refactoring them to accept ToolCallEvent would require changes to 64 existing hook tests. Instead, Claude Code path uses existing handlers; non-Claude agents use engine.scan(ToolCallEvent).
- **GenericAdapter scans entire JSON dump**: When no known content fields are found, the entire raw event is JSON-serialized and scanned. This ensures unknown agent types never get a free pass (T-03-05).
- **detect_agent_type uses definitive keys**: hook_type is unique to Claude Code; hook_event_name + workspace_roots is unique to Cursor; hook_event_name alone is Gemini CLI. No ambiguity.
- **No new dependencies**: All adapters use only stdlib + existing cloneguard types. No pyproject.toml changes needed.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- PYTHONPATH needed for worktree test execution since the venv points to the main repo, not the worktree. Used `PYTHONPATH=src` prefix for all test runs.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- InputAdapter Protocol and registry ready for all subsequent Phase 3 plans
- AGT plugin (Plan 2) can implement InputAdapter or extend with ToolCallInterceptor
- MCP middleware (Plan 3) can implement InputAdapter with additional scan_response()
- CI/CD adapter (Plan 4) can implement InputAdapter for GitHub Actions webhook events
- OTel emitter (Plan 5) can consume agent_type from adapter for span attributes

## Self-Check: PASSED

All 7 files verified present. All 3 commit hashes verified in git log.

---
*Phase: 03-framework-integration*
*Completed: 2026-04-06*
