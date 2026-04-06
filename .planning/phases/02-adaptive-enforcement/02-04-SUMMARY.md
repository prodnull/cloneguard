---
phase: 02-adaptive-enforcement
plan: 04
subsystem: enforcement/registry
tags: [hallucination, slopsquatting, registry, npm, pypi, detection-signal]
dependency_graph:
  requires: [detection-types]
  provides: [package-hallucination-signal, registry-client]
  affects: [detection-engine]
tech_stack:
  added: [urllib.request]
  patterns: [session-cache, lazy-loading, graceful-degradation, tdd]
key_files:
  created:
    - src/cloneguard/enforcement/__init__.py
    - src/cloneguard/enforcement/registry.py
    - tests/test_enforcement_registry.py
    - tests/test_detection_engine_hallucination.py
  modified:
    - src/cloneguard/detection/engine.py
decisions:
  - Used stdlib urllib.request instead of httpx/requests -- zero new dependencies
  - Regex-based package extraction with explicit flag/path/VCS filtering
  - Session cache keyed by (package, registry) tuple for deduplication
  - Hallucination check placed between pattern scan and build warnings in scan_pre_tool_use
  - try/except around registry check in engine to ensure hook pipeline never breaks
metrics:
  duration: 7m
  completed: "2026-04-06T01:30:33Z"
  tasks_completed: 2
  tasks_total: 2
  tests_added: 39
  tests_total_passing: 116
---

# Phase 02 Plan 04: Package Hallucination Detection Summary

Package hallucination detection via npm/PyPI registry cross-referencing using stdlib urllib with session caching and 3-second timeout

## What Was Built

PackageRegistryClient extracts package names from `npm install`, `pip install`, `pip3 install`, and `yarn add` commands, then checks each against the corresponding public registry API (registry.npmjs.org for npm, pypi.org for PyPI). A 404 response indicates a hallucinated package name, producing a `SignalResult` with `signal_type="package_hallucination"` and `verdict="detected"` at 0.95 confidence. This feeds into the standard detection pipeline via `DetectionEngine.scan_pre_tool_use()`.

The check is positioned after the injection pattern scan and before the build command warnings, ensuring hallucinated packages are caught before the generic build warning masks the issue. Network failures always degrade gracefully -- skip check, log warning, never block the agent.

## Task Execution

### Task 1: PackageRegistryClient with npm and PyPI checks (TDD)

- **RED:** 33 failing tests covering extraction, HTTP mocking, caching, graceful degradation
- **GREEN:** Implemented `PackageRegistryClient` with `extract_packages()`, `check_package()`, `check_packages_for_hallucination()`
- **Commits:** `846789b` (red), `145d285` (green)
- **Tests:** 33 pass

### Task 2: Integrate package hallucination into DetectionEngine (TDD)

- **RED:** 6 failing integration tests covering full scan_pre_tool_use path
- **GREEN:** Added `_registry_client` field, `_get_registry_client()` lazy loader, hallucination check block in `scan_pre_tool_use()`
- **Commits:** `0270d5a` (red), `851311c` (green)
- **Tests:** 6 pass, 77 existing engine+hook tests unaffected

## Deviations from Plan

None -- plan executed exactly as written.

## Decisions Made

1. **stdlib urllib over httpx/requests:** Zero new dependencies. The registry check is a simple GET with timeout -- no connection pooling or async needed.
2. **Regex extraction strategy:** Three regex patterns (npm install, pip install, yarn add) with post-extraction token filtering for flags, paths, VCS URLs, and version specifiers.
3. **Integration placement:** Between pattern scan (line ~630) and build command warnings (line ~650) in `scan_pre_tool_use()`. This ensures hallucinated packages get caught before the build warning early return.
4. **Exception wrapping in engine:** The entire registry check is wrapped in `try/except Exception: pass` to guarantee the hook pipeline is never broken by registry client failures.

## Verification Results

| Check | Result |
|-------|--------|
| test_enforcement_registry.py | 33 passed |
| test_detection_engine_hallucination.py | 6 passed |
| test_detection_engine.py | 13 passed |
| test_hooks.py | 64 passed, 1 skipped |
| ruff check (both files) | clean |
| mypy --strict (both files) | clean |

## Self-Check: PASSED

All 4 created files exist. All 4 commits verified in git log.
