---
phase: 04-detection-excellence
plan: 05
subsystem: detection-engine
tags: [fusion, handler-wiring, agent-type, cls-embedding, melon-decoupling]
dependency_graph:
  requires: [04-01, 04-02, 04-03]
  provides: [fusion-wired-handlers, agent-type-profiles, public-cls-api]
  affects: [engine.py, hooks.py, semantic.py, melon.py]
tech_stack:
  added: []
  patterns: [_fuse_signals_to_result-shared-helper, get_cls_embedding-public-api, hasattr-fallback-pattern]
key_files:
  created: []
  modified:
    - src/cloneguard/detection/engine.py
    - src/cloneguard/detection/semantic.py
    - src/cloneguard/detection/melon.py
    - src/cloneguard/hooks.py
    - tests/test_detection_engine.py
    - tests/test_melon.py
decisions:
  - "Shared _fuse_signals_to_result() helper extracts fusion+MELON logic from scan() for reuse across all handlers"
  - "agent_type parameter threaded from hooks.py through get_detection_engine to load_weight_profile"
  - "BLOCKED/WARNING prefixes preserved in scan_instructions_loaded via conditional prepend"
  - "melon.py uses hasattr fallback pattern for backward compat with pre-Phase-4 classifiers"
  - "_collect_signals propagates caller's ScanMode as hook_default to _detect_mode_for_tier15"
metrics:
  duration_seconds: 513
  completed: "2026-04-06T21:28:21Z"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 6
  tests_added: 7
  tests_total_passing: 122
---

# Phase 4 Plan 5: Fusion Wiring and CLS Embedding API Summary

Three-signal fusion wired into all Claude Code handler methods via _collect_signals() + _fuse_signals_to_result() shared helper; agent-type profile selection added; MiniSemanticClassifier exposes public get_cls_embedding() API that MELON uses instead of private attribute access.

## Tasks Completed

### Task 1: Wire fusion into handler methods and add agent_type support

**Commit:** `2b00ed3`

Refactored all three handler methods (`scan_instructions_loaded`, `scan_pre_tool_use`, `scan_post_tool_use`) to use `_collect_signals()` + `_fuse_signals_to_result()` instead of the old pattern-then-semantic waterfall. Created `_fuse_signals_to_result()` as a shared helper encapsulating the fusion + MELON logic that was previously inline in `scan()`. Added `agent_type` parameter to `DetectionEngine.__init__()` and `get_detection_engine()` factory, threaded through `hooks.py` `_get_bridged_engine()`.

Key changes:
- `_fuse_signals_to_result()` handles fusion layer, MELON post-fusion, and waterfall fallback
- `_collect_signals()` now propagates caller's ScanMode as `hook_default` for tier15 mode detection
- `scan_instructions_loaded()` prepends BLOCKED/WARNING prefixes to fused messages for backward compat
- `scan_pre_tool_use()` content-aware write scanning uses fusion instead of waterfall
- `scan_post_tool_use()` preserves CRITICAL severity -> exit 2 behavior through fused path
- All three Claude Code hook handlers in hooks.py pass `agent_type="claude-code"`
- Non-Claude agents pass `adapter.agent_type` to the bridged engine

5 new tests added covering fusion path for all handlers and agent_type parameter.

### Task 2: Add get_cls_embedding() to MiniSemanticClassifier and refactor melon.py

**Commit:** `bcd1d80`

Added public `get_cls_embedding(content)` method to `MiniSemanticClassifier` that extracts 384-dim CLS embeddings from the ONNX model. Refactored `melon.py::extract_cls_embedding()` to prefer the public API via `hasattr` check, with backward-compatible fallback to direct `_session`/`_tokenizer` access for pre-Phase-4 classifiers. Updated existing MELON tests to use the new mock pattern.

2 new tests added: public API usage test and fallback path test.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed _collect_signals ScanMode propagation**
- **Found during:** Task 1
- **Issue:** `_collect_signals()` hardcoded `ScanMode.STANDARD` as `hook_default` for `_detect_mode_for_tier15`, causing `scan_instructions_loaded()` (which passes `ScanMode.STRICT`) to lose the strict mode for Tier 1.5 classification.
- **Fix:** Changed line 298 to use the `mode` parameter instead of `ScanMode.STANDARD`.
- **Files modified:** `src/cloneguard/detection/engine.py`
- **Commit:** `2b00ed3`

**2. [Rule 1 - Bug] Preserved BLOCKED/WARNING message prefixes**
- **Found during:** Task 1
- **Issue:** Fusion path messages from `_format_matches()` don't include "BLOCKED:" prefix, causing existing test `test_malicious_instructions_blocked` to fail.
- **Fix:** Added conditional prefix prepend in `scan_instructions_loaded()` loop.
- **Files modified:** `src/cloneguard/detection/engine.py`
- **Commit:** `2b00ed3`

**3. [Rule 1 - Bug] Removed unused `signals` variable in scan_pre_tool_use**
- **Found during:** Task 1 (ruff check)
- **Issue:** Leftover `signals: list[SignalResult] = []` from old waterfall code no longer needed after fusion refactor.
- **Fix:** Removed the unused variable.
- **Files modified:** `src/cloneguard/detection/engine.py`
- **Commit:** `2b00ed3`

**4. [Rule 1 - Bug] Updated existing MELON test mocks for public API**
- **Found during:** Task 2
- **Issue:** Existing `TestDetect` tests used `MagicMock()` which auto-creates `get_cls_embedding` attribute, causing `extract_cls_embedding()` to call the auto-mock (returns MagicMock, not numpy array) instead of `_session`/`_tokenizer`.
- **Fix:** Updated 3 existing tests to explicitly set `get_cls_embedding.return_value` with proper numpy embeddings.
- **Files modified:** `tests/test_melon.py`
- **Commit:** `bcd1d80`

## Verification Results

| Check | Result |
|-------|--------|
| `grep -c "_collect_signals" engine.py` >= 5 | 6 |
| `grep "_fuse_signals_to_result" engine.py` >= 4 lines | 5 lines (def + 4 call sites) |
| `grep "agent_type" engine.py` in __init__, _init_fusion, get_detection_engine | Pass |
| `grep "load_weight_profile(agent_type=" engine.py` >= 1 | 1 |
| `grep "def get_cls_embedding" semantic.py` == 1 | 1 |
| `grep "classifier.get_cls_embedding" melon.py` >= 1 | 1 |
| `grep "hasattr.*get_cls_embedding" melon.py` == 1 | 1 |
| test_detection_engine.py passes | 18/18 pass |
| test_fusion.py passes | 14/14 pass |
| test_melon.py passes | 26/26 pass |
| test_hooks.py passes | 64/64 pass (1 skipped) |
| ruff check all modified files | All checks passed |
| `DetectionEngine(agent_type='claude-code')` works | OK |

## Decisions Made

1. **Shared helper over inline duplication:** Created `_fuse_signals_to_result()` as single point of truth for fusion+MELON logic rather than duplicating fusion calls in each handler. Reduces maintenance surface from 4 copies to 1.

2. **Conditional message prefixing:** Rather than modifying `_fuse_signals_to_result()` to produce "BLOCKED:" prefixed messages (which would couple it to handler-specific concerns), the prefix logic stays in `scan_instructions_loaded()` which knows the handler context.

3. **hasattr fallback in melon.py:** Uses `hasattr(classifier, "get_cls_embedding")` rather than `isinstance` check, maintaining duck-typing compatibility with any classifier-like object that exposes the method.

4. **agent_type singleton semantics:** `get_detection_engine(agent_type)` accepts agent_type on first call only; subsequent calls return the cached singleton. This matches the existing singleton pattern where configuration is set at process start.

## Self-Check: PASSED

All 7 modified/created files verified on disk. Both commit hashes (2b00ed3, bcd1d80) found in git log. 122 tests passing across 4 test files.
