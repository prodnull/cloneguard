---
phase: 06-agent-expansion
plan: 03
subsystem: enforcement
tags: [sandbox, adapter-registry, auto-selection, dispatch, integration]
dependency_graph:
  requires: [06-01, 06-02]
  provides: [adapter-registry-wiring, sandbox-exec-dispatch, pyproject-extras]
  affects: [enforcement-pipeline, sandbox-exec]
tech_stack:
  added: []
  patterns: [lazy-import-probes, frozenset-dispatch, adapter-execute-sandboxed]
key_files:
  created: []
  modified:
    - src/cloneguard/enforcement/adapter.py
    - src/cloneguard/enforcement/sandbox_exec.py
    - pyproject.toml
    - tests/test_sandbox_adapters.py
    - tests/test_patterns.py
decisions:
  - "Lazy probe wrappers use try/except ImportError to avoid pulling optional deps at module load"
  - "External adapters dispatch via execute_sandboxed; self-restrict adapters use existing apply+exec"
  - "Added docker>=7.1 and wasmtime>=43.0 to pyproject.toml all extra"
metrics:
  duration: ~5 minutes
  completed: 2026-04-07
  tasks: 2
  files: 5
---

# Phase 06 Plan 03: Adapter Registry Wiring and Sandbox Exec Dispatch Summary

Wired 4 new sandbox adapters into the strength-ordered registry (D-08: Firecracker > gVisor > Docker > WASM > Landlock > Seatbelt), extended sandbox_exec.py with dual dispatch model (external execution vs self-restrict+exec), and added pyproject.toml optional extras.

## Changes Made

### Task 1: Adapter Registry and Sandbox Exec Dispatch (145cead)

**adapter.py:**
- Added 4 lazy probe wrapper functions (`_probe_firecracker_lazy`, `_probe_gvisor_lazy`, `_probe_docker_lazy`, `_probe_wasm_lazy`) that import probe functions from adapter modules only when called, avoiding optional dependency imports at module load time
- Updated `_ADAPTER_REGISTRY` from 2 entries (landlock, seatbelt) to 6 entries in D-08 strength order

**sandbox_exec.py:**
- Added `_EXTERNAL_EXEC_ADAPTERS` frozenset (docker, gvisor, firecracker, wasm) and `_SELF_RESTRICT_ADAPTERS` frozenset (landlock, seatbelt, noop, auto)
- Added `_execute_via_adapter()` function that applies constraints then dispatches to `adapter.execute_sandboxed()`, handling both `subprocess.CompletedProcess` (Docker/gVisor) and `dict` (Firecracker/WASM) return types
- Modified `main()` to check adapter type before dispatching: external adapters route to `_execute_via_adapter`, self-restrict adapters use existing apply+exec path

### Task 2: PyProject Extras and Integration Tests (f144e63)

**pyproject.toml:**
- Added `docker = ["docker>=7.1"]`, `wasm = ["wasmtime>=43.0"]`, `sandbox = ["docker>=7.1", "wasmtime>=43.0"]` optional extras
- Updated `all` extra to include docker and wasmtime

**test_sandbox_adapters.py (4 new tests):**
- `TestAutoSelection.test_registry_strength_order` -- verifies 6-adapter D-08 order
- `TestAutoSelection.test_auto_select_falls_through_to_noop` -- all probes False yields NoopAdapter
- `TestAutoSelection.test_auto_select_picks_strongest_available` -- mock Docker probe True, verify selection
- `TestAutoSelection.test_preferred_override` -- operator override to noop

**test_sandbox_adapters.py (2 dispatch tests):**
- `TestSandboxExecDispatch.test_external_exec_adapters_set` -- frozenset contents
- `TestSandboxExecDispatch.test_self_restrict_adapters_set` -- frozenset contents

**test_patterns.py (2 new tests):**
- `TestAgentTypePatternLoading.test_agent_type_categories_loaded` -- 8 agent-type categories present
- `TestAgentTypePatternLoading.test_no_pattern_id_collisions` -- no duplicate IDs across all rules

## Deviations from Plan

None - plan executed exactly as written.

## Test Results

- Full suite: 1479 passed, 127 skipped, 1 xfailed, 0 failed
- Focused suite (sandbox_adapters + patterns): 193 passed
- ruff check: all checks passed
- Pre-existing failures (numpy/sklearn deps): test_mahalanobis.py, test_train_freelb.py, test_transfer_experiment.py, test_augmentation.py -- excluded (not related to this plan)

## Threat Mitigations

- **T-06-13 (Registry tampering):** `_ADAPTER_REGISTRY` remains a module-level constant list; only `preferred` parameter in policy.yaml can override selection
- **T-06-14 (Dispatch bypass):** `_EXTERNAL_EXEC_ADAPTERS` is a frozenset constant; adapter name sourced from constraint spec file written by hook handler
- **T-06-15 (Import failure DoS):** All lazy probe wrappers wrap ImportError, gracefully falling through to next adapter

## Self-Check: PASSED
