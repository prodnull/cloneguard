---
phase: 02-adaptive-enforcement
plan: 03
subsystem: enforcement
tags: [sandbox, landlock, seatbelt, os-enforcement, wrapper-binary]
dependency_graph:
  requires: [02-01]
  provides: [LandlockAdapter, SeatbeltAdapter, sandbox-exec-entrypoint]
  affects: [02-05]
tech_stack:
  added: [ctypes-landlock, ctypes-seatbelt, sandbox-exec-entrypoint]
  patterns: [wrapper-binary-exec, constraint-serialization, deny-default-sbpl]
key_files:
  created:
    - src/cloneguard/enforcement/landlock.py
    - src/cloneguard/enforcement/seatbelt.py
    - src/cloneguard/enforcement/sandbox_exec.py
    - tests/test_enforcement_landlock.py
    - tests/test_enforcement_seatbelt.py
    - tests/test_enforcement_sandbox_exec.py
  modified:
    - src/cloneguard/enforcement/adapter.py
    - tests/test_enforcement_adapter.py
    - pyproject.toml
decisions:
  - apply_restrictions() added to SandboxAdapter Protocol (required for mypy strict compliance at sandbox_exec boundary)
  - O_PATH constant handled via getattr fallback for cross-platform compatibility in landlock.py
  - Pre-existing adapter test mock fixed (registry stores function refs, not strings)
metrics:
  duration_seconds: 1914
  completed: "2026-04-06T01:52:25Z"
  tasks_completed: 2
  tasks_total: 2
  tests_added: 45
  files_created: 6
  files_modified: 3
---

# Phase 02 Plan 03: OS-Level Sandbox Adapters Summary

Landlock (Linux) and Seatbelt (macOS) adapters with ctypes syscalls, plus cloneguard-sandbox-exec wrapper binary that applies OS sandbox before exec'ing the target command.

## Task Results

| Task | Name | Commit | Status |
|------|------|--------|--------|
| 1 | LandlockAdapter and SeatbeltAdapter with apply_restrictions() | b4ca5b8, 51d82fe | Done |
| 2 | cloneguard-sandbox-exec wrapper entry point | 5ace37e | Done |

## What Was Built

### LandlockAdapter (landlock.py)
- ctypes-based Linux Landlock LSM enforcement via syscalls 444-446
- ABI version detection at init (v1-v4 support, v4 enables network)
- apply_restrictions(): prctl -> create_ruleset -> add_rule per path -> restrict_self
- Always-allowed minimum paths: /tmp writable; /proc, /dev/null, /dev/urandom, /usr/lib, /etc readable
- Graceful degradation on ENOSYS, missing libc, or any syscall failure
- serialize_constraints() for JSON cross-process transport

### SeatbeltAdapter (seatbelt.py)
- ctypes-based macOS Seatbelt enforcement via libSystem.dylib sandbox_init_with_parameters
- Generates deny-default SBPL profiles with selective allows
- Path escaping prevents SBPL injection (T-02-15): backslashes doubled, quotes escaped
- Always-allowed: /tmp, /private/tmp, /private/var/folders writable; system libs readable
- Graceful degradation on missing libSystem or sandbox_init failure
- serialize_constraints() for JSON cross-process transport

### cloneguard-sandbox-exec (sandbox_exec.py)
- Wrapper binary entry point: reads constraint spec, applies OS sandbox, exec's target
- Two input modes: --spec-file (production, avoids ps leakage) and --policy (base64, convenience)
- Spec file deleted after read (one-shot enforcement, prevents replay per T-02-14)
- Fail-open: any constraint loading/applying error falls through to unrestricted exec
- write_constraint_spec() helper creates mkstemp temp file with 0600 permissions
- Registered in pyproject.toml as cloneguard-sandbox-exec entry point

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] O_PATH constant unavailable on macOS**
- **Found during:** Task 1
- **Issue:** `os.O_PATH` is Linux-only; tests run on macOS host
- **Fix:** Used `getattr(os, "O_PATH", 0x200000)` fallback in landlock.py; mocked os.open/os.close in tests
- **Files modified:** src/cloneguard/enforcement/landlock.py, tests/test_enforcement_landlock.py

**2. [Rule 3 - Blocking] apply_restrictions() not on SandboxAdapter Protocol**
- **Found during:** Task 2 (mypy --strict)
- **Issue:** sandbox_exec.py calls adapter.apply_restrictions() but Protocol lacked it
- **Fix:** Added apply_restrictions() to SandboxAdapter Protocol and NoopAdapter
- **Files modified:** src/cloneguard/enforcement/adapter.py

**3. [Rule 1 - Bug] Pre-existing test_enforcement_adapter probe mock ineffective**
- **Found during:** Task 2 (regression check)
- **Issue:** _ADAPTER_REGISTRY stores function refs at import time; mock.patch on module attr doesn't reach stored refs. Test passed before only because seatbelt.py module didn't exist.
- **Fix:** Mock _ADAPTER_REGISTRY directly instead of individual probe functions
- **Files modified:** tests/test_enforcement_adapter.py

## Known Stubs

None -- all adapters are fully wired with real OS syscall paths (mocked in tests, real at runtime).

## Threat Mitigations Applied

| Threat ID | Mitigation |
|-----------|------------|
| T-02-11 | apply_restrictions() only called from sandbox_exec.main(), never from hook handler |
| T-02-12 | Landlock resolves symlinks natively; Seatbelt paths used as-is (SBPL subpath matching) |
| T-02-13 | Always-allowed minimum paths prevent tool breakage |
| T-02-14 | mkstemp (0600) + immediate unlink after read |
| T-02-15 | _escape_sbpl_path() doubles backslashes and escapes quotes |
| T-02-17 | Constraints are additive-only; worst case is NoopAdapter behavior |

## Self-Check: PASSED

- All 7 created files verified on disk
- All 3 commits (b4ca5b8, 51d82fe, 5ace37e) verified in git log
- 64 tests pass across all enforcement test files
- ruff check clean, mypy --strict clean on all new source files
