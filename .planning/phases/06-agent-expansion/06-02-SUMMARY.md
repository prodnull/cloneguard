---
phase: 06-agent-expansion
plan: 02
subsystem: enforcement
tags: [docker, gvisor, firecracker, wasm, wasmtime, sandbox, protocol, isolation]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: SandboxAdapter Protocol, Landlock/Seatbelt reference implementations
provides:
  - Docker container sandbox adapter with full enforcement depth
  - gVisor (runsc) kernel-level sandbox adapter with Docker runtime integration
  - Firecracker microVM sandbox adapter with REST API over Unix socket
  - WASM/Wasmtime process-level sandbox adapter with WASI capabilities
  - Probe functions for runtime availability detection
  - 53 Protocol conformance and probe tests
affects: [06-agent-expansion, adapter-registry, sandbox-auto-selection]

# Tech tracking
tech-stack:
  added: [docker SDK (optional), wasmtime (optional)]
  patterns: [SandboxAdapter Protocol conformance, probe-based runtime detection, adapter-specific execute_sandboxed]

key-files:
  created:
    - src/cloneguard/enforcement/docker_adapter.py
    - src/cloneguard/enforcement/wasm_adapter.py
    - src/cloneguard/enforcement/gvisor_adapter.py
    - src/cloneguard/enforcement/firecracker_adapter.py
    - tests/test_sandbox_adapters.py
  modified: []

key-decisions:
  - "All four adapters use no-op apply_restrictions() since restrictions are applied at container/VM/module creation, not process self-restriction"
  - "Firecracker uses stdlib http.client with Unix socket instead of third-party SDK (v0.0.5 pre-release)"
  - "UnixHTTPConnection extracted as module-level class for testability"

patterns-established:
  - "Adapter execute_sandboxed pattern: each adapter implements adapter-specific execution model via execute_sandboxed(target_cmd)"
  - "Probe function pattern: _probe_{adapter}() checks platform, binary availability, and runtime accessibility"
  - "Protocol conformance test pattern: 10-check template (isinstance, name, restrict_*, serialize, snapshot, rollback, audit_log)"

requirements-completed: [AGNT-05]

# Metrics
duration: 8min
completed: 2026-04-07
---

# Phase 6 Plan 2: Sandbox Adapters Summary

**Four sandbox adapters (Docker, gVisor, Firecracker, WASM) implementing SandboxAdapter Protocol with full D-07 enforcement depth and 53 Protocol conformance tests**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-07T03:13:26Z
- **Completed:** 2026-04-07T03:21:00Z
- **Tasks:** 2
- **Files created:** 5

## Accomplishments
- Four new sandbox adapters spanning VM-level (Firecracker), kernel-level (gVisor), container-level (Docker), and process-level (WASM) isolation
- All four implement SandboxAdapter Protocol with restrict_filesystem + restrict_network + restrict_syscalls + execute_sandboxed + serialize_constraints
- Probe functions correctly detect platform requirements: Docker/WASM work on macOS, gVisor/Firecracker check sys.platform == 'linux'
- 53 Protocol conformance and probe tests passing, full suite 1419 passed with 0 regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement Docker and WASM sandbox adapters** - `11e0705` (feat)
2. **Task 2: Implement gVisor and Firecracker sandbox adapters** - `2b7f819` (feat)

## Files Created/Modified
- `src/cloneguard/enforcement/docker_adapter.py` - Docker container sandbox with --cap-drop ALL, --read-only, resource limits, execute_sandboxed via docker run
- `src/cloneguard/enforcement/wasm_adapter.py` - WASM/Wasmtime sandbox with WASI capability-based restrictions, preopened directories, module execution
- `src/cloneguard/enforcement/gvisor_adapter.py` - gVisor sandbox with docker run --runtime=runsc for kernel-level syscall interception
- `src/cloneguard/enforcement/firecracker_adapter.py` - Firecracker microVM sandbox with REST API over Unix socket, KVM hardware isolation
- `tests/test_sandbox_adapters.py` - 53 tests: Protocol conformance (4 adapters x 10+ checks each), probe behavior, execute_sandboxed mock verification

## Decisions Made
- All four adapters use no-op apply_restrictions() since restrictions are applied at container/VM/module creation, not by modifying the current process (unlike Landlock/Seatbelt)
- Firecracker uses stdlib http.client with Unix domain socket connection rather than the firecracker-python SDK which is v0.0.5 pre-release
- UnixHTTPConnection extracted as module-level class (not nested in method) for testability and clean mocking in tests
- Docker/gVisor adapters include T-06-10 resource limits: --memory 512m, --cpus 1.0, --pids-limit 256

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required. Docker, wasmtime, gVisor, and Firecracker are optional runtime dependencies detected via probe functions at startup.

## Next Phase Readiness
- All four adapters ready for Plan 03 integration into adapter registry auto-selection (D-08 ranking)
- Adapters follow the same Protocol as existing Landlock/Seatbelt, drop-in compatible with get_sandbox_adapter()

---
*Phase: 06-agent-expansion*
*Completed: 2026-04-07*

## Self-Check: PASSED

- All 5 created files exist on disk
- Commit 11e0705 (Task 1) verified in git log
- Commit 2b7f819 (Task 2) verified in git log
- 53/53 tests passing
- 1419/1419 full suite passing, 0 regressions
- All 4 adapters pass isinstance(SandboxAdapter) Protocol check
- ruff check clean on all 4 adapter files
