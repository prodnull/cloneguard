---
phase: 01-foundation
plan: 03
subsystem: audit-cli-packaging
tags: [sarif, integrity, packaging, version-fix, cli, sarif-pydantic]

# Dependency graph
requires:
  - "01-01: DetectionEngine with PatternEngine for rule enumeration"
  - "01-02: audit package with Pydantic v2 AuditEvent and NDJSONEmitter"
provides:
  - "cloneguard.audit.sarif: SARIF 2.1.0 emitter using sarif-pydantic (D-08, D-09, D-10)"
  - "cloneguard.integrity: Hook config integrity self-check (D-13, CVE-2025-59536 defense)"
  - "CLI --sarif flag and CLONEGUARD_SARIF_OUTPUT env var for SARIF output"
  - "CLI --check-hooks subcommand for manual integrity verification"
  - "Fixed __version__ = 0.5.0 matching pyproject.toml"
  - "sarif-pydantic>=0.6 as core dependency"
affects: [02-adapter-layer, 03-integration, github-actions-ci]

# Tech tracking
tech-stack:
  added: ["sarif-pydantic>=0.6 (SARIF 2.1.0 model generation)"]
  patterns:
    - "SARIF emitter using sarif-pydantic for schema-correct serialization (D-10)"
    - "Verdict-to-level mapping via dict lookup keyed by verdict_severity (D-09)"
    - "SHA-256 partialFingerprints for cross-run deduplication"
    - "Result cap at 5,000 per GitHub Advanced Security limits"
    - "Command-pattern integrity check (substring match, not path comparison) per Pitfall 5"
    - "Once-per-process startup integrity check via env var flag"

key-files:
  created:
    - src/cloneguard/audit/sarif.py
    - src/cloneguard/integrity.py
    - tests/test_sarif_emitter.py
    - tests/test_integrity.py
  modified:
    - src/cloneguard/audit/__init__.py
    - src/cloneguard/cli.py
    - src/cloneguard/__init__.py
    - pyproject.toml

key-decisions:
  - "sarif-pydantic added to mypy overrides (no py.typed marker in library)"
  - "SARIFEmitter.emit_json() returns JSON string; CLI handles stdout vs file routing"
  - "_scan_report_to_sarif_dicts() bridges ScanReport FileResult to SARIF result dicts"
  - "Integrity check runs once per process via _CLONEGUARD_INTEGRITY_CHECKED env var guard"

patterns-established:
  - "SARIF output: build_sarif() returns sarif-pydantic Sarif object, serialize with model_dump_json(by_alias=True)"
  - "Pattern rule enumeration: _build_rules_from_patterns() iterates PatternEngine.rules for reportingDescriptors"
  - "Integrity self-check: substring match on command pattern, warn-only (never block)"

requirements-completed: [FNDN-03, FNDN-04, FNDN-05]

# Metrics
duration: 8min
completed: 2026-04-05
---

# Phase 01 Plan 03: SARIF Emitter, Packaging, and Integrity Check Summary

**SARIF 2.1.0 emitter using sarif-pydantic with verdict-to-level mapping, fixed packaging for standalone install (version 0.5.0), and hook config integrity self-check defending against CVE-2025-59536-class tampering**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-05T23:15:44Z
- **Completed:** 2026-04-05T23:23:58Z
- **Tasks:** 2 (both TDD: RED + GREEN)
- **Files modified:** 8

## Accomplishments
- SARIF 2.1.0 emitter produces valid output using sarif-pydantic per D-10. Verdict-to-level mapping: DETECTED+CRITICAL/HIGH to ERROR, MEDIUM to WARNING, LOW to NOTE, SUSPICIOUS to WARNING, CLEAN not emitted (D-09)
- All 204 pattern rules mapped to SARIF reportingDescriptors via _build_rules_from_patterns()
- Results capped at 5,000 with partialFingerprints SHA-256 hashes for GitHub Advanced Security dedup (T-03-03)
- CLI supports --sarif flag on scan subcommand and CLONEGUARD_SARIF_OUTPUT env var for file output (D-08)
- Version discrepancy fixed: __init__.py now declares 0.5.0 matching pyproject.toml (Pitfall 2)
- sarif-pydantic>=0.6 added as core dependency alongside pydantic>=2.0 (D-11)
- Hook config integrity self-check detects tampered settings.json (D-13, CVE-2025-59536)
- Checks command pattern substring, not binary path -- tolerates uv/pipx/venv installs (Pitfall 5)
- CLI --check-hooks subcommand for manual verification; hook-check path runs integrity once per process
- Wheel builds as cloneguard-0.5.0-py3-none-any.whl with entry point cloneguard=cloneguard.cli:main (D-12)
- 22 new tests (15 SARIF + 7 integrity), 1300 total tests passing, ruff clean, mypy --strict clean

## Task Commits

Each task was committed atomically:

1. **Task 1: SARIF emitter (TDD RED)** - `3946e32` (test)
2. **Task 1: SARIF emitter (TDD GREEN)** - `169b3a4` (feat)
3. **Task 2: Integrity check (TDD RED)** - `7495068` (test)
4. **Task 2: Integrity check (TDD GREEN)** - `af432e5` (feat)

## Files Created/Modified
- `src/cloneguard/audit/sarif.py` - SARIF 2.1.0 emitter: build_sarif(), _build_rules_from_patterns(), SARIFEmitter class, _compute_fingerprint(), _MAX_RESULTS=5000
- `src/cloneguard/integrity.py` - Hook config integrity check: check_hook_integrity(), _EXPECTED_COMMAND_PREFIX, _EXPECTED_EVENTS
- `tests/test_sarif_emitter.py` - 15 tests: SARIF structure, verdict mapping (6 levels), rules, tool info, locations, result cap, fingerprints, emitter class, pattern engine integration
- `tests/test_integrity.py` - 7 tests: valid config, bad command, missing events, missing file, malformed JSON, path-agnostic, version match
- `src/cloneguard/audit/__init__.py` - Added SARIFEmitter and build_sarif re-exports
- `src/cloneguard/cli.py` - Added --sarif flag on scan, CLONEGUARD_SARIF_OUTPUT env var, --check-hooks subcommand, startup integrity check in hook-check path
- `src/cloneguard/__init__.py` - Fixed __version__ from "0.2.2" to "0.5.0"
- `pyproject.toml` - Added sarif-pydantic>=0.6 to dependencies, sarif_pydantic.* to mypy overrides

## Decisions Made
- **sarif-pydantic mypy override:** Library lacks py.typed marker, so added to ignore_missing_imports in pyproject.toml alongside existing sklearn/scipy overrides
- **SARIFEmitter design:** emit_json() returns a JSON string rather than writing directly, letting the CLI control output destination (stdout vs file)
- **ScanReport to SARIF bridge:** _scan_report_to_sarif_dicts() converts FileResult status/issues to SARIF-compatible dicts -- keeps SARIF emitter decoupled from scanner internals
- **Integrity check timing:** Once per process via _CLONEGUARD_INTEGRITY_CHECKED env var, runs in hook-check path only (not scan), wrapped in try/except to never block hook execution

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None -- all tasks executed smoothly.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Phase 1 Foundation complete: detection package extracted (Plan 01), audit layer with NDJSON (Plan 02), SARIF output + packaging + integrity (Plan 03)
- All 1300 tests pass across the full suite
- Phase 2 (Enforcement/Adapter) can now build on the detection engine, audit events, and SARIF output
- CLI ready for standalone use via `uv tool install cloneguard`

## Self-Check: PASSED

All 4 created files verified present. All 4 task commits verified in git log.

---
*Phase: 01-foundation*
*Completed: 2026-04-05*
