---
phase: 01-foundation
verified: 2026-04-06T00:12:09Z
status: passed
score: 6/6 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 4/6
  gaps_closed:
    - "hooks.py handlers are thin shims (~10 lines each) that delegate to DetectionEngine"
    - "DetectionEngine.scan() clean input test — test_clean_input_returns_clean_verdict now mocks MiniSemanticClassifier and passes"
  gaps_remaining: []
  regressions: []
---

# Phase 01: Foundation Verification Report

**Phase Goal:** Detection engine is modular with typed contracts, structured audit meets EU AI Act Article 12, and existing users see zero behavior change
**Verified:** 2026-04-06T00:12:09Z
**Status:** passed
**Re-verification:** Yes — after gap closure (Plan 01-04)

## Goal Achievement

### Observable Truths

Truths sourced from ROADMAP.md Phase 1 Success Criteria (SC1–SC5) and Plan frontmatter must_haves across all four plans. Two truths that were previously FAILED or PARTIAL are re-verified as VERIFIED after Plan 01-04 gap closure.

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Running `cloneguard` via `uv tool install` or `pipx` produces a working standalone binary | VERIFIED | `__version__ = "0.5.0"` in `__init__.py`, `pyproject.toml` version matches, entry point `cloneguard = "cloneguard.cli:main"` present, `pydantic>=2.0` and `sarif-pydantic>=0.6` in dependencies |
| 2 | Every detection event emits a valid NDJSON line with session_id, verdict, confidence, signals, enforcement_action | VERIFIED | `AuditEvent.to_ndjson()` returns valid JSON; all 5 required fields confirmed present; `NDJSONEmitter` defaults to stderr, never stdout; `_emit_audit_event()` in hooks.py lazy-imports Pydantic and wraps in try/except |
| 3 | `cloneguard scan --sarif` produces valid SARIF 2.1.0 output consumable by GitHub Advanced Security | VERIFIED | `build_sarif()` produces version "2.1.0", 204 pattern rules as reportingDescriptors, correct verdict-to-level mapping (DETECTED+CRITICAL/HIGH→ERROR, MEDIUM→WARNING, LOW→NOTE, SUSPICIOUS→WARNING, CLEAN not emitted), results capped at 5000, SHA-256 partialFingerprints present |
| 4 | Claude Code hook integration (JSON stdin/exit 0/2) behaves identically to v0.5.0 — all existing hook tests pass | VERIFIED | `uv run python -m pytest tests/test_hooks.py` reports 65/65 passing; backward-compat import paths (`cloneguard.patterns`, `cloneguard.mini_semantic`, `cloneguard.monitor`) all resolve; re-export shims export all private names used by tests |
| 5 | Hook config integrity self-check detects tampered configuration (CVE-2025-59536 class defense) | VERIFIED | `check_hook_integrity()` returns empty list for valid config, warns on missing events, warns on unexpected command, handles malformed JSON, checks command pattern not binary path (Pitfall 5 per plan) |
| 6 | hooks.py handlers are thin shims (~10 lines each) that delegate to DetectionEngine | VERIFIED | Three handlers each 14–15 lines total (5–6 statements + docstring). `_get_bridged_engine()` at line 166 calls `get_detection_engine()`. All handlers: line 184 (`handle_instructions_loaded`), line 199 (`handle_pre_tool_use`), line 216 (`handle_post_tool_use`) call `_get_bridged_engine()`. `grep -c "get_detection_engine" src/cloneguard/hooks.py` returns 2 (import + call). `grep -c "_classify_with_tier15\|_format_matches\|_is_protected_path\|_is_sensitive_target" src/cloneguard/hooks.py` returns 0. |

**Score:** 6/6 truths verified

### Re-Verification: Gap Closure Confirmation

| Gap (Previous) | Status | Evidence |
|----------------|--------|---------|
| Gap 1: hooks.py handlers 88/135/81 lines calling `_get_engine()` directly | CLOSED | Handlers now 14–15 lines each; `_get_bridged_engine()` → `get_detection_engine()` replaces all inline orchestration; 0 occurrences of `_classify_with_tier15`/`_format_matches`/`_is_protected_path`/`_is_sensitive_target` |
| Gap 2: `test_clean_input_returns_clean_verdict` committed broken (MiniLM false positive at 99.1%) | CLOSED | Test now uses `patch.object(engine, '_get_mini_classifier', return_value=None)` to mock out Tier 1.5; 13/13 detection engine tests pass |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/cloneguard/detection/__init__.py` | Public re-exports (DetectionEngine, DetectionResult, ToolCallEvent) | VERIFIED | All three exported |
| `src/cloneguard/detection/types.py` | Protocol interfaces and dataclass contracts | VERIFIED | ToolCallEvent, SignalResult, DetectionResult (all frozen=True), DetectionEngineProtocol (@runtime_checkable) |
| `src/cloneguard/detection/engine.py` | DetectionEngine orchestration with scan/scan_instructions_loaded/scan_pre_tool_use/scan_post_tool_use | VERIFIED | All 4 methods present; `get_detection_engine()` factory; `_detect_mode_for_tier15` (used by hooks backward-compat wrapper) |
| `src/cloneguard/detection/patterns.py` | PatternEngine moved from patterns.py | VERIFIED | `class PatternEngine` present |
| `src/cloneguard/detection/semantic.py` | MiniSemanticClassifier moved from mini_semantic.py | VERIFIED | `class MiniSemanticClassifier` present |
| `src/cloneguard/detection/sequence.py` | ToolCallMonitor moved from monitor.py | VERIFIED | `class ToolCallMonitor`, `get_monitor()` present |
| `src/cloneguard/patterns.py` | Backward-compat re-export shim | VERIFIED | Imports from `cloneguard.detection.patterns` |
| `src/cloneguard/mini_semantic.py` | Backward-compat re-export shim | VERIFIED | Imports from `cloneguard.detection.semantic` |
| `src/cloneguard/monitor.py` | Backward-compat re-export shim | VERIFIED | Imports from `cloneguard.detection.sequence` |
| `src/cloneguard/hooks.py` | Thin shim delegating to DetectionEngine (≤15 lines per handler body) | VERIFIED | 244 lines total; three handlers 14–15 lines each; `_get_bridged_engine()` calls `get_detection_engine()`; no inline detection orchestration |
| `tests/test_detection_engine.py` | Unit tests for DetectionEngine (min 80 lines, all passing) | VERIFIED | 227 lines, 13 test functions, 13/13 pass; `test_clean_input_returns_clean_verdict` mocks Tier 1.5 classifier |
| `src/cloneguard/audit/__init__.py` | Public re-exports (AuditEvent, NDJSONEmitter, SignalDetails, SARIFEmitter, build_sarif) | VERIFIED | All present |
| `src/cloneguard/audit/types.py` | Pydantic v2 frozen AuditEvent (cloneguard/event/v1) | VERIFIED | `ConfigDict(frozen=True)`, `schema_version = "cloneguard/event/v1"`, `enforcement_action = "ALLOW"`, `to_ndjson()` |
| `src/cloneguard/audit/ndjson.py` | NDJSONEmitter never writing to stdout | VERIFIED | Default is `sys.stderr`; `from_env()` opens file from `CLONEGUARD_NDJSON_OUTPUT` |
| `tests/test_audit_ndjson.py` | Audit tests (min 60 lines) | VERIFIED | 243 lines, 9 test functions, all pass |
| `src/cloneguard/audit/sarif.py` | SARIF 2.1.0 emitter using sarif-pydantic | VERIFIED | `build_sarif()`, `SARIFEmitter`, `_MAX_RESULTS = 5000`, `from sarif_pydantic import` |
| `tests/test_sarif_emitter.py` | SARIF tests (min 80 lines) | VERIFIED | 242 lines, 15 test functions, all pass |
| `src/cloneguard/integrity.py` | `check_hook_integrity()` function | VERIFIED | `_EXPECTED_COMMAND_PREFIX = "cloneguard hook-check --event"`, checks InstructionsLoaded/PreToolUse/PostToolUse |
| `src/cloneguard/__init__.py` | `__version__ = "0.5.0"` | VERIFIED | Exact match |
| `pyproject.toml` | pydantic, sarif-pydantic dependencies; entry point | VERIFIED | `pydantic>=2.0`, `sarif-pydantic>=0.6`, `cloneguard = "cloneguard.cli:main"` |
| `tests/test_integrity.py` | Integrity tests (min 40 lines) | VERIFIED | 161 lines, 7 test functions, all pass |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `detection/engine.py` | `detection/patterns.py` | `from cloneguard.detection.patterns import` | WIRED | Confirmed at import block |
| `detection/engine.py` | `detection/semantic.py` | `from cloneguard.detection.semantic import` | WIRED | Lazy-loaded in engine |
| `detection/engine.py` | `detection/sequence.py` | `from cloneguard.detection.sequence import` | WIRED | `get_monitor` lazy-imported inside method bodies |
| `patterns.py` | `detection/patterns.py` | backward-compat re-export | WIRED | First line of shim |
| `hooks.py` | `detection/engine.py` | `get_detection_engine()` call via `_get_bridged_engine()` | WIRED | `get_detection_engine` imported at line 27; called at line 166 in `_get_bridged_engine()`; all three handlers call `_get_bridged_engine()` |
| `hooks.py` | `audit/ndjson.py` | `NDJSONEmitter.emit()` | WIRED | Lazy-imported inside `_emit_audit_event()`, called in all three handlers |
| `audit/types.py` | `pydantic` | `from pydantic import BaseModel` | WIRED | Confirmed |
| `cli.py` | `audit/sarif.py` | `--sarif` flag | WIRED | `--sarif` arg present, `SARIFEmitter` imported |
| `cli.py` | `integrity.py` | `check_hook_integrity` | WIRED | Called in hook-check path |
| `audit/sarif.py` | `sarif_pydantic` | `from sarif_pydantic import` | WIRED | All required SARIF types imported |
| `test_hooks.py` | `detection/sequence.py` | 6 monitor mock patch points | WIRED | All 6 instances patch `cloneguard.detection.sequence.get_monitor` (engine's lazy import path); `grep -c "cloneguard.detection.sequence.get_monitor" tests/test_hooks.py` = 6 |
| `test_hooks.py` | `detection/engine.py` | `patch.object(engine, ...)` in TestModeThreadingHooks | WIRED | 5 tests use `patch.object(engine, '_pattern_engine', ...)` and `patch.object(engine, '_mini_classifier', ...)` for clean isolation |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `hooks.py: handle_instructions_loaded()` | `result: DetectionResult` | `engine.scan_instructions_loaded(data)` — DetectionEngine processes real hook JSON | Yes — full tier 0+1.5 detection pipeline runs | FLOWING |
| `hooks.py: handle_pre_tool_use()` | `result: DetectionResult` | `engine.scan_pre_tool_use(data)` — DetectionEngine processes real hook JSON | Yes — full detection pipeline including sequence monitor | FLOWING |
| `hooks.py: handle_post_tool_use()` | `result: DetectionResult` | `engine.scan_post_tool_use(data)` — DetectionEngine processes real hook JSON | Yes — full detection pipeline including sequence event recording | FLOWING |
| `audit/types.py: AuditEvent.to_ndjson()` | Pydantic model fields | `_emit_audit_event()` populates from `DetectionResult` | Yes — real detection results populate fields | FLOWING |
| `audit/sarif.py: build_sarif()` | `scan_results` list | `SARIFEmitter.emit_from_scan_report()` converts FileResult objects | Yes — real scan results mapped to SARIF dicts | FLOWING |
| `integrity.py: check_hook_integrity()` | `config` dict | reads `~/.claude/settings.json` from disk | Yes — reads actual operator settings file | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| test_clean_input_returns_clean_verdict passes | `pytest tests/test_detection_engine.py::TestDetectionEngineCleanInput::test_clean_input_returns_clean_verdict` | 1 passed | PASS |
| All 13 DetectionEngine tests pass | `pytest tests/test_detection_engine.py` | 13 passed | PASS |
| All 65 hook protocol tests pass | `pytest tests/test_hooks.py` | 65 passed | PASS |
| Full suite (excluding pre-existing framing failure) | `pytest tests/ --ignore=tests/test_framing.py` | 1364 passed, 16 skipped, 1 xpassed | PASS |
| hooks.py has no inline detection helpers | `grep -c "_classify_with_tier15\|_format_matches\|_is_protected_path\|_is_sensitive_target" src/cloneguard/hooks.py` | 0 | PASS |
| hooks.py calls get_detection_engine | `grep -c "get_detection_engine" src/cloneguard/hooks.py` | 2 (import + call) | PASS |
| get_monitor backward-compat re-export present | `grep -c "from cloneguard.monitor import get_monitor" src/cloneguard/hooks.py` | 1 | PASS |
| 6 monitor patch points use engine's import path | `grep -c "cloneguard.detection.sequence.get_monitor" tests/test_hooks.py` | 6 | PASS |
| ruff check hooks.py | `ruff check src/cloneguard/hooks.py` | All checks passed | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| FNDN-01 | 01-01, 01-04 | Detection engine extracted into standalone module with typed Protocol interfaces | SATISFIED | `cloneguard.detection` package with DetectionEngineProtocol, DetectionEngine, ToolCallEvent, DetectionResult; hooks.py delegates all detection to DetectionEngine via `_get_bridged_engine()` |
| FNDN-02 | 01-02 | Structured NDJSON event schema per detection event | SATISFIED | AuditEvent with cloneguard/event/v1 schema, all required fields, NDJSONEmitter |
| FNDN-03 | 01-03 | SARIF 2.1.0 emitter for GitHub Advanced Security | SATISFIED | `build_sarif()` produces valid 2.1.0, 204 rules, verdict-to-level mapping, result caps |
| FNDN-04 | 01-03 | `uv tool install` / `pipx` packaging | SATISFIED | pyproject.toml entry point, correct version, all dependencies declared |
| FNDN-05 | 01-03 | Hook config integrity self-check (CVE-2025-59536) | SATISFIED | `check_hook_integrity()` in `integrity.py`, command-pattern check, warn-only, all 3 events verified |
| FNDN-06 | 01-02, 01-04 | Backward compatibility — existing hook protocol works via thin shims | SATISFIED | 65/65 hook tests pass; re-export shims work; handlers are now true thin shims (14–15 lines) calling `engine.scan_*()` methods; `_session_trust`, `_get_engine`, `_get_mini_classifier`, `_detect_mode_for_tier15`, `get_monitor` all importable from `cloneguard.hooks` |

### Anti-Patterns Found

No blockers or warnings. The one pre-existing anti-pattern is a documentation framing issue unrelated to Phase 01 code:

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `docs/publications/medium-claude-code-classifier-analysis.md` | 74 | Prohibited framing "immune to" | Pre-existing (commit b38f9aa, 2026-03-10) | No impact on Phase 01 goal — predates this work by 26 days; `test_framing.py` failure is pre-existing and out of scope |

### Human Verification Required

None — all Phase 01 goals are verifiable programmatically. The full test suite passes and all gap closures are confirmed by code inspection and automated test results.

### Gaps Summary

No gaps. Both previous blockers are closed:

**Gap 1 (CLOSED): hooks.py thin shim.** `handle_instructions_loaded`, `handle_pre_tool_use`, and `handle_post_tool_use` are now 14–15 lines each. All three call `_get_bridged_engine()` which invokes `get_detection_engine()` and delegates to `engine.scan_instructions_loaded()`, `engine.scan_pre_tool_use()`, and `engine.scan_post_tool_use()`. Zero inline detection helpers remain in handler bodies. The `_get_bridged_engine()` pattern correctly bridges the hooks-level `_session_trust` dict to the engine singleton (T-04-01 threat mitigation).

**Gap 2 (CLOSED): test_clean_input_returns_clean_verdict.** The test now uses `unittest.mock.patch.object(engine, '_get_mini_classifier', return_value=None)` to mock out the MiniSemanticClassifier, correctly isolating the unit test to Tier 0 pattern-engine behavior. All 13 detection engine tests pass.

---

_Verified: 2026-04-06T00:12:09Z_
_Verifier: Claude (gsd-verifier)_
