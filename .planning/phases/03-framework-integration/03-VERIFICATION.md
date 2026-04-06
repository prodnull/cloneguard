---
phase: 03-framework-integration
verified: 2026-04-06T14:28:12Z
status: gaps_found
score: 8/10 must-haves verified
gaps:
  - truth: "OTel emitter plugs into existing audit pipeline alongside NDJSON and SARIF emitters"
    status: failed
    reason: "OTelEmitter is defined in audit/otel.py and exported from audit/__init__.py but is never called from hooks.py or any other production code path. Only NDJSONEmitter.emit() is invoked in hooks.py. The emitter exists as a library class but has no wiring into the live audit pipeline."
    artifacts:
      - path: "src/cloneguard/audit/otel.py"
        issue: "Class is substantive and correct, but no call site in production code"
      - path: "src/cloneguard/hooks.py"
        issue: "Only invokes NDJSONEmitter.emit() at line 201; OTelEmitter never instantiated or called"
    missing:
      - "Add OTelEmitter instantiation and emit() call in hooks.py _emit_audit_event() function alongside NDJSONEmitter, guarded by availability check"
  - truth: "MCP adapter normalizes MCP CallToolRequest into ToolCallEvent via InputAdapter Protocol"
    status: partial
    reason: "MCPAdapter is correctly implemented and works when instantiated directly. However, adapters/__init__.py does not import adapters/mcp.py, so get_adapter('mcp') returns GenericAdapter instead of MCPAdapter. The @register_adapter('mcp') decorator in mcp.py never fires via the standard registry path."
    artifacts:
      - path: "src/cloneguard/adapters/__init__.py"
        issue: "Missing import for cloneguard.adapters.mcp — only cicd, claude_code, cursor, gemini_cli, generic are imported at module bottom"
    missing:
      - "Add 'import cloneguard.adapters.mcp as _mcp' to the registry-triggering imports at the bottom of adapters/__init__.py"
---

# Phase 3: Framework Integration Verification Report

**Phase Goal:** CloneGuard scans tool calls from any major agent platform (not just Claude Code) and emits observability signals that enterprise SOC teams can consume
**Verified:** 2026-04-06T14:28:12Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (from ROADMAP Success Criteria and PLAN must_haves)

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| SC1 | Same detection+enforcement pipeline processes Claude Code, Gemini CLI, and MCP tool calls without agent-specific logic in engine | VERIFIED | hooks.py delegates to get_adapter("auto") which dispatches to ClaudeCodeAdapter, GeminiCLIAdapter, or MCPAdapter; all produce ToolCallEvent consumed by detection engine |
| SC2 | Microsoft AGT ToolCallInterceptor exposes CloneGuard as a semantic sensor in AGT governance pipeline | VERIFIED | CloneGuardInterceptor in adapters/agt.py calls get_detection_engine().scan(), maps detected->DENY, suspicious->CONSTRAIN, clean->ALLOW; importable without agent-os-kernel |
| SC3 | GitHub Actions workflow runs CloneGuard on PR events and uploads SARIF to Security tab | VERIFIED | .github/actions/cloneguard-scan/action.yml uses composite runner, astral-sh/setup-uv@v5, cloneguard scan --sarif, github/codeql-action/upload-sarif@v4 with if: always() |
| SC4 | OTel spans conforming to GenAI semantic conventions appear in OTel-compatible collector when OTel emission is enabled | FAILED | OTelEmitter is correctly implemented (gen_ai.system, gen_ai.operation.name, gen_ai.tool.name, cloneguard.verdict attributes) but is never called from hooks.py or any production code path |
| SC5 | Input adapters normalize tool calls from at least two additional agent platforms (Gemini CLI, Cursor) into ToolCallEvent, with adapter-specific tests | VERIFIED | GeminiCLIAdapter maps BeforeTool->PreToolUse, AfterTool->PostToolUse; CursorAdapter handles beforeShellExecution and beforeMCPExecution with JSON-string parsing; 51 tests in test_adapters.py pass |
| P01-1 | Claude Code hook JSON normalizes to ToolCallEvent with correct event_type, tool_name, tool_input, content, session_id | VERIFIED | ClaudeCodeAdapter verified working; 54 tests pass including isinstance(a, InputAdapter) check |
| P01-2 | get_adapter() auto-detects agent type from JSON structure | VERIFIED | detect_agent_type: hook_type->claude-code, hook_event_name+workspace_roots->cursor, hook_event_name alone->gemini-cli, fallback->generic; spot-checked programmatically |
| P01-3 | hooks.py delegates to adapter registry for normalization | VERIFIED | hooks.py imports get_adapter (line 29), calls get_adapter("auto", raw_event=data) (line 355), calls adapter.normalize(data) (line 371) |
| P02-1 | MCP adapter normalizes MCP CallToolRequest into ToolCallEvent via InputAdapter Protocol | PARTIAL | MCPAdapter class is correctly implemented (scan_response, description extraction for RADE, format_response), but get_adapter("mcp") returns GenericAdapter because adapters/__init__.py does not import adapters/mcp.py |
| P03-1 | OTel emitter is zero-cost when opentelemetry-api is not installed | VERIFIED | _OTEL_AVAILABLE=False path returns immediately from emit(); all 12 OTel tests pass including no-op behavior |

**Score:** 8/10 truths verified (2 gaps)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/cloneguard/adapters/__init__.py` | InputAdapter Protocol, get_adapter(), detect_agent_type(), register_adapter() | VERIFIED | All four exports present; runtime_checkable Protocol |
| `src/cloneguard/adapters/claude_code.py` | Claude Code hook JSON normalization | VERIFIED | ClaudeCodeAdapter with @register_adapter("claude-code") |
| `src/cloneguard/adapters/gemini_cli.py` | Gemini CLI hook JSON normalization | VERIFIED | GeminiCLIAdapter with BeforeTool/AfterTool mapping |
| `src/cloneguard/adapters/cursor.py` | Cursor hook JSON normalization | VERIFIED | CursorAdapter with json.loads for tool_input string parsing |
| `src/cloneguard/adapters/generic.py` | Best-effort fallback adapter | VERIFIED | GenericAdapter with JSON dump fallback |
| `tests/test_adapters.py` | Adapter normalization and registry tests (min 150 lines) | VERIFIED | 54 tests; passes full |
| `src/cloneguard/adapters/agt.py` | Microsoft AGT ToolCallInterceptor | VERIFIED | CloneGuardInterceptor with before_tool_call(), after_tool_call(), _verdict_to_decision() |
| `src/cloneguard/adapters/mcp.py` | MCP protocol middleware adapter | VERIFIED (partial wiring) | MCPAdapter with scan_response(), description extraction, CloneGuardMCPPlugin compat wrapper; but not in registry via __init__.py |
| `src/cloneguard/mcp_plugin.py` | Backward-compatible shim with DeprecationWarning | VERIFIED | Emits DeprecationWarning, re-exports from adapters.mcp |
| `tests/test_agt_adapter.py` | AGT adapter tests with verdict mapping (min 60 lines) | VERIFIED | 17 tests including exhaustive verdict matrix |
| `tests/test_mcp_adapter.py` | MCP adapter tests (min 80 lines) | VERIFIED | 22 tests including RADE surface, scan_response, DeprecationWarning |
| `.github/actions/cloneguard-scan/action.yml` | GitHub Actions composite action | VERIFIED | composite runner, all 4 inputs, astral-sh/setup-uv@v5, upload-sarif@v4, if: always() |
| `src/cloneguard/adapters/cicd.py` | CI/CD adapter normalizing webhook events | VERIFIED | CICDAdapter with @register_adapter("cicd"), normalize(), format_response() |
| `src/cloneguard/audit/otel.py` | OTel span emitter | VERIFIED (orphaned) | OTelEmitter class is substantive with correct attributes; not wired into production pipeline |
| `tests/test_cicd_adapter.py` | CI/CD adapter tests (min 60 lines) | VERIFIED | 20 tests including action.yml structure validation |
| `tests/test_otel_emitter.py` | OTel emitter tests including no-op behavior (min 80 lines) | VERIFIED | 15 tests including T-03-12 info disclosure and no force_flush |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| hooks.py | adapters/__init__.py | get_adapter() call | VERIFIED | Import at line 29; call at line 355; normalize() at line 371 — gsd-tools regex pattern didn't match because calls are on separate lines, but both are present |
| adapters/claude_code.py | detection/types.py | ToolCallEvent instances | VERIFIED | Pattern found in source by gsd-tools |
| adapters/agt.py | detection/engine.py | get_detection_engine().scan() | VERIFIED | Pattern found in source by gsd-tools |
| adapters/mcp.py | detection/engine.py | get_detection_engine().scan() | VERIFIED | Used in scan_response() |
| mcp_plugin.py | adapters/mcp.py | re-import compatibility shim | VERIFIED | from cloneguard.adapters.mcp import CloneGuardMCPPlugin as CloneGuardPlugin |
| .github/actions/cloneguard-scan/action.yml | cli.py | cloneguard scan --sarif CLI invocation | VERIFIED | Pattern found in action.yml |
| .github/actions/cloneguard-scan/action.yml | audit/sarif.py | SARIF output consumed by upload-sarif | VERIFIED | upload-sarif@v4 present with if: always() |
| audit/otel.py | audit/types.py | OTelEmitter.emit() accepts AuditEvent | VERIFIED | TYPE_CHECKING import; AuditEvent type annotation |
| adapters/__init__.py | adapters/mcp.py | mcp registration import | NOT WIRED | adapters/__init__.py imports cicd, claude_code, cursor, gemini_cli, generic — but NOT mcp |
| hooks.py | audit/otel.py | OTelEmitter.emit() in audit pipeline | NOT WIRED | hooks.py only calls NDJSONEmitter.emit(); OTelEmitter never instantiated or called |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| hooks.py audit pipeline | AuditEvent | detection result via _emit_audit_event() | Yes (NDJSONEmitter.emit called) | FLOWING for NDJSON; DISCONNECTED for OTel |
| adapters/agt.py CloneGuardInterceptor | DetectionResult | get_detection_engine().scan(event) | Yes | FLOWING |
| adapters/mcp.py MCPAdapter.scan_response() | DetectionResult | get_detection_engine().scan(event) | Yes | FLOWING |
| audit/otel.py OTelEmitter | AuditEvent | Never passed by production caller | No | DISCONNECTED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| detect_agent_type identifies all 4 platforms | python3 -c "from cloneguard.adapters import detect_agent_type; ..." | claude-code, gemini-cli, cursor, generic returned correctly | PASS |
| Gemini CLI adapter normalizes BeforeTool to PreToolUse | GeminiCLIAdapter().normalize({"hook_event_name":"BeforeTool",...}) | event.event_type=="PreToolUse" | PASS |
| Cursor adapter extracts content from shell command | CursorAdapter().normalize({"hook_event_name":"beforeShellExecution","command":"rm -rf /",...}) | event.content=="rm -rf /" | PASS |
| AGT verdict mapping | _verdict_to_decision("detected",...) / _verdict_to_decision("clean",...) | DENY / ALLOW respectively | PASS |
| mcp_plugin.py DeprecationWarning | python3 -W default -c "import cloneguard.mcp_plugin" | DeprecationWarning: cloneguard.mcp_plugin is deprecated | PASS |
| get_adapter("mcp") returns MCPAdapter | python3 -c "from cloneguard.adapters import get_adapter; print(type(get_adapter('mcp')).__name__)" | Returns GenericAdapter (expected MCPAdapter) | FAIL |
| OTelEmitter wired into hooks.py | grep OTelEmitter src/cloneguard/hooks.py | No match — OTelEmitter never called | FAIL |
| action.yml SARIF upload with if: always() | yaml.safe_load() inspect | if: always(), category: cloneguard | PASS |
| All Phase-3 tests pass | python -m pytest tests/test_adapters.py ... | 113 passed | PASS |
| Full regression (excluding pre-existing failures) | python -m pytest tests/ (1 pre-existing failure) | 1684 passed, 1 pre-existing unrelated failure | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|------------|------------|-------------|--------|---------|
| INTG-01 | 03-01-PLAN.md | Input adapter abstraction decoupling detection engine from Claude Code hook protocol | SATISFIED | InputAdapter Protocol, 4 adapters (ClaudeCode, GeminiCLI, Cursor, Generic), hooks.py delegation |
| INTG-02 | 03-02-PLAN.md | Microsoft AGT ToolCallInterceptor plugin exposing CloneGuard as a semantic sensor | SATISFIED | CloneGuardInterceptor.before_tool_call/after_tool_call, DENY/CONSTRAIN/ALLOW mapping, importable without SDK |
| INTG-03 | 03-02-PLAN.md | MCP protocol middleware adapter for scanning MCP tool calls | PARTIALLY SATISFIED | MCPAdapter with scan_response() and RADE detection works correctly when used directly; auto-registry wiring missing (get_adapter("mcp") returns GenericAdapter) |
| INTG-04 | 03-03-PLAN.md | CI/CD runner deployment (GitHub Actions) with SARIF upload to Security tab | SATISFIED | .github/actions/cloneguard-scan/action.yml complete with all inputs, composite runner, SARIF upload |
| INTG-05 | 03-03-PLAN.md | OTel span emission conforming to GenAI semantic conventions | PARTIALLY SATISFIED | OTelEmitter class is correct (spans, attributes, zero-cost no-op, no force_flush, no info disclosure); not wired into production audit pipeline |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| src/cloneguard/adapters/__init__.py | bottom | Missing mcp module import in registry trigger block | Warning | get_adapter("mcp") returns GenericAdapter fallback; MCP events still get scanned (full content) but via wrong adapter |
| src/cloneguard/hooks.py | ~199 | OTelEmitter never instantiated or called in _emit_audit_event() | Warning | OTel observability signals not emitted; INTG-05 SC-4 not met |

### Human Verification Required

None required — all observable behaviors are verifiable programmatically.

### Gaps Summary

Two gaps block full goal achievement:

**Gap 1 — OTelEmitter not wired into audit pipeline (INTG-05 / SC-4):**
OTelEmitter exists as a correctly implemented library class in `audit/otel.py` and is exported from `audit/__init__.py`. However, `hooks.py`'s `_emit_audit_event()` function only calls `NDJSONEmitter.emit()`. OTelEmitter is never instantiated or called anywhere in production code. The plan success criterion "OTel emitter plugs into existing audit pipeline alongside NDJSON and SARIF emitters" is not met. Enterprise SOC teams configuring an OTel collector will receive no spans from CloneGuard.

**Gap 2 — MCP adapter not in adapter registry (INTG-03 partial):**
`adapters/__init__.py` imports five adapter modules at its bottom to trigger `@register_adapter` decorators: cicd, claude_code, cursor, gemini_cli, and generic. `adapters/mcp.py` is not in this list. As a result, `get_adapter("mcp")` returns `GenericAdapter`. MCPAdapter works correctly when instantiated directly (as `CloneGuardMCPPlugin` does), and the generic fallback still scans all content rather than silently passing. However, the adapter cannot be selected by type string via the standard registry, and auto-detection for MCP protocol events would not produce the richer MCP-specific normalization (RADE surface extraction, response scanning).

Both gaps are narrow code additions: one import line in `adapters/__init__.py` and OTelEmitter wiring in `_emit_audit_event()` in `hooks.py`. No architectural rework required.

---

_Verified: 2026-04-06T14:28:12Z_
_Verifier: Claude (gsd-verifier)_
