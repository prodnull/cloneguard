# Phase 3: Framework Integration - Research

**Researched:** 2026-04-06
**Domain:** Multi-platform agent adapter abstraction, governance framework integration, CI/CD deployment, observability
**Confidence:** MEDIUM (AGT SDK is 4 days old; MCP middleware pattern needs runtime verification)

## Summary

Phase 3 wraps the Phase 1-2 detection+enforcement pipeline with platform-specific integration layers: input adapters for Claude Code/Gemini CLI/Cursor, a Microsoft AGT plugin, MCP protocol middleware, a GitHub Actions composite action with SARIF upload, and OTel span emission. The detection engine and enforcement pipeline remain unchanged.

The core technical challenge is **adapter normalization**: three agent platforms (Claude Code, Gemini CLI, Cursor) send substantially different hook JSON schemas with different field names, event lifecycles, and response protocols. The `InputAdapter` Protocol must abstract these differences into the existing `ToolCallEvent` frozen dataclass without losing platform-specific context needed for response formatting.

**Primary recommendation:** Implement adapters in dependency order: (1) InputAdapter Protocol + adapter registry, (2) Claude Code adapter (extract from hooks.py), (3) Gemini CLI + Cursor adapters, (4) MCP adapter refactor, (5) AGT plugin, (6) CI/CD action, (7) OTel emitter. The AGT SDK (`agent-os-kernel` 3.0.2) is brand new (released 2026-04-02) and its ToolCallInterceptor interface is not yet well-documented -- the adapter should use the `PolicyEngine.evaluate()` pattern with graceful degradation.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Define an `InputAdapter` Protocol (PEP 544) with a single core method: `normalize(raw_event: dict[str, Any]) -> ToolCallEvent`. Each agent platform gets its own adapter module that translates platform-specific hook JSON into the existing `ToolCallEvent` dataclass from `detection/types.py`.
- **D-02:** Adapter modules live in `src/cloneguard/adapters/` package. Initial adapters: `claude_code.py` (extract from current hooks.py JSON parsing), `gemini_cli.py`, `cursor.py`. Each adapter is a concrete class conforming to the `InputAdapter` Protocol.
- **D-03:** Adapter registry pattern: `get_adapter(agent_type: str) -> InputAdapter` function that returns the correct adapter based on agent type string (auto-detected from hook JSON structure or explicitly configured). Unknown agent types fall back to a `GenericAdapter` that attempts best-effort normalization.
- **D-04:** hooks.py evolution: the thin shim gets thinner -- it calls `get_adapter().normalize()` to produce a `ToolCallEvent`, then passes it through the existing DetectionEngine -> PolicyEngine -> enforcement pipeline. No agent-specific logic remains in hooks.py.
- **D-05:** Adapter-specific tests validate that each platform's hook JSON format normalizes correctly into `ToolCallEvent`. Use captured real hook payloads as test fixtures.
- **D-06:** In-tree module at `src/cloneguard/adapters/agt.py` implementing `ToolCallInterceptor` from the AGT SDK. The interceptor wraps `DetectionEngine.scan()` and maps results to AGT `PolicyDecision` types.
- **D-07:** AGT SDK (`agent-os-kernel`) is an optional dependency -- import guarded with try/except, graceful degradation if unavailable.
- **D-08:** The AGT plugin does NOT use the hook protocol. It's a direct Python API call.
- **D-09:** Refactor existing `src/cloneguard/mcp_plugin.py` into the adapter framework at `src/cloneguard/adapters/mcp.py`. Evolve from mcp-gateway plugin API to direct MCP SDK usage.
- **D-10:** The MCP adapter scans both tool request content and tool response content via `InputAdapter` Protocol plus additional `scan_response()` method.
- **D-11:** MCP adapter handles MCP-specific threat surface: tool description poisoning (RADE attacks), log-to-leak patterns, tool call chaining for exfiltration.
- **D-12:** GitHub Actions composite action published as `prodnull/cloneguard-action@v1`. Installs via `uv tool install`, runs `cloneguard scan --sarif`, uploads SARIF via `github/codeql-action/upload-sarif`.
- **D-13:** Action accepts configuration inputs: `threshold`, `scan-paths`, `fail-on`.
- **D-14:** Action metadata at `.github/actions/cloneguard-scan/action.yml`. Composite action (not Docker).
- **D-15:** CI/CD adapter at `src/cloneguard/adapters/cicd.py` normalizes GitHub Actions webhook event payloads into `ToolCallEvent`.
- **D-16:** `opentelemetry-api` as an optional dependency (extras: `[otel]`). When available, emit OTel spans. When unavailable, no-op.
- **D-17:** Spans conform to OpenTelemetry GenAI semantic conventions (experimental). Span attributes include: `gen_ai.system`, `cloneguard.verdict`, `cloneguard.confidence`, `cloneguard.enforcement_action`, etc.
- **D-18:** OTel emitter module at `src/cloneguard/audit/otel.py`. Plugs into existing audit pipeline alongside NDJSON and SARIF emitters.
- **D-19:** OTel export configured via standard `OTEL_EXPORTER_*` environment variables. CloneGuard does not manage the collector.

### Claude's Discretion
- Internal module organization within `src/cloneguard/adapters/` package
- Exact Gemini CLI and Cursor hook JSON parsing logic (derive from documented event formats)
- AGT SDK version pinning strategy
- MCP SDK version requirements and API surface used
- GitHub Actions action.yml exact input/output schema
- OTel span naming convention details beyond the specified attributes
- Test fixture generation strategy for multi-platform hook payloads
- Error handling for malformed platform-specific hook input

### Deferred Ideas (OUT OF SCOPE)
- Browser agent CDP input adapter (Phase 5 AGNT-01)
- Autonomous agent SDK middleware adapters (LangChain, AutoGen, ADK, CrewAI) (Phase 5 AGNT-02)
- Financial agent custom API middleware (Phase 5 AGNT-03)
- CI/CD agent pattern library (Phase 5 AGNT-04)
- OPA external data source REST endpoint (Phase 5 GOVN-01)
- Cedar context attribute provider (Phase 5 GOVN-02)
- Windsurf and VS Code Copilot adapters (incremental, follow same pattern)
- Agent type auto-detection from process name or environment
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| INTG-01 | Input adapter abstraction decoupling detection engine from Claude Code hook protocol | InputAdapter Protocol (PEP 544), adapter registry, three platform JSON schemas documented. Existing `ToolCallEvent` dataclass is the normalization target. |
| INTG-02 | Microsoft AGT ToolCallInterceptor plugin exposing CloneGuard as a semantic sensor | `agent-os-kernel` 3.0.2 (MIT, 2026-04-02). PolicyEngine.evaluate() and stateless_execute() APIs documented. ToolCallInterceptor is a public interface. |
| INTG-03 | MCP protocol middleware adapter for scanning MCP tool calls | `mcp` 1.27.0 SDK. FastMCP tool handler pattern. Existing `mcp_plugin.py` provides refactoring baseline. Response scanning via `scan_response()` extension. |
| INTG-04 | CI/CD runner deployment (GitHub Actions) with SARIF upload to Security tab | Composite action using `github/codeql-action/upload-sarif@v4`. Existing `SARIFEmitter` produces valid SARIF 2.1.0. `cloneguard scan --sarif` CLI path exists. |
| INTG-05 | OTel span emission conforming to GenAI semantic conventions | `opentelemetry-api` 1.40.0. GenAI semantic conventions (experimental). `gen_ai.tool.name`, `gen_ai.operation.name`, `gen_ai.provider.name` are standard attributes. Custom `cloneguard.*` namespace for detection-specific attributes. |
</phase_requirements>

## Standard Stack

### Core (Existing -- No New Core Dependencies)

The detection engine (`DetectionEngine`), enforcement pipeline (`PolicyEngine`, `SandboxAdapter`), and audit infrastructure (`NDJSONEmitter`, `SARIFEmitter`, `AuditEvent`) are all Phase 1-2 outputs that this phase wraps, not modifies.

### New Optional Dependencies

| Library | Version | Purpose | Why Standard | Confidence |
|---------|---------|---------|--------------|------------|
| `opentelemetry-api` | 1.40.0 | OTel span creation API (no-op when SDK absent) | Official OTel API package. API-only dep means zero overhead when tracing disabled. | HIGH [VERIFIED: PyPI, 2026-03-04 release] |
| `agent-os-kernel` | 3.0.2 | Microsoft AGT PolicyEngine integration | Official Microsoft AGT package (MIT). Only optional dep needed for AGT plugin. | MEDIUM [VERIFIED: PyPI, 2026-04-02 release] |
| `mcp` | >=1.26.0 | MCP Python SDK for middleware adapter | Official MCP SDK. Already installed in project venv (1.26.0). | HIGH [VERIFIED: project venv] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `opentelemetry-api` only | `opentelemetry-sdk` + exporters | SDK adds weight. API-only is correct: users bring their own SDK+exporter. CloneGuard just creates spans. |
| `agent-os-kernel` | Direct AGT GitHub source | PyPI package is canonical. Pin to `>=3.0,<4.0` given SDK is brand new. |
| Direct MCP SDK (`mcp`) | Keep `mcp-gateway` plugin API | CONTEXT.md D-09 explicitly requires evolving to direct SDK. mcp-gateway is the old approach. |

### New pyproject.toml Extras

```toml
[project.optional-dependencies]
# Existing
dev = ["pytest>=8.0", "pytest-cov>=6.0", "ruff>=0.8", "mypy>=1.13", "types-PyYAML>=6.0"]
mini = ["onnxruntime>=1.17", "transformers>=4.36", "numpy>=1.26"]
semantic = ["ollama>=0.4"]
# New Phase 3
otel = ["opentelemetry-api>=1.40"]
agt = ["agent-os-kernel>=3.0,<4.0"]
mcp = ["mcp>=1.26"]
# Updated all
all = [
    "onnxruntime>=1.17", "transformers>=4.36", "numpy>=1.26",
    "ollama>=0.4",
    "opentelemetry-api>=1.40",
    "agent-os-kernel>=3.0,<4.0",
    "mcp>=1.26",
]
```

## Architecture Patterns

### Recommended Project Structure

```
src/cloneguard/
  adapters/
    __init__.py          # InputAdapter Protocol, get_adapter() registry, auto-detect
    claude_code.py       # Claude Code hook JSON -> ToolCallEvent
    gemini_cli.py        # Gemini CLI hook JSON -> ToolCallEvent
    cursor.py            # Cursor hook JSON -> ToolCallEvent
    generic.py           # Best-effort fallback adapter
    agt.py               # Microsoft AGT ToolCallInterceptor (optional dep)
    mcp.py               # MCP middleware adapter (refactored from mcp_plugin.py)
    cicd.py              # GitHub Actions webhook -> ToolCallEvent
  audit/
    __init__.py
    ndjson.py            # Existing
    sarif.py             # Existing
    otel.py              # NEW: OTel span emitter
    types.py             # Existing AuditEvent
  detection/             # UNCHANGED
  enforcement/           # UNCHANGED
  hooks.py               # Thinned: delegates to adapter registry
  mcp_plugin.py          # DEPRECATED: replaced by adapters/mcp.py
.github/
  actions/
    cloneguard-scan/
      action.yml         # Composite action metadata
```

### Pattern 1: InputAdapter Protocol

**What:** PEP 544 structural subtyping Protocol for normalizing agent-specific hook JSON into `ToolCallEvent`.
**When to use:** Every new agent platform integration.
**Example:**

```python
# Source: Derived from existing SandboxAdapter Protocol pattern in enforcement/adapter.py
from __future__ import annotations
from typing import Any, Protocol, runtime_checkable
from cloneguard.detection.types import ToolCallEvent

@runtime_checkable
class InputAdapter(Protocol):
    """Normalize agent-specific hook JSON into ToolCallEvent (D-01)."""

    @property
    def agent_type(self) -> str:
        """Identifier for this agent platform (e.g., 'claude-code', 'gemini-cli')."""
        ...

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        """Convert platform-specific event JSON to normalized ToolCallEvent."""
        ...

    def format_response(self, result: Any, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Convert detection/enforcement result back to platform-specific response format."""
        ...
```

[ASSUMED] The `format_response` method is needed because each platform has different response expectations (Claude Code: exit code + stdout, Gemini CLI: JSON with `decision` field, Cursor: JSON with `permission` field). This is discretionary -- the planner should decide if response formatting belongs in the adapter or in a separate layer.

### Pattern 2: Adapter Registry with Auto-Detection

**What:** Factory function that selects the correct adapter based on agent type string or JSON structure probing.
**When to use:** At the top of the hook handler pipeline.
**Example:**

```python
# Source: Follows existing get_sandbox_adapter() pattern in enforcement/adapter.py
_ADAPTERS: dict[str, type] = {}

def register_adapter(agent_type: str):
    """Decorator to register an adapter class."""
    def decorator(cls):
        _ADAPTERS[agent_type] = cls
        return cls
    return decorator

def detect_agent_type(raw_event: dict[str, Any]) -> str:
    """Probe JSON structure to identify agent platform."""
    if "hook_type" in raw_event:
        return "claude-code"       # Claude Code: {"hook_type": "PreToolUse", ...}
    if "hook_event_name" in raw_event:
        return "gemini-cli"        # Gemini CLI: {"hook_event_name": "BeforeTool", ...}
    if "hook_event_name" in raw_event and "workspace_roots" in raw_event:
        return "cursor"            # Cursor: {"hook_event_name": "beforeShellExecution", ...}
    return "generic"

def get_adapter(agent_type: str = "auto", raw_event: dict[str, Any] | None = None) -> InputAdapter:
    """Return adapter for the given agent type (D-03)."""
    if agent_type == "auto" and raw_event:
        agent_type = detect_agent_type(raw_event)
    cls = _ADAPTERS.get(agent_type, _ADAPTERS["generic"])
    return cls()
```

[ASSUMED] The auto-detection heuristic above. Gemini CLI and Cursor both use `hook_event_name` but Cursor always includes `workspace_roots`. This needs validation against real captured payloads.

### Pattern 3: OTel No-Op Pattern

**What:** Zero-cost tracing when `opentelemetry-api` is not installed.
**When to use:** OTel emitter initialization.
**Example:**

```python
# Source: Standard OTel Python pattern [CITED: opentelemetry.io/docs/languages/python/]
try:
    from opentelemetry import trace
    _tracer = trace.get_tracer("cloneguard", schema_url="https://opentelemetry.io/schemas/1.29.0")
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    _tracer = None  # No-op: trace.get_tracer() returns NoOpTracer when SDK is absent
```

The `opentelemetry-api` package provides a no-op tracer by default. When only `opentelemetry-api` is installed (no SDK), `trace.get_tracer()` returns a `NoOpTracer` that creates `NonRecordingSpan` objects -- zero allocation overhead. [CITED: opentelemetry.io/docs/languages/python/]

### Pattern 4: Graceful Optional Dependency Import

**What:** Import guard pattern consistent with existing codebase style.
**When to use:** AGT, MCP, OTel imports.
**Example:**

```python
# Source: Existing pattern from mcp_plugin.py and mini_semantic.py
try:
    from agent_os import PolicyEngine
    _AGT_AVAILABLE = True
except ImportError:
    _AGT_AVAILABLE = False

    class PolicyEngine:  # type: ignore[no-redef]
        """Stub for when agent-os-kernel is not installed."""
        def evaluate(self, **kwargs): return type('Decision', (), {'allowed': True})()
```

### Anti-Patterns to Avoid

- **Agent-specific logic in detection engine:** The detection engine is agent-agnostic. All platform-specific parsing belongs in adapters, not in `DetectionEngine` or `PolicyEngine`.
- **Response formatting in adapters that modifies detection results:** Adapters normalize input and format output. They do not alter verdicts, confidences, or signals.
- **Importing heavy SDKs eagerly:** AGT and OTel must be lazy-loaded behind import guards. Only `InputAdapter` Protocol and the adapter registry are loaded eagerly.
- **Blocking on OTel export:** OTel span creation is synchronous but export is asynchronous (handled by SDK's span processor). Never call `force_flush()` on the hot path.

## Platform Hook Schema Reference

### Claude Code (3 events)

**Input (stdin JSON):**
```json
{
  "hook_type": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "ls -la"},
  "session_id": "sess_abc123"
}
```
**Response:** Exit code 0 (allow) or 2 (block). Optional stdout message.
**Source:** Existing `hooks.py` [VERIFIED: codebase]

### Gemini CLI (11 events, key: BeforeTool/AfterTool)

**Input (stdin JSON):**
```json
{
  "session_id": "string",
  "transcript_path": "string",
  "cwd": "string",
  "hook_event_name": "BeforeTool",
  "timestamp": "string",
  "tool_name": "string",
  "tool_input": {},
  "mcp_context": {},
  "original_request_name": "string"
}
```
**Response (stdout JSON):**
```json
{
  "decision": "allow|deny|block",
  "reason": "feedback to agent",
  "continue": true,
  "hookSpecificOutput": {}
}
```
**Source:** [CITED: geminicli.com/docs/hooks/reference/]

### Cursor (6 events, key: beforeShellExecution/beforeMCPExecution/beforeReadFile)

**Input (stdin JSON):**
```json
{
  "conversation_id": "string",
  "generation_id": "string",
  "command": "shell command",
  "cwd": "string",
  "hook_event_name": "beforeShellExecution",
  "workspace_roots": ["string"]
}
```

For `beforeMCPExecution`:
```json
{
  "conversation_id": "string",
  "generation_id": "string",
  "server": "mcp-server-name",
  "tool_name": "tool_name",
  "tool_input": "escaped JSON string",
  "command": "full MCP command",
  "hook_event_name": "beforeMCPExecution",
  "workspace_roots": ["string"]
}
```

**Response (stdout JSON):**
```json
{
  "continue": true,
  "permission": "allow|deny|ask",
  "userMessage": "string",
  "agentMessage": "string"
}
```
**Source:** [CITED: blog.gitbutler.com/cursor-hooks-deep-dive]

### Event Type Mapping

| ToolCallEvent.event_type | Claude Code | Gemini CLI | Cursor |
|--------------------------|-------------|------------|--------|
| `InstructionsLoaded` | `InstructionsLoaded` | `SessionStart` (approx) | `beforeSubmitPrompt` (approx) |
| `PreToolUse` | `PreToolUse` | `BeforeTool` | `beforeShellExecution` / `beforeMCPExecution` |
| `PostToolUse` | `PostToolUse` | `AfterTool` | `afterFileEdit` (partial) |

[ASSUMED] The event type mapping above. Gemini CLI `SessionStart` and Cursor `beforeSubmitPrompt` are not exact equivalents of `InstructionsLoaded` -- they serve different lifecycle purposes. The adapter may need to synthesize `InstructionsLoaded` events from platform-specific triggers, or document that instruction scanning is Claude Code-specific behavior.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| OTel span creation | Custom trace/span infrastructure | `opentelemetry-api` no-op tracer pattern | Standard, zero-cost when disabled, compatible with all OTel backends |
| SARIF file format | Custom JSON construction | Existing `SARIFEmitter` + `sarif-pydantic` | Already built in Phase 1, schema-validated |
| GitHub Actions SARIF upload | Custom API calls to code scanning | `github/codeql-action/upload-sarif@v4` | Official action, handles auth/permissions |
| AGT policy evaluation | Custom governance API | `agent-os-kernel` PolicyEngine | Official Microsoft SDK, sub-ms latency |
| MCP tool/response types | Custom MCP JSON types | `mcp` SDK types (`CallToolResult`, `TextContent`) | Official SDK types, schema-validated |
| Agent type detection | Complex multi-step classification | Simple JSON key probing (3 checks) | Hook JSON schemas are structurally distinct, no ambiguity |

**Key insight:** This phase is primarily an adapter/integration phase. Every external system has an official SDK or established pattern. The value is in clean normalization and correct wiring, not in novel algorithms.

## Common Pitfalls

### Pitfall 1: Response Protocol Mismatch

**What goes wrong:** Each agent platform expects responses in different formats. Claude Code uses exit codes + stdout text. Gemini CLI expects a JSON object with `decision` field. Cursor expects JSON with `permission` field. Returning the wrong format crashes the agent or silently fails.
**Why it happens:** Developer implements normalization (input) correctly but forgets that output also needs platform-specific formatting.
**How to avoid:** Each adapter implements both `normalize()` (input) and `format_response()` (output). The hook handler calls `format_response()` to convert the detection result back to platform-specific format before returning.
**Warning signs:** Agent hangs after hook invocation, "invalid JSON" errors in agent logs, hook returns 0 but agent treats it as block.

### Pitfall 2: Cursor tool_input Is a String, Not a Dict

**What goes wrong:** Cursor's `beforeMCPExecution` passes `tool_input` as an **escaped JSON string**, not a parsed dict. If the adapter passes it directly to `ToolCallEvent.tool_input` (which expects `dict[str, Any]`), type validation fails or detection scans the string representation.
**Why it happens:** Cursor serializes MCP tool arguments as a string for transport.
**How to avoid:** The Cursor adapter must `json.loads(raw_event["tool_input"])` before constructing `ToolCallEvent`. Wrap in try/except -- malformed JSON should fall back to scanning the raw string as content.
**Warning signs:** Pattern engine finding matches on JSON syntax characters rather than content, type errors on `ToolCallEvent` construction.

### Pitfall 3: OTel Span Export Blocking the Hook

**What goes wrong:** If the OTel SDK is configured with a `SimpleSpanProcessor` (synchronous export), span export blocks the hook response, adding 100ms+ latency per invocation.
**Why it happens:** Default OTel SDK configuration may use synchronous processing. CloneGuard docs don't control the user's OTel SDK configuration.
**How to avoid:** Document in README that `BatchSpanProcessor` (async) is required for production use. In the OTel emitter, create and end spans but never call `force_flush()`. Let the SDK's async processor handle export.
**Warning signs:** Hook latency increases from ~20ms to 120ms+ when OTel is enabled.

### Pitfall 4: AGT SDK Version Instability

**What goes wrong:** The `agent-os-kernel` package was released 4 days ago (2026-04-02). The API surface may change rapidly in early releases, breaking the CloneGuard AGT adapter.
**Why it happens:** Brand-new SDK. Version 3.0.2 suggests some iteration already happened, but the public interface documentation is sparse.
**How to avoid:** Pin to `>=3.0,<4.0`. Code defensively with try/except around AGT API calls. Test against actual AGT SDK, not mocks only. The adapter module should degrade gracefully if the AGT API changes.
**Warning signs:** Import errors after `pip install agent-os-kernel` upgrade, unexpected attribute errors on PolicyEngine.

### Pitfall 5: mcp_plugin.py Backward Compatibility

**What goes wrong:** Existing users may have `mcp-gateway` configurations referencing `CloneGuardPlugin` from `cloneguard.mcp_plugin`. Removing or breaking this import path breaks their setup.
**Why it happens:** Refactoring moves the plugin to `cloneguard.adapters.mcp` without preserving the old import path.
**How to avoid:** Keep `mcp_plugin.py` as a thin compatibility shim that re-imports from `adapters.mcp`. Log a deprecation warning. Remove in a future major version.
**Warning signs:** Users report "ModuleNotFoundError: cloneguard.mcp_plugin" after upgrade.

### Pitfall 6: SARIF Upload Requires GitHub Advanced Security

**What goes wrong:** The GitHub Actions workflow runs successfully but SARIF upload fails silently or with a permissions error on private repositories that don't have GitHub Code Security features enabled.
**Why it happens:** GitHub restricts code scanning results to repos with Code Security enabled. Public repos get it for free; private repos must enable it.
**How to avoid:** Document the requirement. The composite action should catch upload failures gracefully and output a clear error message explaining the prerequisite. For public repos, it works out of the box.
**Warning signs:** Action completes but no results appear in the repository Security tab.

## Code Examples

### Claude Code Adapter (extract from hooks.py)

```python
# Source: Derived from existing hooks.py::main() parsing logic [VERIFIED: codebase]
from __future__ import annotations
from typing import Any
from cloneguard.detection.types import ToolCallEvent

class ClaudeCodeAdapter:
    """Normalize Claude Code hook JSON into ToolCallEvent (D-02)."""

    @property
    def agent_type(self) -> str:
        return "claude-code"

    def normalize(self, raw_event: dict[str, Any]) -> ToolCallEvent:
        hook_type = raw_event.get("hook_type", "")
        tool_name = raw_event.get("tool_name", hook_type)
        tool_input = raw_event.get("tool_input", {})

        # Extract content for scanning
        content = ""
        if hook_type == "InstructionsLoaded":
            instructions = raw_event.get("instructions", [])
            content = "\n".join(i.get("content", "") for i in instructions)
        elif hook_type == "PreToolUse":
            content = tool_input.get("content", "") or tool_input.get("command", "")
        elif hook_type == "PostToolUse":
            tool_output = raw_event.get("tool_output", {})
            content = tool_output.get("content", "")

        return ToolCallEvent(
            event_type=hook_type,
            tool_name=tool_name,
            tool_input=tool_input,
            content=content,
            source_path=tool_input.get("file_path", ""),
            session_id=raw_event.get("session_id", ""),
            raw_data=raw_event,
        )

    def format_response(self, result: Any, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Claude Code uses exit code + stdout, not JSON response."""
        return {"exit_code": result.exit_code, "message": result.message}
```

### OTel Span Emitter

```python
# Source: OTel Python API pattern [CITED: opentelemetry.io/docs/languages/python/]
from __future__ import annotations
from typing import Any

try:
    from opentelemetry import trace
    _tracer = trace.get_tracer(
        "cloneguard",
        schema_url="https://opentelemetry.io/schemas/1.29.0",
    )
    _OTEL_AVAILABLE = True
except ImportError:
    _tracer = None
    _OTEL_AVAILABLE = False


class OTelEmitter:
    """Emit OTel spans from AuditEvent objects (D-18).

    When opentelemetry-api is not installed, all methods are no-ops.
    When installed without an SDK, spans are NonRecordingSpan (zero overhead).
    """

    def emit(self, event: Any) -> None:
        if not _OTEL_AVAILABLE or _tracer is None:
            return
        with _tracer.start_as_current_span(
            name=f"cloneguard.scan {event.tool_name}",
            attributes={
                "gen_ai.system": event.agent_type,
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": event.tool_name,
                "cloneguard.verdict": event.verdict,
                "cloneguard.confidence": event.confidence,
                "cloneguard.enforcement_action": event.enforcement_action,
                "cloneguard.sandbox_adapter": event.sandbox_adapter,
                "cloneguard.source_path": event.source_path,
                "cloneguard.schema_version": event.schema_version,
            },
        ):
            pass  # Span auto-ends when context manager exits
```

### GitHub Actions Composite Action

```yaml
# Source: GitHub Actions composite action pattern
# [CITED: docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github]
name: 'CloneGuard Scan'
description: 'Scan repository for prompt injection patterns and upload SARIF results'
inputs:
  threshold:
    description: 'Override suspicious/malicious thresholds (e.g., "0.3/0.7")'
    required: false
    default: ''
  scan-paths:
    description: 'Directories to scan (comma-separated, defaults to repo root)'
    required: false
    default: '.'
  fail-on:
    description: 'Verdict level that fails the check (malicious or suspicious)'
    required: false
    default: 'malicious'
  python-version:
    description: 'Python version for uv'
    required: false
    default: '3.12'
runs:
  using: composite
  steps:
    - name: Install uv
      uses: astral-sh/setup-uv@v5
    - name: Install CloneGuard
      shell: bash
      run: uv tool install cloneguard[mini]
    - name: Run scan
      shell: bash
      run: |
        cloneguard scan ${{ inputs.scan-paths }} \
          --sarif --output cloneguard-results.sarif \
          ${{ inputs.threshold && format('--threshold {0}', inputs.threshold) || '' }}
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: cloneguard-results.sarif
        category: cloneguard
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `mcp-gateway` plugin API | Direct `mcp` SDK (1.27.0) | 2025-Q4 | MCP SDK is now stable enough for direct middleware. mcp-gateway adds unnecessary indirection. |
| No agent abstraction | InputAdapter Protocol | Phase 3 (new) | Decouples detection from any specific agent's JSON format. |
| No OTel support | `opentelemetry-api` 1.40.0 with GenAI semconv | 2025-Q4 onward | GenAI semantic conventions are experimental but adopted by major vendors (Datadog, Grafana). |
| No governance framework | Microsoft AGT (2026-04-02) | Just released | First comprehensive open-source agent governance toolkit. CloneGuard becomes a sensor within it. |
| CodeQL Action v3 | CodeQL Action v4 | 2026 | v3 deprecated December 2026. Use v4 for SARIF upload. |

**Deprecated/outdated:**
- `mcp-gateway` plugin API: Being replaced by direct MCP SDK usage per D-09. Keep as compat shim.
- `github/codeql-action/upload-sarif@v3`: Deprecated December 2026. Use `@v4`.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `format_response()` method needed on InputAdapter for platform-specific response formatting | Architecture Patterns | Medium -- if responses are all handled at the hooks.py level, the Protocol becomes simpler but hooks.py stays platform-aware. |
| A2 | Gemini CLI and Cursor can be distinguished by `workspace_roots` field presence | Architecture Patterns | Low -- can add more heuristic checks. Worst case: require explicit `--agent-type` flag. |
| A3 | Event type mapping (InstructionsLoaded -> SessionStart/beforeSubmitPrompt) is approximate | Platform Hook Schema | Medium -- Gemini CLI `SessionStart` may not carry instruction content. Adapter may need to skip InstructionsLoaded for non-Claude agents or synthesize it differently. |
| A4 | AGT `ToolCallInterceptor` interface has `before_tool_call()` method | AGT Plugin | HIGH -- the interface is documented as public but exact method signatures are not in published docs. The adapter may need adjustment once full AGT API docs are available. |
| A5 | MCP Python SDK supports transparent middleware/interceptor pattern for tool call interception | MCP Adapter | MEDIUM -- The SDK provides `FastMCP` tool handlers and call_tool patterns, but a "proxy MCP server" middleware pattern is not explicitly documented. The adapter may need to implement a wrapping server rather than a true interceptor. |
| A6 | `opentelemetry-api` no-op tracer has zero allocation overhead | OTel Emitter | LOW -- This is a documented design goal of the OTel API specification. Verified against OTel Python docs. |

## Open Questions

1. **AGT ToolCallInterceptor exact interface**
   - What we know: AGT exposes `ToolCallInterceptor` as a public interface for third-party tools. `PolicyEngine.evaluate()` takes agent_id, action, tool params.
   - What's unclear: The exact method signature for `ToolCallInterceptor.before_tool_call()` and the `PolicyDecision` return type (is it the same as CloneGuard's `PolicyDecision`?).
   - Recommendation: Install `agent-os-kernel` 3.0.2 and inspect the source. Write the adapter against the actual API, not the blog-post examples. Pin version tightly.

2. **MCP middleware interception pattern**
   - What we know: MCP SDK provides `FastMCP` for defining tool handlers. Interceptors exist in the LangChain MCP adapter, not the core SDK.
   - What's unclear: Whether the core `mcp` SDK provides a proxy/middleware pattern for intercepting tool calls, or if CloneGuard needs to implement a wrapping MCP server.
   - Recommendation: STATE.md flags this: "Phase 3 MCP SDK response interception API needs verification at planning time." Implement the adapter as a wrapping MCP server that delegates to the upstream server, scanning requests/responses in transit. This is the proven proxy pattern and does not depend on SDK middleware features.

3. **Gemini CLI InstructionsLoaded equivalent**
   - What we know: Gemini CLI has `SessionStart` and `BeforeAgent` hooks. Claude Code's `InstructionsLoaded` is unique -- it delivers instruction file content for scanning.
   - What's unclear: Whether Gemini CLI delivers instruction content in any hook event.
   - Recommendation: For v1, the `InstructionsLoaded` scan is Claude Code-specific. Gemini CLI adapter normalizes `BeforeTool`/`AfterTool` events only. Instruction scanning can be added when Gemini CLI documents a content-delivery hook.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.11+ | All code | Partial (3.14) | 3.14.3 (system) | Use uv venv with 3.11-3.13 for testing |
| uv | CI/CD action, development | Yes | 0.10.6 | pip fallback |
| mcp SDK | MCP adapter | Yes | 1.26.0 | Already in venv |
| opentelemetry-api | OTel emitter | Not installed | -- | No-op when absent (by design) |
| agent-os-kernel | AGT plugin | Not installed | -- | Graceful degradation (by design) |
| GitHub Actions runner | CI/CD action | N/A (runs in CI) | -- | Test locally with `act` |

**Missing dependencies with no fallback:**
- None -- all new dependencies are optional by design.

**Missing dependencies with fallback:**
- `opentelemetry-api`: No-op tracer when absent. Install only when users want tracing.
- `agent-os-kernel`: AGT adapter returns "not available" when absent. Install only for AGT integration.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A -- adapters normalize hook JSON, no auth involved |
| V3 Session Management | Partial | Session IDs from platform hooks flow through to audit events. No new session management. |
| V4 Access Control | Yes | Adapters must not allow agent to modify adapter registry or bypass detection. AGT plugin must map CloneGuard verdicts correctly to AGT PolicyDecision (no false allows). |
| V5 Input Validation | Yes | All adapter `normalize()` methods must validate JSON structure. Malformed input -> exit 0 (allow, never crash). Cursor `tool_input` string must be safely JSON-parsed. |
| V6 Cryptography | No | No new crypto. Existing content hashing (SHA-256) unchanged. |

### Known Threat Patterns for This Phase

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Adapter bypass via unrecognized event type | Elevation | GenericAdapter falls back to scanning content; never silently passes unknown events |
| Malformed hook JSON causing exception | Denial of Service | try/except in normalize(); return exit 0 (allow, not crash) per T-01-02 |
| OTel span containing sensitive tool_input | Information Disclosure | Never include `gen_ai.tool.call.arguments` or raw content in spans. Only hashes and verdicts. |
| AGT PolicyDecision mapping error (MALICIOUS -> ALLOW) | Tampering | Unit tests verify verdict-to-AGT-decision mapping for all verdict combinations |
| MCP response content injection | Tampering | MCP adapter scans response content through same detection pipeline, not just requests |
| SARIF file contains matched text from secrets | Information Disclosure | Existing SARIFEmitter uses matched_text (pattern text) not full file content. Verify this for CI/CD context. |

## Sources

### Primary (HIGH confidence)
- CloneGuard codebase: `detection/types.py`, `detection/engine.py`, `enforcement/adapter.py`, `audit/ndjson.py`, `audit/sarif.py`, `audit/types.py`, `hooks.py`, `mcp_plugin.py`, `pyproject.toml`
- v2 Architecture Design: `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` sections 3, 7, 8.1
- [Gemini CLI Hooks Reference](https://geminicli.com/docs/hooks/reference/) -- complete input/output JSON schemas
- [Cursor Hooks Deep Dive](https://blog.gitbutler.com/cursor-hooks-deep-dive) -- all 6 event types with field schemas
- [GitHub SARIF Upload Documentation](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github) -- `github/codeql-action/upload-sarif@v4`
- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/) -- `gen_ai.*` attribute names and types
- [opentelemetry-api 1.40.0 on PyPI](https://pypi.org/project/opentelemetry-api/) -- latest version, 2026-03-04

### Secondary (MEDIUM confidence)
- [Microsoft AGT Blog Post](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) -- ToolCallInterceptor mentioned as public interface
- [agent-os-kernel 3.0.2 on PyPI](https://pypi.org/project/agent-os-kernel/) -- PolicyEngine.evaluate() API
- [MCP Python SDK 1.27.0](https://pypi.org/project/mcp/) -- FastMCP tool handler pattern
- [MCP Python SDK GitHub](https://github.com/modelcontextprotocol/python-sdk) -- FastMCP, Context, CallToolResult

### Tertiary (LOW confidence)
- AGT ToolCallInterceptor method signatures -- not documented in published sources, inferred from blog and README
- MCP SDK middleware interception pattern -- interceptors documented in LangChain MCP adapter, not core SDK

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all packages verified on PyPI with current versions
- Architecture (adapters, registry): HIGH -- follows existing codebase patterns (SandboxAdapter, PatternEngine)
- Architecture (AGT plugin): MEDIUM -- AGT SDK is 4 days old, API may shift
- Architecture (MCP adapter): MEDIUM -- middleware pattern needs runtime verification
- Architecture (OTel emitter): HIGH -- standard OTel pattern, well-documented
- Architecture (CI/CD action): HIGH -- GitHub Actions composite action is well-established
- Pitfalls: HIGH -- derived from documented protocol differences and codebase analysis
- Platform hook schemas: HIGH for Claude Code (codebase), MEDIUM for Gemini CLI/Cursor (external docs)

**Research date:** 2026-04-06
**Valid until:** 2026-04-20 (AGT SDK is brand new -- check for API changes frequently)
