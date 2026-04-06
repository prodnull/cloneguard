# Phase 3: Framework Integration - Context

**Gathered:** 2026-04-06 (auto mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

CloneGuard scans tool calls from any major agent platform (not just Claude Code) and emits observability signals that enterprise SOC teams can consume. This phase builds input adapter abstraction, Microsoft AGT plugin, MCP middleware adapter, GitHub Actions CI/CD deployment with SARIF upload, and OTel span emission. The detection engine and enforcement pipeline (Phase 1-2) remain unchanged — this phase wraps them with platform-specific integration layers.

</domain>

<decisions>
## Implementation Decisions

### Input Adapter Architecture (INTG-01)
- **D-01:** Define an `InputAdapter` Protocol (PEP 544) with a single core method: `normalize(raw_event: dict[str, Any]) -> ToolCallEvent`. Each agent platform gets its own adapter module that translates platform-specific hook JSON into the existing `ToolCallEvent` dataclass from `detection/types.py`.
- **D-02:** Adapter modules live in `src/cloneguard/adapters/` package. Initial adapters: `claude_code.py` (extract from current hooks.py JSON parsing), `gemini_cli.py`, `cursor.py`. Each adapter is a concrete class conforming to the `InputAdapter` Protocol.
- **D-03:** Adapter registry pattern: `get_adapter(agent_type: str) -> InputAdapter` function that returns the correct adapter based on agent type string (auto-detected from hook JSON structure or explicitly configured). Unknown agent types fall back to a `GenericAdapter` that attempts best-effort normalization.
- **D-04:** hooks.py evolution: the thin shim gets thinner — it calls `get_adapter().normalize()` to produce a `ToolCallEvent`, then passes it through the existing DetectionEngine → PolicyEngine → enforcement pipeline. No agent-specific logic remains in hooks.py.
- **D-05:** Adapter-specific tests validate that each platform's hook JSON format normalizes correctly into `ToolCallEvent`. Use captured real hook payloads as test fixtures (from the verified agent hook APIs: Claude Code 3 events, Gemini CLI 11 events, Cursor 19+ events).

### Microsoft AGT Plugin (INTG-02)
- **D-06:** In-tree module at `src/cloneguard/adapters/agt.py` implementing `ToolCallInterceptor` from the AGT SDK. The interceptor wraps `DetectionEngine.scan()` and maps results to AGT `PolicyDecision` types (DENY/CONSTRAIN/ALLOW).
- **D-07:** AGT SDK (`autogen-agentchat`) is an optional dependency — import guarded with try/except, graceful degradation if unavailable. Follows the same pattern as existing `mcp_plugin.py` with stub base classes when SDK is missing.
- **D-08:** The AGT plugin does NOT use the hook protocol (stdin/stdout JSON). It's a direct Python API call — the AGT framework calls `CloneGuardInterceptor.before_tool_call()` which internally creates a `ToolCallEvent` and runs the full detection+enforcement pipeline.

### MCP Protocol Middleware (INTG-03)
- **D-09:** Refactor existing `src/cloneguard/mcp_plugin.py` into the adapter framework at `src/cloneguard/adapters/mcp.py`. Evolve from mcp-gateway plugin API to direct MCP SDK usage (the MCP protocol SDK is now stable enough for middleware interception).
- **D-10:** The MCP adapter scans both tool request content (before execution) and tool response content (after execution) by implementing the `InputAdapter` Protocol plus an additional `scan_response(response: dict) -> DetectionResult` method.
- **D-11:** MCP adapter handles the MCP-specific threat surface: tool description poisoning (RADE attacks), log-to-leak patterns, and tool call chaining for exfiltration. These map to existing pattern rules plus future `mcp/*.yaml` pattern library (Phase 5 agent expansion).

### CI/CD Deployment (INTG-04)
- **D-12:** GitHub Actions composite action published as `prodnull/cloneguard-action@v1`. The action installs CloneGuard via `uv tool install`, runs `cloneguard scan --sarif` on the PR checkout, and uploads SARIF results to the repository Security tab via `github/codeql-action/upload-sarif`.
- **D-13:** The action accepts configuration inputs: `threshold` (override default suspicious/malicious thresholds), `scan-paths` (directories to scan, defaults to repo root), `fail-on` (verdict level that fails the check: `malicious` default, `suspicious` optional).
- **D-14:** Action metadata at `.github/actions/cloneguard-scan/action.yml` in the CloneGuard repo. Composite action — not Docker-based — to minimize startup latency and allow `uv` caching across runs.
- **D-15:** CI/CD adapter at `src/cloneguard/adapters/cicd.py` normalizes GitHub Actions webhook event payloads into `ToolCallEvent` for PR-level scanning (file-by-file detection on changed files).

### OTel Span Emission (INTG-05)
- **D-16:** `opentelemetry-api` as an optional dependency (extras: `[otel]`). When available, CloneGuard emits OTel spans for each detection event. When unavailable, no-op — zero overhead.
- **D-17:** Spans conform to OpenTelemetry GenAI semantic conventions (draft). Span attributes include: `gen_ai.system` (agent type), `cloneguard.verdict`, `cloneguard.confidence`, `cloneguard.enforcement_action`, `cloneguard.signals.pattern`, `cloneguard.signals.semantic`, `cloneguard.signals.sequence`, `cloneguard.sandbox_adapter`, `cloneguard.tool_name`.
- **D-18:** OTel emitter module at `src/cloneguard/audit/otel.py` — a thin wrapper that creates spans from `AuditEvent` objects (Phase 1 infrastructure). Plugs into the existing audit pipeline alongside NDJSON and SARIF emitters.
- **D-19:** OTel export is configured via standard `OTEL_EXPORTER_*` environment variables — CloneGuard does not manage the OTel collector or exporter choice. This keeps CloneGuard agnostic to the observability backend (Splunk, Datadog, Grafana, Azure Monitor).

### Claude's Discretion
- Internal module organization within `src/cloneguard/adapters/` package
- Exact Gemini CLI and Cursor hook JSON parsing logic (derive from documented event formats)
- AGT SDK version pinning strategy
- MCP SDK version requirements and API surface used
- GitHub Actions action.yml exact input/output schema
- OTel span naming convention details beyond the specified attributes
- Test fixture generation strategy for multi-platform hook payloads
- Error handling for malformed platform-specific hook input

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v2 Architecture Design
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` -- Full v2 architecture with input adapter layer (section 3), AGT plugin (section 8.1), agent type expansion table (section 7)
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` §3 -- Input adapter types: Hook Adapter, Framework Adapter, Protocol Adapter
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` §7 -- Agent type table with adapter mapping, pattern library, and default constraints per agent type
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` §8.1 -- Microsoft AGT ToolCallInterceptor plugin code example

### Detection Engine (Phase 1 output — adapters normalize into this)
- `src/cloneguard/detection/types.py` -- ToolCallEvent, SignalResult, DetectionResult (adapters produce ToolCallEvent)
- `src/cloneguard/detection/engine.py` -- DetectionEngine with scan methods (adapters feed into this)

### Enforcement Pipeline (Phase 2 output — adapters trigger this)
- `src/cloneguard/enforcement/types.py` -- PolicyDecision, Constraints, EnforcementOutcome
- `src/cloneguard/enforcement/policy.py` -- PolicyEngine (adapters → DetectionEngine → PolicyEngine)
- `src/cloneguard/enforcement/adapter.py` -- SandboxAdapter Protocol and auto-selection

### Audit Infrastructure (Phase 1 output — OTel extends this)
- `src/cloneguard/audit/ndjson.py` -- NDJSONEmitter (OTel emitter follows this pattern)
- `src/cloneguard/audit/sarif.py` -- SARIF emitter (CI/CD action consumes SARIF output)
- `src/cloneguard/audit/types.py` -- AuditEvent type (OTel emitter consumes this)

### Existing Hook Protocol (extraction source for Claude Code adapter)
- `src/cloneguard/hooks.py` -- Current thin shim with Claude Code JSON parsing (extract into adapter)

### Existing MCP Plugin (refactor target)
- `src/cloneguard/mcp_plugin.py` -- Current mcp-gateway plugin (refactor into adapters/mcp.py)

### Verified Agent Hook APIs
- Claude Code: 3 events, JSON stdin/stdout, exit 0/2
- Gemini CLI v0.30.1+: 11 events, `gemini hooks migrate --from-claude` compatibility
- Cursor v2.6.13+: 19+ events, `failClosed`, `prompt` type hooks
- Windsurf v1.108.2+: 12 events, snake_case naming
- VS Code Copilot v1.109+: 8 events, preview API

### Standards (external)
- OpenTelemetry GenAI semantic conventions (draft) -- Span attribute naming for AI/ML workloads
- OpenTelemetry Python SDK documentation -- Instrumentation API, span creation, export configuration
- Microsoft AGT SDK documentation -- ToolCallInterceptor Protocol, PolicyDecision types
- MCP Protocol specification -- Tool call/response lifecycle, middleware interception points
- GitHub Actions SARIF upload -- `github/codeql-action/upload-sarif` action API

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ToolCallEvent` (detection/types.py): The normalized input format all adapters produce. Already has `event_type`, `tool_name`, `tool_input`, `content`, `source_path`, `scan_mode_hint`, `session_id`, `raw_data` fields.
- `DetectionEngine` (detection/engine.py): The scan pipeline that all adapters feed into. Has handler-specific methods (scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use) plus generic scan().
- `mcp_plugin.py`: Existing MCP integration with mcp-gateway. Has pattern scanning, severity mapping, graceful degradation pattern. Refactor target for adapters/mcp.py.
- `NDJSONEmitter` (audit/ndjson.py): Audit emission pattern that OTel emitter can follow. Plugs into the audit pipeline.
- `SARIFEmitter` (audit/sarif.py): SARIF output that CI/CD action consumes directly.
- `PolicyEngine` (enforcement/policy.py): Policy evaluation that all adapters trigger through the pipeline.
- hooks.py JSON parsing: Claude Code-specific stdin parsing logic that becomes the first InputAdapter.

### Established Patterns
- **Protocol-based interfaces** (PEP 544): InputAdapter must be a Protocol, consistent with DetectionEngineProtocol and SandboxAdapter.
- **Graceful degradation**: Optional imports with try/except for framework SDKs (AGT, MCP, OTel). Follow mcp_plugin.py pattern.
- **Frozen dataclasses**: All new types on the hot path are frozen dataclasses.
- **TOCTOU-safe**: Adapters must normalize content from the raw event, never re-read from disk.
- **Session-scoped**: Adapters maintain no cross-session state.

### Integration Points
- `hooks.py::main()`: Current entry point for Claude Code hooks — will delegate to adapter registry
- `cli.py::handle_wrap()`: Layer 0 wrapper — may need adapter awareness for non-Claude agents
- `pyproject.toml`: New optional dependency groups: `[agt]`, `[mcp]`, `[otel]`
- `audit/` package: OTel emitter joins NDJSON and SARIF emitters

</code_context>

<specifics>
## Specific Ideas

- The adapter registry should auto-detect agent type from hook JSON structure when possible. Claude Code sends `{"event": ...}`, Gemini CLI uses a different envelope, Cursor has its own format. Pattern-match on the JSON structure to select the right adapter without requiring explicit configuration.
- STATE.md flags "Phase 3 MCP SDK response interception API needs verification at planning time" — the research step should verify current MCP SDK capabilities for middleware interception.
- The CI/CD action should work with minimal configuration — `uses: prodnull/cloneguard-action@v1` with zero inputs should scan the repo and upload SARIF.
- OTel emission should be zero-cost when disabled — check `opentelemetry-api` availability once at startup, then use a no-op tracer if unavailable.

</specifics>

<deferred>
## Deferred Ideas

- Browser agent CDP input adapter — Phase 5 (AGNT-01), requires browser extension infrastructure
- Autonomous agent SDK middleware adapters (LangChain, AutoGen, ADK, CrewAI) — Phase 5 (AGNT-02), beyond AGT interceptor
- Financial agent custom API middleware — Phase 5 (AGNT-03)
- CI/CD agent pattern library (cicd/*.yaml) — Phase 5 (AGNT-04), patterns not adapters
- OPA external data source REST endpoint — Phase 5 (GOVN-01)
- Cedar context attribute provider — Phase 5 (GOVN-02)
- Windsurf and VS Code Copilot adapters — prioritize Claude Code, Gemini, Cursor first; remaining agents follow the same adapter pattern and can be added incrementally
- Agent type auto-detection from process name or environment — nice-to-have, explicit config sufficient for v1

None -- analysis stayed within phase scope.

</deferred>

---

*Phase: 03-framework-integration*
*Context gathered: 2026-04-06*
