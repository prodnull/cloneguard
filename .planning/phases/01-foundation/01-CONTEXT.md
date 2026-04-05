# Phase 1: Foundation - Context

**Gathered:** 2026-04-05 (auto mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

Extract the detection engine from monolithic hooks.py into a standalone module with typed Protocol interfaces. Ship structured NDJSON audit logging and SARIF 2.1.0 output for EU AI Act Article 12 compliance. Fix packaging for standalone installation. Add hook config integrity self-check. Existing users see zero behavior change.

</domain>

<decisions>
## Implementation Decisions

### Detection Engine Extraction
- **D-01:** Extract a `DetectionEngine` class from hooks.py with a Protocol-based interface. The engine accepts a `ToolCallEvent` dataclass and returns a `DetectionResult` dataclass. All pattern matching, semantic classification, and sequence monitoring move into the engine.
- **D-02:** hooks.py becomes a thin shim (~10 lines per handler) that: parses Claude Code JSON stdin into a `ToolCallEvent`, calls `DetectionEngine.scan()`, and maps the `DetectionResult` back to the hook protocol (exit 0/2). No detection logic remains in hooks.py.
- **D-03:** scanner.py becomes a thin shim delegating to `DetectionEngine` with repo-scan configuration. The `RepoScanner` API surface stays identical.
- **D-04:** All typed contracts use `typing.Protocol` (PEP 544) for structural subtyping, not ABCs. This enables future framework integration (e.g., conforming to AGT's `ToolCallInterceptor`) without inheritance chains.

### Event Schema Design
- **D-05:** Internal event representation uses Pydantic v2 frozen models as canonical types. Fields: schema version, timestamp, session_id, agent_type, event_type, tool_name, tool_input_hash (SHA-256), verdict, confidence, signals (pattern/semantic/sequence sub-objects), enforcement_action, constraints_applied, sandbox_adapter, outcome, policy_version, cloneguard_version.
- **D-06:** NDJSON serialization is a method on the event model — `event.to_ndjson()`. One line per event to stdout or configurable output file.
- **D-07:** Schema version starts at `cloneguard/event/v1`. Breaking changes increment the version. Non-breaking additions are backward-compatible within a version.

### SARIF Output
- **D-08:** SARIF 2.1.0 output via `--sarif` CLI flag or `CLONEGUARD_SARIF_OUTPUT` env var. Validates against OASIS schema.
- **D-09:** Mapping: each CloneGuard pattern/SEQ rule ID becomes a SARIF `reportingDescriptor` (rule). Each detection event becomes a SARIF `result` with verdict mapped to SARIF level (error/warning/note). The `tool.driver` contains CloneGuard name and version.
- **D-10:** Use `sarif-pydantic` (0.6.2) for SARIF model generation rather than manual JSON construction.

### Packaging
- **D-11:** Support `uv tool install cloneguard` and `pipx install cloneguard` for standalone binary. The 87MB ONNX model ships inside the wheel — security tools must work fully offline.
- **D-12:** Entry point `cloneguard` defined in pyproject.toml `[project.scripts]`. Ensure hatchling build includes model artifacts in the wheel.

### Hook Config Integrity Self-Check
- **D-13:** On startup, CloneGuard verifies its own hook configuration hasn't been tampered with (CVE-2025-59536 class). Check that the hook entry in Claude Code settings.json points to the expected CloneGuard binary path. Warn on mismatch.

### Backward Compatibility
- **D-14:** The Claude Code hook protocol (JSON stdin, exit 0/2) works identically after refactoring. The thin shims in hooks.py preserve the exact API contract.
- **D-15:** All 1,321 existing tests must pass without modification after the extraction. New tests are added for the DetectionEngine module; existing tests validate the shims.

### Claude's Discretion
- Internal module organization within the new detection engine package
- Exact Pydantic model field naming and nesting beyond the specified schema
- Error handling strategy for malformed hook input
- CI benchmark regression gate implementation details
- Test organization for new vs migrated tests

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v2 Architecture Design
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` -- Full v2 architecture with component diagram, sandbox adapter interface, policy engine, audit layer design

### Current Implementation (extraction source)
- `src/cloneguard/hooks.py` -- Layer 1-3 hook handlers (extraction target, becomes thin shim)
- `src/cloneguard/scanner.py` -- Layer 0 RepoScanner (extraction target, becomes thin shim)
- `src/cloneguard/patterns.py` -- PatternEngine, ScanMode/Verdict enums (moves into engine)
- `src/cloneguard/mini_semantic.py` -- MiniLM ONNX classifier (moves into engine)
- `src/cloneguard/monitor.py` -- ToolCallMonitor, SEQ rules (moves into engine)
- `src/cloneguard/cli.py` -- CLI entry point (packaging changes)

### Packaging
- `pyproject.toml` -- Build config, entry points, dependencies

### Research
- `.planning/research/STACK.md` -- Technology recommendations (Pydantic v2, sarif-pydantic)
- `.planning/research/ARCHITECTURE.md` -- Component boundaries, data flow, build order
- `.planning/research/PITFALLS.md` -- FPR explosion risk, backward compat contract, latency benchmark gate

### Standards
- OASIS SARIF 2.1.0 specification (external) -- SARIF schema validation target
- EU AI Act Article 12 (external) -- Structured audit logging compliance requirement

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PatternEngine` (patterns.py): Already has clean scan interface, returns list of `PatternMatch`. Moves directly into engine.
- `MiniSemanticClassifier` (mini_semantic.py): Standalone classify() method. Clean extraction target.
- `ToolCallMonitor` (monitor.py): Session-scoped, tracks events and enforces SEQ rules. Moves into engine.
- `Verdict` and `ScanMode` enums (patterns.py): Foundation for three-verdict model in Phase 2.
- `TrustCache` (trust_cache.py): File-hash caching for amortized scan cost. Integration point for engine.
- `Allowlist` and `SequenceAllowlist`: User-configurable false positive management. Integration point.

### Established Patterns
- **Graceful degradation**: Optional imports with try/except for ML dependencies (onnxruntime, transformers, numpy, ollama). Engine must preserve this.
- **TOCTOU-safe design**: All decisions bind to stdin JSON content, never re-read from disk. Engine must maintain this invariant.
- **Session-scoped trust**: Content hashes cached within agent session. Engine maintains session state.
- **ruff + mypy strict**: All new code must pass existing lint/type-check configuration.

### Integration Points
- `cli.py::handle_wrap()` calls `RepoScanner` -- will call engine after extraction
- `hooks.py::handle_*` functions parse JSON stdin -- become thin shims to engine
- `pyproject.toml` defines `[project.scripts]` entry point
- `tests/` suite validates hook behavior end-to-end

</code_context>

<specifics>
## Specific Ideas

- The v2 design doc specifies the pipeline as strictly linear: ToolCallEvent -> DetectionResult -> PolicyDecision -> EnforcementOutcome -> AuditEvent. Phase 1 implements only the first two stages plus AuditEvent (no policy or enforcement yet).
- Enforcement_action field in NDJSON defaults to "ALLOW" in Phase 1 (no enforcement layer yet). This field is forward-compatible for Phase 2.
- The latency benchmark gate (research pitfall) should be established in CI during this phase so that all future phases inherit the constraint.

</specifics>

<deferred>
## Deferred Ideas

- OTel span emission -- Phase 3 (INTG-05)
- Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) -- Phase 2 (ENFC-01); Phase 1 emits current binary verdict
- Policy engine -- Phase 2 (ENFC-06)
- Sandbox adapters -- Phase 2 (ENFC-02 through ENFC-05)
- Input adapter abstraction for non-Claude-Code agents -- Phase 3 (INTG-01)

None -- analysis stayed within phase scope.

</deferred>

---

*Phase: 01-foundation*
*Context gathered: 2026-04-05*
