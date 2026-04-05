# Architecture Research

**Domain:** Universal agentic defense layer (modular decomposition of monolithic hooks.py)
**Researched:** 2026-04-05
**Confidence:** HIGH

## System Overview

The architecture decomposes CloneGuard's current monolithic `hooks.py` + `scanner.py` into five cleanly-bounded subsystems connected by typed data contracts. The pipeline is strictly linear: Input Adapter -> Detection Engine -> Policy Engine -> Enforcement Layer -> Audit Layer. Every subsystem communicates through defined dataclasses, never through shared mutable state or global singletons.

```
+------------------------------------------------------------------+
|                      CloneGuard Runtime                           |
|                                                                   |
|  +--------------------------------------------------------------+|
|  |                    INPUT ADAPTERS                             ||
|  |                                                               ||
|  |  HookAdapter         FrameworkAdapter     ProtocolAdapter     ||
|  |  (Claude Code,       (AGT Interceptor,    (MCP middleware,    ||
|  |   Cursor, Gemini,     LangChain, AutoGen,  browser CDP,      ||
|  |   Windsurf, Copilot)  ADK, CrewAI)         CI/CD events)     ||
|  |                                                               ||
|  |  Output: ToolCallEvent (normalized)                           ||
|  +-----------------------------+---------------------------------+|
|                                |                                  |
|                                v                                  |
|  +--------------------------------------------------------------+|
|  |                   DETECTION ENGINE                            ||
|  |                                                               ||
|  |  Signal 1: PatternEngine ------+                              ||
|  |  (per-agent-type YAML libs)    |                              ||
|  |                                +---> FusionLayer              ||
|  |  Signal 2: SemanticClassifier  |     (calibrated on 208K     ||
|  |  (MiniLM ONNX + Ollama)      -+      trajectories)           ||
|  |                                |          |                   ||
|  |  Signal 3: SequenceAnalyzer ---+          v                   ||
|  |  (SEQ rules + MELON)                DetectionResult           ||
|  |                                  (verdict, confidence,        ||
|  |                                   signals, context)           ||
|  +-----------------------------+---------------------------------+|
|                                |                                  |
|                                v                                  |
|  +--------------------------------------------------------------+|
|  |                   POLICY ENGINE                               ||
|  |                                                               ||
|  |  Inputs: DetectionResult + ToolCallEvent + OperatorConfig     ||
|  |                                                               ||
|  |  Policy backends (compile to PolicyDecision):                 ||
|  |    YAMLPolicy (default)  |  OPAPolicy  |  CedarPolicy        ||
|  |                                                               ||
|  |  Output: PolicyDecision                                       ||
|  |    ALLOW | CONSTRAIN(constraints) | BLOCK(reason)             ||
|  +-----------------------------+---------------------------------+|
|                                |                                  |
|                                v                                  |
|  +--------------------------------------------------------------+|
|  |                 ENFORCEMENT LAYER                             ||
|  |                                                               ||
|  |  SandboxAdapter (Protocol):                                   ||
|  |    NoopAdapter | LandlockAdapter | SeatbeltAdapter |          ||
|  |    BubblewrapAdapter | DockerAdapter                          ||
|  |                                                               ||
|  |  Output: EnforcementOutcome                                   ||
|  |    (action_taken, constraints_applied, sandbox_id)            ||
|  +-----------------------------+---------------------------------+|
|                                |                                  |
|                                v                                  |
|  +--------------------------------------------------------------+|
|  |                    AUDIT LAYER                                ||
|  |                                                               ||
|  |  EventBuilder assembles AuditEvent from all upstream data     ||
|  |                                                               ||
|  |  Simultaneous emission:                                       ||
|  |    NDJSONEmitter  -> file/SIEM/S3                             ||
|  |    SARIFEmitter   -> GitHub Security / VS Code                ||
|  |    OTelEmitter    -> Splunk / Datadog / Grafana               ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
```

### Component Responsibilities

| Component | Responsibility | Depends On |
|-----------|----------------|------------|
| InputAdapter (Protocol) | Normalize agent-specific hook/event JSON into `ToolCallEvent` | Nothing (entry point) |
| DetectionEngine | Run all three signals, fuse into single `DetectionResult` | PatternEngine, SemanticClassifier, SequenceAnalyzer, FusionLayer |
| PatternEngine | Fast regex scan (<50ms) against YAML rule files per agent type | YAML rule files |
| SemanticClassifier | ONNX MiniLM embedding + Mahalanobis distance scoring | ONNX Runtime, model files |
| SequenceAnalyzer | Behavioral sequence monitoring (SEQ rules, ring buffer) | Session event history |
| FusionLayer | Weighted combination of three signals into calibrated verdict + confidence | Calibration parameters (from 208K trajectory dataset) |
| PolicyEngine | Evaluate DetectionResult + context against operator policy -> enforcement decision | Policy backend (YAML/OPA/Cedar) |
| SandboxAdapter (Protocol) | Apply/remove constraints on the execution environment | OS sandbox primitives |
| AuditLayer | Build structured events from all pipeline stages, emit in multiple formats | SARIF schema, OTel SDK |
| RuntimeOrchestrator | Wire adapters, run the pipeline for each event, manage session lifecycle | All components |

## Recommended Project Structure

```
src/cloneguard/
├── __init__.py              # Version, public API surface
├── cli.py                   # CLI entry points (unchanged)
├── runtime.py               # RuntimeOrchestrator — wires pipeline, dispatches events
│
├── adapters/                # Input adapters (normalize agent events)
│   ├── __init__.py
│   ├── base.py              # InputAdapter Protocol + ToolCallEvent dataclass
│   ├── claude_code.py       # Claude Code hook JSON protocol
│   ├── cursor.py            # Cursor hook events
│   ├── gemini.py            # Gemini CLI hook events
│   ├── mcp.py               # MCP protocol middleware
│   └── agt.py               # Microsoft AGT ToolCallInterceptor
│
├── detection/               # Detection engine (three-signal fusion)
│   ├── __init__.py          # DetectionEngine facade
│   ├── engine.py            # DetectionEngine class (orchestrates signals)
│   ├── patterns.py          # PatternEngine (moved from src/cloneguard/patterns.py)
│   ├── semantic.py          # SemanticClassifier (MiniLM ONNX, Ollama fallback)
│   ├── sequence.py          # SequenceAnalyzer (extracted from monitor.py)
│   ├── fusion.py            # FusionLayer (weighted signal combination)
│   └── types.py             # DetectionResult, SignalResult, Verdict, Confidence
│
├── policy/                  # Policy engine (verdict -> enforcement decision)
│   ├── __init__.py
│   ├── engine.py            # PolicyEngine (dispatches to backend)
│   ├── types.py             # PolicyDecision, Constraint, ConstraintSet
│   ├── yaml_backend.py      # YAML policy evaluation (default)
│   ├── opa_backend.py       # OPA/Rego evaluation (REST API to sidecar)
│   └── cedar_backend.py     # Cedar evaluation (via cedarpy bindings)
│
├── enforcement/             # Sandbox adapters (apply constraints)
│   ├── __init__.py
│   ├── base.py              # SandboxAdapter Protocol + EnforcementOutcome
│   ├── noop.py              # NoopAdapter (detection-only, v0.5.0 compat)
│   ├── landlock.py          # LandlockAdapter (Linux 5.13+, unprivileged)
│   ├── seatbelt.py          # SeatbeltAdapter (macOS sandbox-exec)
│   └── probe.py             # Auto-detection of available sandbox capabilities
│
├── audit/                   # Audit layer (structured event emission)
│   ├── __init__.py
│   ├── builder.py           # EventBuilder (assembles AuditEvent from pipeline data)
│   ├── types.py             # AuditEvent schema, event_type enum
│   ├── ndjson.py            # NDJSON line emitter
│   ├── sarif.py             # SARIF 2.1.0 emitter (using sarif-om)
│   └── otel.py              # OpenTelemetry span emitter
│
├── rules/                   # Pattern rule YAML files (existing, reorganized)
│   ├── coding/              # Current 204 patterns (25 YAMLs, moved from rules/)
│   ├── browser/             # Future: DOM injection, invisible text
│   ├── cicd/                # Future: workflow injection, secret exfil
│   ├── mcp/                 # Future: tool poisoning, RADE
│   └── common/              # Cross-agent patterns (encoding, unicode)
│
├── model/                   # ML model artifacts (unchanged)
│   ├── mini_semantic.onnx
│   └── mahalanobis_params.npz
│
├── config/                  # Configuration management
│   ├── __init__.py
│   ├── loader.py            # Config file discovery + merge logic
│   └── schema.py            # Pydantic models for config validation
│
├── hooks.py                 # THIN SHIM — dispatches to runtime.py (backward compat)
├── scanner.py               # THIN SHIM — calls DetectionEngine (backward compat)
├── allowlist.py             # Unchanged (user-local false positive suppression)
├── sequence_allowlist.py    # Unchanged (user-local SEQ rule escape hatch)
└── trust_cache.py           # Unchanged (Layer 0 file hash caching)
```

### Structure Rationale

- **adapters/:** Each agent platform speaks a different protocol. Normalizing to `ToolCallEvent` at the boundary means the entire engine below is agent-agnostic. New agent support = new adapter file, zero changes to detection/policy/enforcement/audit.
- **detection/:** Three signals + fusion belong together because they share the `DetectionResult` output contract. `patterns.py`, `semantic.py`, and `sequence.py` are leaf modules with no cross-dependencies. `fusion.py` consumes all three and produces the calibrated verdict.
- **policy/:** Separate from detection because the same detection result can produce different enforcement decisions based on operator policy. A startup with YOLO settings and an enterprise with strict compliance use the same detection engine with different policy backends.
- **enforcement/:** Sandbox adapters are a classic Strategy pattern. The `SandboxAdapter` Protocol defines what enforcement can do; concrete adapters map to OS primitives. `probe.py` auto-detects available adapters at startup.
- **audit/:** Separate from enforcement because audit must capture ALL events (including ALLOW decisions), not just constrained/blocked ones. Multiple emitters run in parallel for the same event. Audit is the final pipeline stage and depends on data from every upstream stage.
- **hooks.py / scanner.py as thin shims:** Backward compatibility with v0.5.0 is non-negotiable. These files remain importable at their current paths, but their implementation becomes a 5-line dispatch to `runtime.py`. This ensures `cloneguard hook-check --event PreToolUse` continues to work identically.

## Architectural Patterns

### Pattern 1: Pipeline with Typed Contracts

**What:** Every pipeline stage communicates through immutable dataclasses. The pipeline is strictly `ToolCallEvent -> DetectionResult -> PolicyDecision -> EnforcementOutcome -> AuditEvent`. No stage reaches back into a previous stage or accesses global state.

**When to use:** Always. This is the backbone of the architecture.

**Trade-offs:** Slightly more boilerplate than passing dicts around. Far easier to test, type-check, and debug. Each stage can be tested in isolation with constructed inputs.

**Example:**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class Verdict(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

@dataclass(frozen=True)
class SignalResult:
    """Output of a single detection signal."""
    signal_name: str          # "pattern", "semantic", "sequence"
    score: float              # 0.0 - 1.0
    verdict: Verdict
    details: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class DetectionResult:
    """Fused output of all detection signals."""
    verdict: Verdict
    confidence: float         # 0.0 - 1.0
    signals: tuple[SignalResult, ...]
    scan_time_ms: float
    context: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class PolicyDecision:
    """Output of policy evaluation."""
    action: str               # "allow", "constrain", "block"
    constraints: ConstraintSet | None = None
    reason: str = ""
    policy_version: str = ""

@dataclass(frozen=True)
class EnforcementOutcome:
    """What the sandbox adapter actually did."""
    action_taken: str         # "allowed", "constrained", "blocked"
    constraints_applied: dict[str, Any] = field(default_factory=dict)
    sandbox_adapter: str = "noop"
    snapshot_id: str | None = None
```

### Pattern 2: Protocol-Based Adapter Interfaces

**What:** Use `typing.Protocol` (PEP 544 structural subtyping) for all extension points: `InputAdapter`, `SandboxAdapter`, `PolicyBackend`, `AuditEmitter`. Consumers depend on the Protocol, not on concrete implementations.

**When to use:** For every boundary where multiple implementations exist or will exist. Protocols over ABCs because they support structural subtyping -- a third-party class that implements the right methods satisfies the protocol without inheriting from CloneGuard's base class. This matters for the AGT `ToolCallInterceptor` integration where CloneGuard must conform to Microsoft's interface, not the other way around.

**Trade-offs:** Protocols provide no runtime enforcement of the contract (unlike ABCs with `@abstractmethod`). Mitigated by `mypy --strict` catching violations at type-check time and by explicit integration tests.

**Example:**

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class InputAdapter(Protocol):
    """Normalize any agent event into a ToolCallEvent."""

    @property
    def agent_type(self) -> str: ...

    def parse_event(self, raw: bytes) -> ToolCallEvent | None:
        """Parse raw input into normalized event. Returns None if not applicable."""
        ...

@runtime_checkable
class SandboxAdapter(Protocol):
    """Apply/remove execution constraints."""

    @property
    def name(self) -> str: ...

    def restrict_network(self, allow: list[str]) -> None: ...
    def restrict_filesystem(self, writable: list[str], readable: list[str]) -> None: ...
    def snapshot(self) -> str: ...
    def rollback(self, snapshot_id: str) -> None: ...
    def release(self) -> None: ...

@runtime_checkable
class PolicyBackend(Protocol):
    """Evaluate detection result against policy."""

    def evaluate(
        self,
        event: ToolCallEvent,
        result: DetectionResult,
        config: OperatorConfig,
    ) -> PolicyDecision: ...

@runtime_checkable
class AuditEmitter(Protocol):
    """Emit an audit event in a specific format."""

    def emit(self, event: AuditEvent) -> None: ...
    def flush(self) -> None: ...
```

### Pattern 3: Composition Root with Auto-Discovery

**What:** A single `RuntimeOrchestrator` class wires all components at startup. It discovers available sandbox adapters (via `probe.py`), loads operator config, selects policy backend, and constructs the pipeline. No component discovers its own dependencies -- the orchestrator injects everything.

**When to use:** At application startup (CLI entry point, hook entry point, library import).

**Trade-offs:** One class that knows about all components (a "god class" concern). Acceptable because it is pure wiring logic with no business rules. Each component it wires is independently testable.

**Example:**

```python
class RuntimeOrchestrator:
    """Wires the pipeline and dispatches events."""

    def __init__(self, config: OperatorConfig | None = None) -> None:
        self.config = config or OperatorConfig.load()
        self.detection = DetectionEngine(
            patterns=PatternEngine(rule_dirs=self.config.rule_dirs),
            semantic=SemanticClassifier(),
            sequence=SequenceAnalyzer(),
            fusion=FusionLayer(calibration=self.config.fusion_calibration),
        )
        self.policy = PolicyEngine(backend=self._select_policy_backend())
        self.sandbox = probe_best_adapter(preference=self.config.sandbox_preference)
        self.audit = AuditLayer(emitters=self._build_emitters())

    def process_event(self, event: ToolCallEvent) -> int:
        """Run the full pipeline. Returns exit code for hook protocol."""
        result = self.detection.analyze(event)
        decision = self.policy.evaluate(event, result, self.config)
        outcome = self._enforce(decision)
        self.audit.record(event, result, decision, outcome)
        return self._exit_code(decision)
```

### Pattern 4: Backward-Compatible Thin Shims

**What:** The existing `hooks.py::main()` and `scanner.py::RepoScanner` become thin wrappers that construct a `RuntimeOrchestrator` and delegate. The Claude Code hook protocol calls `cloneguard hook-check --event PreToolUse` exactly as before. The shim reads stdin JSON, constructs a `ToolCallEvent` via `ClaudeCodeAdapter`, and passes it to the orchestrator.

**When to use:** For the v0.5.0 -> v2 migration. The shims exist solely for backward compatibility. New integrations (AGT, MCP middleware) go directly through the RuntimeOrchestrator or the appropriate adapter.

**Trade-offs:** Two entry paths to the same logic. Shims must be kept in sync until a major version bump deprecates them. Mitigated by shim implementation being ~10 lines of delegation.

## Data Flow

### Hook Event Flow (Layers 1-3)

```
Claude Code invokes hook
    |
    v
hooks.py::main() [thin shim]
    |
    v
ClaudeCodeAdapter.parse_event(stdin_json) -> ToolCallEvent
    |  Fields: event_type, tool_name, tool_input, source_path,
    |          content, agent_type, session_id
    v
RuntimeOrchestrator.process_event(event)
    |
    +--> DetectionEngine.analyze(event)
    |        |
    |        +--> PatternEngine.scan(content, mode) -> SignalResult
    |        +--> SemanticClassifier.classify(content, mode) -> SignalResult
    |        +--> SequenceAnalyzer.check(event, session) -> SignalResult
    |        +--> FusionLayer.fuse(pattern, semantic, sequence) -> DetectionResult
    |        |
    |        v
    |    DetectionResult(verdict, confidence, signals)
    |
    +--> PolicyEngine.evaluate(event, detection_result, config)
    |        |
    |        v
    |    PolicyDecision(action, constraints, reason)
    |
    +--> SandboxAdapter.apply(decision.constraints)   [if CONSTRAIN]
    |    SandboxAdapter.block()                        [if BLOCK]
    |        |
    |        v
    |    EnforcementOutcome(action_taken, constraints_applied)
    |
    +--> AuditLayer.record(event, detection, decision, outcome)
    |        |
    |        +--> NDJSONEmitter.emit(audit_event)
    |        +--> SARIFEmitter.emit(audit_event)    [if configured]
    |        +--> OTelEmitter.emit(audit_event)     [if configured]
    |
    v
Exit code returned to Claude Code (0=allow, 2=block)
```

### Layer 0 Pre-Execution Scan Flow

```
CLI: cloneguard [scan|wrap]
    |
    v
scanner.py [thin shim]
    |
    v
RuntimeOrchestrator (Layer 0 mode)
    |
    +--> File collection (high/medium priority)
    |
    +--> For each file:
    |      TrustCache check -> skip if hash unchanged
    |      Allowlist check -> skip if content hash approved
    |      DetectionEngine.analyze(file_event) -> DetectionResult
    |      PolicyEngine.evaluate(file_event, result) -> PolicyDecision
    |
    +--> Aggregate results -> ScanReport
    |
    +--> AuditLayer.flush()
    |
    v
Exit code + formatted report to stdout
```

### Session State Flow

```
Session starts
    |
    v
SequenceAnalyzer creates session ring buffer (max 50 events)
    |
    +--> Each ToolCallEvent is recorded in ring buffer
    |    (tool_name, timestamp, path, has_sensitive_read, etc.)
    |
    +--> On PreToolUse: check_enforcement() scans lookback window (10 events)
    |    for SEQ-001/002/005 patterns
    |
    +--> Session trust cache: path -> SHA256 of approved content
    |    (prevents redundant rescanning within session)
    |
    v
Session ends (process exit) -> all state discarded
```

### Key Data Flows

1. **ToolCallEvent normalization:** Every adapter produces the same `ToolCallEvent` dataclass. The detection engine never sees agent-specific formats. This is the critical abstraction boundary -- everything downstream of the adapter is agent-agnostic.

2. **Three-signal fusion:** Pattern, semantic, and sequence signals are computed independently (potentially in parallel for pattern + semantic). The FusionLayer combines them using context-weighted scoring calibrated against the 208K trajectory dataset. The fusion output is a single `DetectionResult` with verdict (SAFE/SUSPICIOUS/MALICIOUS) and confidence (0.0-1.0).

3. **Policy evaluation:** The policy engine receives the full `DetectionResult` plus the original `ToolCallEvent` plus operator config. This allows policies like "block MALICIOUS on any tool" or "constrain SUSPICIOUS only when tool_name is Bash and network access is involved." Policy backends (YAML, OPA, Cedar) all produce the same `PolicyDecision`.

4. **Audit assembly:** The `EventBuilder` collects data from every pipeline stage (event, detection, decision, outcome) and assembles a complete `AuditEvent`. Each emitter (NDJSON, SARIF, OTel) renders the same `AuditEvent` in its format. This ensures all formats contain identical information.

## Internal Boundaries and Interface Contracts

| Boundary | Protocol/Contract | Direction | Cardinality |
|----------|-------------------|-----------|-------------|
| Agent -> InputAdapter | Agent-specific (hook JSON, AGT API, MCP proto) | Inbound | Many adapters, one per agent type |
| InputAdapter -> RuntimeOrchestrator | `ToolCallEvent` dataclass | Forward | 1:1 per event |
| RuntimeOrchestrator -> DetectionEngine | `ToolCallEvent` -> `DetectionResult` | Forward | 1:1 |
| DetectionEngine -> PatternEngine | `str` content + `ScanMode` -> `SignalResult` | Internal | 1:1 |
| DetectionEngine -> SemanticClassifier | `str` content + `ScanMode` -> `SignalResult` | Internal | 1:1 |
| DetectionEngine -> SequenceAnalyzer | `ToolCallEvent` + session -> `SignalResult` | Internal | 1:1 |
| DetectionEngine -> FusionLayer | 3x `SignalResult` -> `DetectionResult` | Internal | 1:1 |
| RuntimeOrchestrator -> PolicyEngine | `ToolCallEvent` + `DetectionResult` -> `PolicyDecision` | Forward | 1:1 |
| RuntimeOrchestrator -> SandboxAdapter | `PolicyDecision.constraints` -> `EnforcementOutcome` | Forward | 1:1 |
| RuntimeOrchestrator -> AuditLayer | All upstream data -> `AuditEvent` emitted | Forward | 1:N (one per emitter) |
| AuditLayer -> AuditEmitter | `AuditEvent` -> format-specific output | Internal | 1:1 per emitter |

## Build Order (Dependencies Between Components)

The build order is constrained by what depends on what. Build bottom-up from types to orchestration.

```
Phase order (each phase builds on the previous):

Phase A: Core Types + Detection Extraction
  ├── detection/types.py (Verdict, SignalResult, DetectionResult)
  ├── policy/types.py (PolicyDecision, ConstraintSet)
  ├── enforcement/base.py (SandboxAdapter Protocol, EnforcementOutcome)
  ├── audit/types.py (AuditEvent schema)
  ├── adapters/base.py (InputAdapter Protocol, ToolCallEvent)
  └── detection/engine.py (extract from hooks.py, wrap existing PatternEngine + MiniSemantic)
      Depends on: detection/types.py

Phase B: Audit Layer + NDJSON
  ├── audit/builder.py (EventBuilder)
  ├── audit/ndjson.py (NDJSONEmitter)
  └── audit/sarif.py (SARIF 2.1.0 emitter using sarif-om)
      Depends on: audit/types.py

Phase C: Policy Engine + YAML Backend
  ├── policy/engine.py (PolicyEngine dispatcher)
  └── policy/yaml_backend.py (YAML policy evaluation)
      Depends on: policy/types.py, detection/types.py, adapters/base.py

Phase D: Enforcement Layer + NoopAdapter
  ├── enforcement/noop.py (preserve v0.5.0 exit-code behavior)
  └── enforcement/probe.py (auto-detection of capabilities)
      Depends on: enforcement/base.py

Phase E: Input Adapters + Runtime Orchestrator
  ├── adapters/claude_code.py (normalize existing hooks.py JSON parsing)
  ├── runtime.py (wire everything together)
  ├── hooks.py (thin shim delegating to runtime.py)
  └── scanner.py (thin shim delegating to runtime.py)
      Depends on: ALL of the above

Phase F: Additional Adapters + Sandbox Adapters
  ├── enforcement/landlock.py (Linux)
  ├── enforcement/seatbelt.py (macOS)
  ├── adapters/agt.py (Microsoft AGT ToolCallInterceptor)
  ├── adapters/mcp.py (MCP protocol middleware)
  └── detection/fusion.py (calibrated three-signal fusion)
      Depends on: Phase E complete

Phase G: Enterprise Policy Backends
  ├── policy/opa_backend.py (REST API to OPA sidecar)
  └── policy/cedar_backend.py (via cedarpy PyPI bindings)
      Depends on: Phase C (policy engine interface)
```

**Rationale for this ordering:**

1. **Types first** (Phase A): Every downstream component imports these dataclasses. They have zero external dependencies and can be tested trivially.

2. **Detection extraction second** (Phase A): The detection engine is the highest-risk refactor -- it's extracting logic from the 500-line `hooks.py` and the 1000-line `monitor.py`. Do this before anything else because it's the most likely place for regression.

3. **Audit before policy** (Phase B before C): NDJSON audit logging provides immediate operational value and is the simplest subsystem to build. It also validates the `AuditEvent` schema that every subsequent phase will use. SARIF emission satisfies GitHub Advanced Security integration.

4. **Policy before enforcement** (Phase C before D): The policy engine's `PolicyDecision` type defines what enforcement must implement. Building policy first ensures the enforcement interface is correct.

5. **NoopAdapter alongside policy** (Phase D): The `NoopAdapter` is trivial but critical -- it preserves exact v0.5.0 behavior. Building it alongside policy proves the enforcement interface works without requiring OS sandbox complexity.

6. **Orchestrator wires everything** (Phase E): The `RuntimeOrchestrator` can only be built after all components it wires exist. The thin shims in `hooks.py` and `scanner.py` are the final backward-compatibility layer.

7. **Real sandboxes and adapters last** (Phase F): LandlockAdapter, SeatbeltAdapter, and framework adapters (AGT, MCP) are additive. They plug into existing interfaces without modifying core logic.

8. **Enterprise backends even later** (Phase G): OPA and Cedar backends require external dependencies (OPA sidecar or cedarpy bindings). They are enterprise features that can ship independently.

## Anti-Patterns

### Anti-Pattern 1: Global Singletons for Engine State

**What people do:** Current `hooks.py` uses module-level singletons (`_engine`, `_mini_classifier`, `_mini_attempted`) for lazy initialization. This works for a single-threaded hook process but prevents testing, parallel execution, and multi-session support.

**Why it's wrong:** Singletons make components untestable in isolation, introduce hidden coupling between modules, and prevent configuration changes without process restart. They also break if CloneGuard is imported as a library rather than invoked as a process.

**Do this instead:** Constructor injection in `RuntimeOrchestrator`. Each orchestrator instance owns its components. Tests construct orchestrators with mock components. Process-level caching (if needed for performance) lives in a `_cache` module separate from business logic.

### Anti-Pattern 2: Agent-Specific Logic in the Detection Engine

**What people do:** Embed Claude Code-specific parsing (reading `tool_input.command`, interpreting `tool_input.content`, etc.) inside the detection engine or policy engine.

**Why it's wrong:** Every new agent type requires modifying the core engine. The engine becomes a tangle of `if agent_type == "claude-code"` branches. Testing requires mocking agent-specific formats.

**Do this instead:** All agent-specific parsing lives in the input adapter. The detection engine receives a `ToolCallEvent` with normalized fields (`content: str`, `tool_name: str`, `source_path: str`). The adapter is responsible for extracting these from whatever format the agent provides.

### Anti-Pattern 3: Mixing Detection and Policy

**What people do:** Hardcode enforcement decisions inside the detection engine (e.g., "if severity >= HIGH then block"). Current `hooks.py` does this -- the same function both detects patterns and decides the exit code.

**Why it's wrong:** Two operators with identical detections may want different enforcement: a startup might warn-only while an enterprise blocks. Hardcoding the decision inside detection makes this impossible without forking detection logic.

**Do this instead:** Detection produces `DetectionResult` (verdict + confidence + signals). Policy produces `PolicyDecision` (action + constraints + reason). They are separate pipeline stages with separate tests, separate configuration, and separate concerns.

### Anti-Pattern 4: Stdout Pollution from Non-Hook Components

**What people do:** Use `print()` for logging, debugging, or status messages from anywhere in the codebase.

**Why it's wrong:** Stdout is the hook communication channel. Any non-hook output on stdout breaks the JSON protocol with Claude Code. Current `hooks.py` is careful about this, but a modular architecture with multiple components increases the risk.

**Do this instead:** All components use Python `logging` module exclusively. Only `hooks.py::main()` and `cli.py` write to stdout (hook responses and user-facing output, respectively). The audit layer writes to files or network, never stdout.

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| Single developer workstation (current) | Full pipeline runs synchronously in-process. NoopAdapter. NDJSON to local file. <20ms per hook invocation. No changes needed. |
| Team of 10-50 developers | Add SARIF output for GitHub Advanced Security integration. Policy YAML in repo for team-wide consistency. Fleet deployment via MDM/Ansible. |
| Enterprise (100+ developers) | OPA/Cedar policy backends. SIEM integration (NDJSON to Splunk HEC/Sentinel). OTel spans for observability. Centralized policy management. SPIFFE identity on audit events. |
| CI/CD pipeline integration | Input adapter for GitHub Actions events. LandlockAdapter for runner sandboxing. SARIF upload to GitHub Security tab. No architectural changes -- just new adapters. |

### Scaling Priorities

1. **First bottleneck: Detection latency at high SUSPICIOUS rates.** If many events hit the ambiguous zone (0.4-0.6 confidence), selective MELON re-execution adds ~200ms per event. Mitigation: MELON is opt-in and selective (5-10% of events). FusionLayer calibration should minimize the ambiguous zone.

2. **Second bottleneck: Audit emission under high event volume.** CI/CD runners may generate hundreds of events per minute. Mitigation: NDJSON emitter is append-only to a file (fast). SARIF emitter batches results per run. OTel emitter uses the standard BatchSpanProcessor with 30s export interval.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| OPA (Rego) | REST API to localhost sidecar (port 8181) | Deploy OPA alongside CloneGuard. No embedded Rego interpreter exists for Python. WASM compilation of Rego policies is an alternative for single-binary deployment. |
| Cedar (cedarpy) | In-process Python bindings via PyPI `cedarpy` | Rust-backed, ~134ms for 1000 batch evaluations. Ships as platform wheel (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64). |
| SARIF | In-process using `sarif-om` (Microsoft Python SARIF object model) | Generated from SARIF 2.1.0 JSON schema. Alternatively `sarif-pydantic` for Pydantic models. |
| OpenTelemetry | In-process using `opentelemetry-sdk` | TracerProvider + BatchSpanProcessor. Each pipeline invocation is a span with detection/policy/enforcement as child spans. |
| Ollama (Tier 2) | HTTP to localhost:11434 | Existing integration. No changes for modular architecture. |
| Landlock | Python ctypes to kernel syscalls via `landlock` PyPI package | Linux 5.13+ only. Unprivileged. Dev version 1.0.0.dev5 (May 2025). |
| macOS Seatbelt | subprocess call to `sandbox-exec` with SBPL profile | Deprecated by Apple but still functional. Used by Claude Code itself. Long-term uncertainty. |
| Microsoft AGT | Implement `ToolCallInterceptor` interface from `agent-governance-toolkit` PyPI | CloneGuard becomes a plugin in AGT's governance pipeline. <0.1ms policy overhead per AGT's benchmarks. |

### Internal Boundaries (Module-to-Module Communication)

| Boundary | Communication | Notes |
|----------|---------------|-------|
| adapters -> detection | `ToolCallEvent` dataclass (frozen, immutable) | Adapter must normalize all agent-specific fields. Detection never parses raw agent JSON. |
| detection -> policy | `DetectionResult` dataclass (frozen, immutable) | Contains verdict, confidence, and all signal details. Policy engine can make fine-grained decisions based on individual signal scores. |
| policy -> enforcement | `PolicyDecision` dataclass with `ConstraintSet` | Enforcement adapter interprets constraints generically. If a constraint type is unsupported by the current adapter, it is logged and the event is escalated to BLOCK (fail-closed). |
| enforcement -> audit | `EnforcementOutcome` dataclass | Records what was actually applied (may differ from what was requested if adapter lacks capability). |
| audit emitters | `AuditEvent` dataclass (fully assembled) | Each emitter transforms the same event to its output format. Emitters are independent -- one emitter failing must not block others. |

## Sources

- [OPA Integration Documentation](https://www.openpolicyagent.org/docs/integration) -- REST API, Go library, WASM integration patterns
- [OPA Rego Python Library](https://github.com/open-policy-agent/rego-python) -- Python interaction with Rego ASTs
- [Cedar Policy Language](https://docs.cedarpolicy.com/) -- Authorization policy language specification
- [cedar-py Python Bindings](https://github.com/k9securityio/cedar-py) -- Python bindings, batch evaluation benchmarks (~134ms/1000 evals)
- [cedarpy on PyPI](https://pypi.org/project/cedarpy/) -- Platform wheels for Linux, macOS, Windows
- [AWS Policy AgentCore + Cedar](https://byteiota.com/aws-policy-agentcore-cedar-language-secures-ai-agents/) -- Cedar in agentic AI context
- [Microsoft SARIF Python Object Model](https://github.com/microsoft/sarif-python-om) -- SARIF 2.1.0 classes generated from JSON schema
- [sarif-pydantic on PyPI](https://pypi.org/project/sarif-pydantic/) -- Pydantic models for SARIF 2.1.0
- [OpenTelemetry Python SDK Trace](https://opentelemetry-python.readthedocs.io/en/latest/sdk/trace.html) -- TracerProvider, SpanProcessor, Span APIs
- [Landlock Python Package](https://pypi.org/project/landlock/) -- Python interface to Landlock LSM (v1.0.0.dev5)
- [Landlock Documentation](https://landlock.io/) -- Unprivileged filesystem/network sandboxing
- [macOS Seatbelt / sandbox-exec](https://pierce.dev/notes/a-deep-dive-on-agent-sandboxes) -- Agent sandbox deep dive including Seatbelt deprecation status
- [agent-seatbelt-sandbox](https://github.com/michaelneale/agent-seatbelt-sandbox) -- Native macOS sandboxing for data egress prevention
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) -- ToolCallInterceptor, PolicyProviderInterface, <0.1ms overhead
- [PEP 544 -- Protocols: Structural Subtyping](https://peps.python.org/pep-0544/) -- Python Protocol class specification
- [structlog](https://www.structlog.org/) -- Structured logging library for Python (NDJSON output)
- [NDJSON for Logs](https://ndjson.com/use-cases/log-processing/) -- NDJSON format specification for structured logging
- CloneGuard v2 Architecture Design Doc (`docs/plans/2026-04-05-cloneguard-v2-architecture-design.md`) -- Internal design document, validated

---
*Architecture research for: CloneGuard v2 universal agentic defense layer*
*Researched: 2026-04-05*
