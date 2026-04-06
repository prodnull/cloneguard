# Phase 4: Detection Excellence - Context

**Gathered:** 2026-04-06 (auto mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

Three-signal fusion (pattern + semantic + sequence) is calibrated on production data across agent types, producing measurably better detection with controlled FPR. MELON selective re-execution triggers in the ambiguous confidence zone with circuit breaker protection. Cross-agent pattern libraries expand detection to memory/config poisoning and MCP tool fingerprinting. Adversarial evaluation publishes honest results against adaptive attackers with full defense knowledge.

</domain>

<decisions>
## Implementation Decisions

### Fusion Scoring Strategy
- **D-01:** New `FusionLayer` module at `src/cloneguard/detection/fusion.py` that sits between individual signal scans and `DetectionResult` construction. Replaces current implicit max(scores) logic in `DetectionEngine`.
- **D-02:** Context-weighted rule table with ScanMode-aware multipliers. Each signal (pattern, semantic, sequence) gets a base weight, multiplied by a ScanMode factor (STRICT signals upweighted, LENIENT downweighted). Agent-type profiles select different weight sets.
- **D-03:** Fusion produces both a single calibrated confidence float (for threshold comparison) and per-signal breakdown retained in `DetectionResult.signals`. Operators use the single score for policy thresholds; researchers use the breakdown for debugging.
- **D-04:** Agent type from `InputAdapter` (Phase 3) drives weight profile selection. Default weight profile for unknown agent types. Profiles stored as YAML shipped with the package.
- **D-05:** Fusion is deterministic and auditable — no ML model in the fusion path, only calibrated weights. This avoids the FPR regression problems seen with IPI Arena retraining (9% to 20-42%).

### Calibration Pipeline
- **D-06:** Offline calibration script (`scripts/calibrate_fusion.py`) runs all three signals against labeled trajectory samples from the 208K dataset. Optimizes weights via grid search to minimize FPR at target TPR thresholds.
- **D-07:** Calibration output is a build-time artifact — weight profiles shipped as YAML in `src/cloneguard/detection/profiles/`. Operators can override weights via `~/.cloneguard/policy.yaml` under a `fusion.weights` section.
- **D-08:** FPR tracked per content type: CI configs, security documentation, test fixtures, MCP tool descriptions, source code. Each must remain below the standalone baseline (9.2%) per category.
- **D-09:** Calibration reproducibility: script produces a calibration report (markdown) documenting dataset splits, weight grid, per-content-type FPR at each grid point, and the selected weight set with rationale.

### MELON Selective Re-Execution (DETC-03)
- **D-10:** MELON triggers post-fusion, pre-enforcement — only when fusion confidence falls in the configurable ambiguous zone (default 0.4-0.6). High-confidence verdicts skip re-execution entirely.
- **D-11:** Re-execution approach: the tool call input is masked (sections removed per ICML 2025 algorithm), re-submitted to the agent, and output compared for semantic divergence. Divergence above threshold upgrades verdict to MALICIOUS.
- **D-12:** Circuit breaker: sliding window rate limiter. If >15% of recent tool calls (window size 20) trigger MELON, MELON is disabled for the remainder of the session with a logged warning. Prevents runaway latency on adversarial content.
- **D-13:** Latency budget: MELON adds up to 500ms per triggered call. Acceptable because it fires only in the ambiguous zone (~5-10% of calls). Total p95 budget remains under 20ms for non-MELON calls.
- **D-14:** MELON requires `snapshot()` / `rollback()` on SandboxAdapter (Phase 2 deferred these as optional no-op). Phase 4 implements these for LandlockAdapter and SeatbeltAdapter. NoopAdapter snapshot/rollback remains no-op (MELON logs divergence but cannot roll back).

### Cross-Agent Pattern Libraries (DETC-04, DETC-05)
- **D-15:** Pattern library reorganization: `rules/` gets subdirectories — `rules/coding/` (existing 25 rules, moved), `rules/memory/` (config/memory poisoning), `rules/mcp/` (tool fingerprinting). PatternEngine loads from all subdirectories.
- **D-16:** Memory/config poisoning patterns (DETC-04): cover agent memory files (`.claude/memory/`, conversation history injection), dotfile injection (`.bashrc`, `.zshrc`, `.gitconfig`), workspace config files (`.vscode/settings.json`, `.cursor/settings.json`), and persistent instructions modification.
- **D-17:** MCP tool description fingerprinting (DETC-05): known-good registry of MCP tool descriptions with hash-based fingerprinting. Flag descriptions that deviate from registered versions (potential RADE attack — tool description poisoning). Registry ships as JSON in `src/cloneguard/detection/mcp_registry.json`.
- **D-18:** Pattern libraries are agent-type-agnostic at the rule level. The engine loads all rules; ScanMode and agent-type context determine which rules fire and at what weight in the fusion layer.

### Adversarial Evaluation (DETC-06)
- **D-19:** Follow "Attacker Moves Second" methodology (Nasr, Carlini, Tramer) with full defense knowledge for adaptive adversary simulation. Extends existing adaptive red team methodology (docs/ADAPTIVE-RED-TEAM.md).
- **D-20:** Evaluation datasets: existing corpora (data/benchmark/malicious_corpus.json, benign_corpus.json), IPI Arena dataset, garak 13,597-probe baseline, plus new fusion-targeting payloads (e.g., payloads that evade one signal but not all three).
- **D-21:** Reporting: structured markdown report with honest bypass rates per attack class, comparison to pre-fusion baseline (standalone Tier 0+1.5), FPR regression analysis per content type, and a "what fusion buys" section showing detection delta.
- **D-22:** Results published alongside code — no cherry-picking. If fusion doesn't help in certain attack classes, report that honestly. Consistent with existing 16.7% bypass rate disclosure approach.

### Claude's Discretion
- Exact weight grid search hyperparameters (step size, bounds)
- Internal data structures for the sliding window circuit breaker
- MELON masking strategy details (which sections to mask, stride)
- MCP registry JSON schema and initial tool entries
- Calibration report formatting
- Test organization for fusion layer vs. MELON vs. pattern libraries

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v2 Architecture Design
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` -- Full v2 architecture with three-signal fusion (section 4.1), MELON selective re-execution (section 4.2), adaptive constraint generation (section 4.3), honest adversarial evaluation (section 4.4)
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` S4.1 -- Fusion layer calibration approach, context-weighted scoring, trajectory dataset usage
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` S4.2 -- MELON selective triggering, ambiguous confidence zone, overhead estimation

### Detection Engine (Phase 1 output -- fusion layer wraps this)
- `src/cloneguard/detection/engine.py` -- DetectionEngine with scan methods, current max(scores) logic to replace
- `src/cloneguard/detection/types.py` -- ToolCallEvent, SignalResult, DetectionResult (fusion extends these)
- `src/cloneguard/detection/patterns.py` -- PatternEngine, ScanMode, Verdict enums
- `src/cloneguard/detection/semantic.py` -- MiniSemanticClassifier (Signal 2 input to fusion)
- `src/cloneguard/detection/sequence.py` -- ToolCallMonitor, SEQ rules (Signal 3 input to fusion)

### Enforcement Pipeline (Phase 2 -- fusion feeds into this)
- `src/cloneguard/enforcement/types.py` -- PolicyDecision, Constraints, EnforcementOutcome
- `src/cloneguard/enforcement/policy.py` -- PolicyEngine (fusion confidence drives verdict thresholds)
- `src/cloneguard/enforcement/adapter.py` -- SandboxAdapter Protocol (MELON needs snapshot/rollback)

### Adapter Layer (Phase 3 -- provides agent_type for fusion profiles)
- `src/cloneguard/adapters/` -- InputAdapter registry, agent-type detection (drives weight profile selection)

### Existing Pattern Rules
- `src/cloneguard/rules/` -- 25 existing YAML rule files (move to rules/coding/ subdirectory)
- `src/cloneguard/rules/mcp_tool_poisoning.yaml` -- Existing MCP patterns (extend for fingerprinting)
- `src/cloneguard/rules/memory_poisoning.yaml` -- Existing memory poisoning patterns (extend for DETC-04)

### Evaluation Assets
- `data/benchmark/` -- Malicious and benign evaluation corpora
- `data/redteam/ipi_arena/` -- IPI Arena attack dataset
- `data/training/` -- Training data for reference (not used in fusion -- fusion uses calibration, not training)
- `docs/ADAPTIVE-RED-TEAM.md` -- Existing adversarial evaluation methodology
- `scripts/pentest/eval_auto_classifier.py` -- Existing eval harness (20/20, 0 FP)

### Trajectory Dataset
- `data/swe-smith/`, `data/nebius-sweagent/`, `data/openhands/` -- 208K trajectory dataset directories (calibration source)

### Research (external)
- MELON: arXiv:2502.05174 (ICML 2025) -- Masked re-execution algorithm for provable PI detection
- Attacker Moves Second: arXiv:2510.09023 (Nasr, Carlini, Tramer) -- Adversarial evaluation methodology
- IPI Arena evaluation results -- 83.2% combined detection baseline

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DetectionEngine` (detection/engine.py): Has `scan_instructions_loaded`, `scan_pre_tool_use`, `scan_post_tool_use` methods that produce `SignalResult` objects. Fusion layer intercepts these signals before final `DetectionResult` assembly.
- `SignalResult` dataclass (detection/types.py): Already has `signal_type`, `verdict`, `confidence`, `details` fields. Perfect input type for the fusion layer.
- `PatternEngine._detect_mode()` (detection/patterns.py): ScanMode detection logic reusable for fusion weight selection.
- `_detect_mode_for_tier15()` (detection/engine.py): Three-signal mode detection heuristic (path + hook + content markers) -- similar concept to fusion, can inform weight selection.
- `ToolCallMonitor` (detection/sequence.py): Ring buffer of 50 events, 10-event lookback. Sequence signal source for fusion.
- `Mahalanobis detector` (mahalanobis.py): OOD scoring used by MiniSemanticClassifier. Produces confidence scores that feed into fusion.
- `eval_auto_classifier.py` (scripts/pentest/): Existing evaluation harness with 20/20 detection, 0 FP. Extend for fusion evaluation.

### Established Patterns
- **Protocol-based interfaces** (PEP 544): FusionLayer should be a Protocol for testability and future replacement.
- **Frozen dataclasses on hot path**: Fusion weight profiles and calibration results should be frozen.
- **Graceful degradation**: If one signal is unavailable (e.g., no ONNX model), fusion proceeds with available signals at reduced confidence.
- **Session-scoped state**: Circuit breaker and MELON rate tracking are session-scoped, consistent with existing trust cache pattern.
- **YAML rule loading**: PatternEngine already loads rules from `rules/` directory. Extend to load from subdirectories.

### Integration Points
- `DetectionEngine.scan()` methods: Fusion layer wraps the point where signals are aggregated into `DetectionResult`
- `PolicyEngine.evaluate()`: Receives fusion-calibrated confidence score for threshold comparison
- `SandboxAdapter.snapshot()/rollback()`: MELON needs these (currently no-op in all adapters)
- `InputAdapter.normalize()`: Provides `agent_type` that selects fusion weight profile
- `NDJSONEmitter` / `OTelEmitter`: Audit events include per-signal breakdown from fusion
- `~/.cloneguard/policy.yaml`: Operator weight overrides live here under `fusion.weights`

</code_context>

<specifics>
## Specific Ideas

- The v2 design doc explicitly says fusion is "context-weighted, not max(scores)" -- the current engine uses an implicit precedence system that must be replaced with the calibrated fusion layer.
- IPI Arena retraining (2026-03-22) showed unacceptable FPR regression (9% to 20-42%) -- this is why fusion uses calibrated weights rather than a trained model. The value is in fusion + calibration, not a better classifier.
- STATE.md flags "Phase 4 MELON production integration needs design work beyond the ICML paper description" -- the research step should study the paper and design the masking/comparison strategy.
- Trajectory data directories appear empty in the working tree (may be gitignored or stored externally) -- calibration pipeline needs to handle data loading from a configurable path.
- The existing 16.7% bypass rate (Opus iterative, bureaucratic-documentation evasion) is the benchmark to beat -- fusion should specifically address bureaucratic-doc payloads that evade the semantic classifier alone.

</specifics>

<deferred>
## Deferred Ideas

- OPA/Rego policy backend for fusion weight policies -- Phase 5 (GOVN-01)
- Cedar policy backend -- Phase 5 (GOVN-02)
- Browser agent pattern library (DOM injection, invisible text) -- Phase 5 (AGNT-01)
- Autonomous agent pattern library (goal hijacking, delegation abuse) -- Phase 5 (AGNT-02)
- Financial agent pattern library (transaction manipulation) -- Phase 5 (AGNT-03)
- CI/CD agent pattern library (workflow injection, release poisoning) -- Phase 5 (AGNT-04)
- Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) -- Phase 5 (AGNT-05)
- Adaptive constraint generation (semantics-aware constraint selection) -- advanced feature, beyond Phase 4 scope
- User-provided ONNX model support (bring-your-own classifier) -- v2 requirement XDET-04

None -- analysis stayed within phase scope.

</deferred>

---

*Phase: 04-detection-excellence*
*Context gathered: 2026-04-06*
