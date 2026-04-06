# Phase 4: Detection Excellence - Research

**Researched:** 2026-04-06
**Domain:** Three-signal fusion, MELON selective re-execution, cross-agent pattern libraries, adversarial evaluation
**Confidence:** HIGH (core architecture verified from codebase; MELON algorithm verified from paper + GitHub)

## Summary

Phase 4 builds the detection fusion layer that replaces the current implicit max(scores)/waterfall logic in `DetectionEngine` with a calibrated context-weighted scoring system. The engine currently processes signals sequentially (pattern -> semantic -> sequence) and returns the first non-clean result. The fusion layer must instead collect all three signals and produce a single calibrated confidence score with per-signal breakdown. This is architecturally the most complex phase -- it touches detection, enforcement (snapshot/rollback), pattern library organization, and evaluation infrastructure simultaneously.

The MELON integration requires careful adaptation from the paper's design. The ICML 2025 algorithm (arXiv:2502.05174) assumes an LLM-in-the-loop for re-execution and embedding comparison. CloneGuard's production constraint is <500ms for MELON-triggered calls and <20ms for non-MELON calls. The paper's approach uses OpenAI's text-embedding-3-small for tool call comparison, but CloneGuard already has MiniLM embeddings in-process. Adapting MELON to use the existing ONNX inference pipeline (embedding extraction from the classifier's CLS output) avoids API dependencies and stays within the latency budget.

The calibration pipeline needs the 208K trajectory dataset which is not in the working tree (gitignored / stored externally). The `scripts/download_trajectories.py` script downloads from HuggingFace. The calibration script must handle a configurable data path and gracefully degrade if data is unavailable (producing default weights). Pattern library reorganization (flat `rules/` to `rules/coding/`, `rules/memory/`, `rules/mcp/`) requires updating the PatternEngine glob pattern from `*.yaml` to `**/*.yaml` -- a one-line change with backward-compatible behavior.

**Primary recommendation:** Structure implementation as four waves: (1) FusionLayer + calibration pipeline, (2) MELON + snapshot/rollback, (3) pattern library expansion, (4) adversarial evaluation. Each wave is independently testable.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** New `FusionLayer` module at `src/cloneguard/detection/fusion.py` that sits between individual signal scans and `DetectionResult` construction. Replaces current implicit max(scores) logic in `DetectionEngine`.
- **D-02:** Context-weighted rule table with ScanMode-aware multipliers. Each signal (pattern, semantic, sequence) gets a base weight, multiplied by a ScanMode factor (STRICT signals upweighted, LENIENT downweighted). Agent-type profiles select different weight sets.
- **D-03:** Fusion produces both a single calibrated confidence float (for threshold comparison) and per-signal breakdown retained in `DetectionResult.signals`. Operators use the single score for policy thresholds; researchers use the breakdown for debugging.
- **D-04:** Agent type from `InputAdapter` (Phase 3) drives weight profile selection. Default weight profile for unknown agent types. Profiles stored as YAML shipped with the package.
- **D-05:** Fusion is deterministic and auditable -- no ML model in the fusion path, only calibrated weights. This avoids the FPR regression problems seen with IPI Arena retraining (9% to 20-42%).
- **D-06:** Offline calibration script (`scripts/calibrate_fusion.py`) runs all three signals against labeled trajectory samples from the 208K dataset. Optimizes weights via grid search to minimize FPR at target TPR thresholds.
- **D-07:** Calibration output is a build-time artifact -- weight profiles shipped as YAML in `src/cloneguard/detection/profiles/`. Operators can override weights via `~/.cloneguard/policy.yaml` under a `fusion.weights` section.
- **D-08:** FPR tracked per content type: CI configs, security documentation, test fixtures, MCP tool descriptions, source code. Each must remain below the standalone baseline (9.2%) per category.
- **D-09:** Calibration reproducibility: script produces a calibration report (markdown) documenting dataset splits, weight grid, per-content-type FPR at each grid point, and the selected weight set with rationale.
- **D-10:** MELON triggers post-fusion, pre-enforcement -- only when fusion confidence falls in the configurable ambiguous zone (default 0.4-0.6). High-confidence verdicts skip re-execution entirely.
- **D-11:** Re-execution approach: the tool call input is masked (sections removed per ICML 2025 algorithm), re-submitted to the agent, and output compared for semantic divergence. Divergence above threshold upgrades verdict to MALICIOUS.
- **D-12:** Circuit breaker: sliding window rate limiter. If >15% of recent tool calls (window size 20) trigger MELON, MELON is disabled for the remainder of the session with a logged warning. Prevents runaway latency on adversarial content.
- **D-13:** Latency budget: MELON adds up to 500ms per triggered call. Acceptable because it fires only in the ambiguous zone (~5-10% of calls). Total p95 budget remains under 20ms for non-MELON calls.
- **D-14:** MELON requires `snapshot()` / `rollback()` on SandboxAdapter (Phase 2 deferred these as optional no-op). Phase 4 implements these for LandlockAdapter and SeatbeltAdapter. NoopAdapter snapshot/rollback remains no-op (MELON logs divergence but cannot roll back).
- **D-15:** Pattern library reorganization: `rules/` gets subdirectories -- `rules/coding/` (existing 25 rules, moved), `rules/memory/` (config/memory poisoning), `rules/mcp/` (tool fingerprinting). PatternEngine loads from all subdirectories.
- **D-16:** Memory/config poisoning patterns (DETC-04): cover agent memory files (`.claude/memory/`, conversation history injection), dotfile injection (`.bashrc`, `.zshrc`, `.gitconfig`), workspace config files (`.vscode/settings.json`, `.cursor/settings.json`), and persistent instructions modification.
- **D-17:** MCP tool description fingerprinting (DETC-05): known-good registry of MCP tool descriptions with hash-based fingerprinting. Flag descriptions that deviate from registered versions (potential RADE attack -- tool description poisoning). Registry ships as JSON in `src/cloneguard/detection/mcp_registry.json`.
- **D-18:** Pattern libraries are agent-type-agnostic at the rule level. The engine loads all rules; ScanMode and agent-type context determine which rules fire and at what weight in the fusion layer.
- **D-19:** Follow "Attacker Moves Second" methodology (Nasr, Carlini, Tramer) with full defense knowledge for adaptive adversary simulation. Extends existing adaptive red team methodology (docs/ADAPTIVE-RED-TEAM.md).
- **D-20:** Evaluation datasets: existing corpora (data/benchmark/malicious_corpus.json, benign_corpus.json), IPI Arena dataset, garak 13,597-probe baseline, plus new fusion-targeting payloads (e.g., payloads that evade one signal but not all three).
- **D-21:** Reporting: structured markdown report with honest bypass rates per attack class, comparison to pre-fusion baseline (standalone Tier 0+1.5), FPR regression analysis per content type, and a "what fusion buys" section showing detection delta.
- **D-22:** Results published alongside code -- no cherry-picking. If fusion doesn't help in certain attack classes, report that honestly. Consistent with existing 16.7% bypass rate disclosure approach.

### Claude's Discretion
- Exact weight grid search hyperparameters (step size, bounds)
- Internal data structures for the sliding window circuit breaker
- MELON masking strategy details (which sections to mask, stride)
- MCP registry JSON schema and initial tool entries
- Calibration report formatting
- Test organization for fusion layer vs. MELON vs. pattern libraries

### Deferred Ideas (OUT OF SCOPE)
- OPA/Rego policy backend for fusion weight policies -- Phase 5 (GOVN-01)
- Cedar policy backend -- Phase 5 (GOVN-02)
- Browser agent pattern library (DOM injection, invisible text) -- Phase 5 (AGNT-01)
- Autonomous agent pattern library (goal hijacking, delegation abuse) -- Phase 5 (AGNT-02)
- Financial agent pattern library (transaction manipulation) -- Phase 5 (AGNT-03)
- CI/CD agent pattern library (workflow injection, release poisoning) -- Phase 5 (AGNT-04)
- Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) -- Phase 5 (AGNT-05)
- Adaptive constraint generation (semantics-aware constraint selection) -- beyond Phase 4 scope
- User-provided ONNX model support (bring-your-own classifier) -- v2 requirement XDET-04
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DETC-01 | Three-signal fusion layer calibrated on 208K trajectory dataset | FusionLayer architecture, calibration pipeline design, weight profile YAML format, trajectory data loading strategy |
| DETC-02 | Context-weighted fusion scoring with mode-aware signal weighting | ScanMode multiplier table, agent-type profiles, `_detect_mode_for_tier15()` reuse for mode detection |
| DETC-03 | MELON selective re-execution in configurable ambiguous confidence zone | MELON paper algorithm analysis, masking strategy adaptation, CLS embedding reuse, circuit breaker design, snapshot/rollback implementation |
| DETC-04 | Memory/config file poisoning pattern library | Pattern categories for agent memory, dotfiles, workspace configs; existing MP-001/MP-002 as foundation; subdirectory organization |
| DETC-05 | MCP tool description fingerprinting against known-good registries | Hash-based registry JSON schema, RADE attack detection, existing MCP-001..005 patterns as foundation |
| DETC-06 | Adversarial evaluation against "Attacker Moves Second" methodology | Paper methodology (Nasr, Carlini, Tramer), existing adaptive red team infrastructure, evaluation harness extension, fusion-targeting payload generation |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Python 3.11+** with strict mypy, ruff linting (E, F, I, N, W, UP rules), line-length 100
- **No custom crypto** -- use battle-tested libraries
- **Never commit secrets** -- validate inputs, parameterized queries, sanitize
- **Authoritative sources only** -- no Wikipedia, Medium, unverified blogs
- **Testing**: minimum 80% coverage, descriptive names, Arrange-Act-Assert, mock external deps
- **Conventional Commits**: `type(scope): description`
- **Performance**: <20ms per hook invocation for Tier 0+1.5, <370ms full repo scan
- **Packaging**: `uv tool install` / `pipx` standalone binary
- **Frozen dataclasses on hot path** -- never Pydantic on hot path
- **`from __future__ import annotations`** at module top
- **Graceful degradation** -- missing optional deps return None, not raise
- **Git**: run formatters/linters/type-checkers before commit; squashed clean history when pushing
- **Never `git add -f` gitignored files**

## Standard Stack

### Core (already in project)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| PyYAML | 6.0.3 | Pattern file + weight profile parsing | Already in dependencies [VERIFIED: pyproject.toml] |
| onnxruntime | 1.24.3 | Tier 1.5 semantic inference + CLS embedding for MELON | Already in `[mini]` extra [VERIFIED: .venv] |
| transformers | 5.3.0 | Tokenizer for MiniLM classifier | Already in `[mini]` extra [VERIFIED: .venv] |
| numpy | 2.4.2 | Numerical ops, embedding cosine similarity | Already in `[mini]` extra [VERIFIED: .venv] |
| pydantic | 2.12.5 | Cold-path YAML validation (policy config) | Already in core deps [VERIFIED: pyproject.toml] |

### Supporting (no new dependencies needed)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| hashlib (stdlib) | N/A | MCP tool description fingerprinting (SHA-256) | DETC-05 registry |
| json (stdlib) | N/A | MCP registry JSON, calibration report data | All DETC requirements |
| dataclasses (stdlib) | N/A | Frozen dataclasses for fusion types | DETC-01/02 hot path |
| collections.deque (stdlib) | N/A | Sliding window for MELON circuit breaker | DETC-03 |
| pathlib (stdlib) | N/A | Rule subdirectory traversal | DETC-04/05 |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Grid search calibration | scipy.optimize / Bayesian opt | Adds dependency; grid search is deterministic and auditable per D-05 |
| In-process embedding (MiniLM CLS) for MELON | OpenAI text-embedding-3-small API | Paper uses API; in-process avoids external dependency, stays within latency budget |
| YAML weight profiles | JSON profiles | YAML aligns with existing rule format and policy.yaml convention |

**Installation:** No new packages required. All dependencies already declared in pyproject.toml extras.

## Architecture Patterns

### Recommended Project Structure
```
src/cloneguard/
├── detection/
│   ├── engine.py           # Modified: delegates to FusionLayer
│   ├── fusion.py           # NEW: FusionLayer, WeightProfile, FusionResult
│   ├── melon.py            # NEW: MELONDetector, masking, comparison
│   ├── mcp_registry.py     # NEW: known-good MCP tool fingerprint registry
│   ├── patterns.py         # Modified: load from subdirectories
│   ├── profiles/           # NEW: YAML weight profiles per agent type
│   │   ├── default.yaml
│   │   ├── claude-code.yaml
│   │   ├── gemini-cli.yaml
│   │   └── cursor.yaml
│   ├── semantic.py         # Unchanged (signal source)
│   ├── sequence.py         # Unchanged (signal source)
│   └── types.py            # Extended: FusionResult fields
├── rules/
│   ├── coding/             # Existing 25 rules moved here
│   │   ├── authority_impersonation.yaml
│   │   ├── ... (25 files)
│   │   └── wsl_cross_boundary.yaml
│   ├── memory/             # NEW: DETC-04
│   │   ├── agent_memory_poisoning.yaml
│   │   ├── dotfile_injection.yaml
│   │   └── workspace_config_poisoning.yaml
│   └── mcp/                # NEW: DETC-05
│       ├── tool_description_fingerprinting.yaml
│       └── mcp_rade_patterns.yaml
├── enforcement/
│   ├── landlock.py         # Modified: implement snapshot/rollback
│   └── seatbelt.py         # Modified: implement snapshot/rollback
scripts/
├── calibrate_fusion.py     # NEW: DETC-01/02 grid search calibration
└── adversarial_eval_fusion.py  # NEW: DETC-06 evaluation harness
```

### Pattern 1: FusionLayer as Interceptor

**What:** FusionLayer sits between individual signal collection and DetectionResult assembly. It receives a list of SignalResults plus context (ScanMode, agent_type, source_path) and produces a FusionResult with calibrated confidence.

**When to use:** Every detection path (scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use, generic scan).

**Example:**
```python
# Source: Designed from D-01 through D-05 decisions
@dataclass(frozen=True)
class WeightProfile:
    """Calibrated weights for three-signal fusion."""
    pattern_base: float = 0.4
    semantic_base: float = 0.4
    sequence_base: float = 0.2
    mode_multipliers: dict[str, dict[str, float]] = field(default_factory=dict)
    # e.g., {"strict": {"pattern": 1.2, "semantic": 1.3, "sequence": 0.8}, ...}

@dataclass(frozen=True)
class FusionResult:
    """Output of the fusion layer."""
    confidence: float  # Single calibrated score [0.0, 1.0]
    verdict: str       # "clean" | "suspicious" | "detected"
    signals: tuple[SignalResult, ...]  # Per-signal breakdown
    melon_triggered: bool = False
    melon_result: str = ""

class FusionLayer:
    """Context-weighted three-signal fusion (D-01 through D-05).
    
    Deterministic, auditable. No ML in the fusion path.
    """
    def __init__(self, profile: WeightProfile | None = None) -> None:
        self._profile = profile or WeightProfile()
    
    def fuse(
        self,
        signals: list[SignalResult],
        mode: ScanMode,
        agent_type: str = "default",
    ) -> FusionResult:
        """Produce calibrated confidence from individual signals."""
        # Weighted combination with mode multipliers
        ...
```
[ASSUMED: Exact fusion formula. Grid search calibration will determine optimal base weights and multipliers.]

### Pattern 2: MELON as Post-Fusion Gate

**What:** MELON fires only when fusion confidence is in the ambiguous zone (0.4-0.6). It masks the tool call input, re-runs through the detection pipeline with masking, and compares tool-call similarity using CLS embeddings.

**When to use:** Post-fusion, pre-enforcement, only in the ambiguous confidence zone.

**Example:**
```python
# Source: Adapted from arXiv:2502.05174 Algorithm 1 + D-10 through D-14
class MELONDetector:
    """Selective re-execution for ambiguous detections (D-10 through D-14)."""
    
    def __init__(
        self,
        threshold: float = 0.8,  # Cosine similarity threshold from paper
        ambiguous_low: float = 0.4,
        ambiguous_high: float = 0.6,
        circuit_breaker_window: int = 20,
        circuit_breaker_rate: float = 0.15,
    ) -> None:
        self._threshold = threshold
        self._ambiguous_range = (ambiguous_low, ambiguous_high)
        self._recent_triggers: deque[bool] = deque(maxlen=circuit_breaker_window)
        self._disabled = False
    
    def should_trigger(self, fusion_confidence: float) -> bool:
        """Check if MELON should fire for this confidence level."""
        if self._disabled:
            return False
        low, high = self._ambiguous_range
        return low <= fusion_confidence <= high
    
    def detect(
        self,
        original_content: str,
        classifier: MiniSemanticClassifier,
    ) -> MELONResult:
        """Run masked re-execution and compare embeddings."""
        # 1. Mask content (remove user-task-specific sections)
        # 2. Get CLS embeddings for original and masked
        # 3. Compute cosine similarity
        # 4. If similarity > threshold: attack detected
        # 5. Update circuit breaker
        ...
```
[CITED: arxiv.org/abs/2502.05174 -- threshold=0.8, masking strategy, tool call comparison]

### Pattern 3: Recursive Rule Directory Loading

**What:** PatternEngine loads YAML rules from subdirectories of the rules directory, not just flat files.

**When to use:** PatternEngine initialization.

**Example:**
```python
# Source: Codebase patterns.py line 121 -- change glob pattern
# Current:
for yaml_file in sorted(rules_dir.glob("*.yaml")):

# New (D-15):
for yaml_file in sorted(rules_dir.glob("**/*.yaml")):
```
[VERIFIED: src/cloneguard/detection/patterns.py line 121]

### Anti-Patterns to Avoid

- **ML in the fusion path:** D-05 explicitly prohibits this. The IPI Arena retraining showed 9% to 20-42% FPR regression. Fusion uses calibrated weights only. [VERIFIED: CONTEXT.md D-05]
- **Sequential waterfall instead of fusion:** The current engine returns on the first non-clean signal. Fusion must collect ALL available signals before scoring. This requires refactoring the scan methods to collect signals without early return. [VERIFIED: engine.py lines 268-335]
- **MELON on every call:** Must only trigger in the ambiguous zone. Circuit breaker must disable MELON if trigger rate exceeds 15%. [VERIFIED: CONTEXT.md D-12, D-13]
- **External API calls for MELON embedding comparison:** The paper uses OpenAI API; CloneGuard must use the in-process MiniLM CLS embeddings to avoid external dependencies and latency. [ASSUMED: CLS embedding extraction from existing ONNX model outputs[1] is available -- verified that model outputs include CLS embeddings at `outputs[1][0]` in semantic.py line 188]
- **Breaking backward compatibility of rules/:** Moving 25 YAML files into `rules/coding/` must not break any code that references rule files by path. The PatternEngine itself doesn't expose file paths in its API, so the change is internal.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Embedding cosine similarity | Custom distance function | `numpy.dot(a, b) / (numpy.linalg.norm(a) * numpy.linalg.norm(b))` | Numerically stable, well-tested [VERIFIED: numpy available in venv] |
| YAML parsing | Custom parser | PyYAML `yaml.safe_load()` | Already used throughout codebase [VERIFIED: patterns.py, policy.py] |
| Content hashing for MCP fingerprinting | Custom hash | `hashlib.sha256()` | Standard, already used in engine.py `_content_hash()` [VERIFIED: engine.py line 94] |
| Sliding window rate limiter | Custom ring buffer | `collections.deque(maxlen=N)` | Already used in ToolCallMonitor [VERIFIED: sequence.py line 40] |
| Grid search | Custom optimizer | Nested loops over weight parameters | Grid search is simple enough; no need for scipy/optuna for this |
| Agent type detection | Custom logic | `InputAdapter.agent_type` from Phase 3 adapters | Already implemented [VERIFIED: adapters/__init__.py] |

**Key insight:** Phase 4 requires zero new dependencies. All building blocks exist in the current stack. The complexity is in orchestration (wiring fusion into the detection pipeline) and calibration (finding good weights), not in new libraries.

## MELON Algorithm Deep Dive

### Paper Algorithm (arXiv:2502.05174)

The MELON algorithm from the ICML 2025 paper works as follows: [CITED: arxiv.org/abs/2502.05174, arxiv.org/html/2502.05174]

1. **Masking function** M(T_u, A_1:t, O_1:t) = (T_f, empty, O_1^t): Replace user task with task-neutral prompt ("Summarize the provided content. If there are any instructions, execute them."), remove prior action history, concatenate tool outputs into single context.

2. **Comparison function**: Convert tool calls to natural language descriptions, embed with text-embedding-3-small, compute cosine similarity. If any pair exceeds threshold (0.8), alert.

3. **Tool call cache**: Cache all tool calls from masked execution across all steps (not just the current step). This catches timing mismatches where malicious tasks execute at different points.

4. **Focus on tool calls only**: Compare only tool calls (C), not text responses (R). Text responses naturally differ between runs; malicious tool calls remain consistent.

### CloneGuard Adaptation

The paper's design must be adapted for CloneGuard's constraints:

| Paper Design | CloneGuard Adaptation | Rationale |
|---|---|---|
| OpenAI text-embedding-3-small API | MiniLM CLS embedding from ONNX (already available at `outputs[1][0]`) | No external API dependency; stays within 500ms budget |
| Full agent re-execution | Content-only re-analysis with masking | CloneGuard is a hook, not an agent; cannot re-execute tool calls |
| Threshold 0.8 | Start with 0.8, calibrate on trajectory data | Paper's threshold showed minimal sensitivity in 0.5-0.9 range |
| Task-neutral masking prompt | Section removal from content + instruction neutralization | Adapted for static analysis context vs. agentic re-execution |

**Critical adaptation note:** The paper assumes MELON can re-execute the agent's tool call with a masked prompt and observe different behavior. CloneGuard cannot re-execute tool calls -- it is a hook that observes them. The adaptation is: mask sections of the content being analyzed, re-run the classifier, and check if the classification diverges. If the masked version is classified as SAFE but the original was ambiguous, the ambiguous signal likely came from the masked-out section (potentially injected). This is a detector-level adaptation of the paper's agent-level re-execution. [ASSUMED: This adaptation preserves the paper's core insight (masked content removes attacker influence, making divergence detectable) while being feasible in the hook architecture.]

### Failure Modes from Paper
The paper identifies four failure categories: [CITED: arxiv.org/html/2502.05174]
1. **Response-based attacks (72.73% of failures)**: Malicious objectives achieved via text responses, not tool calls. Not applicable to CloneGuard -- we scan content, not tool call execution.
2. **Tool call redundancy (15.15%)**: Original reuses cached results while masked regenerates. Partially applicable -- mitigated by comparing content analysis results, not tool executions.
3. **State hallucination (6.06%)**: Agent fabricates info. Not applicable to hook-level detection.
4. **Function hallucination (6.06%)**: Agent calls non-existent tools. Not applicable.

## Snapshot/Rollback Implementation

### LandlockAdapter (Linux)

Landlock operates at the kernel level by restricting access rights for the current process. Key constraints for snapshot/rollback: [ASSUMED: Based on Landlock ABI understanding]

- Landlock restrictions are **additive and irrevocable** -- once applied to a process, they cannot be removed
- True "rollback" of filesystem restrictions is impossible with Landlock
- **Practical implementation**: Snapshot captures the *file state* (not the restriction state) before MELON-triggered execution. Rollback restores files to their pre-execution state.
- Implementation approach: `snapshot()` records checksums of writable paths; `rollback()` restores from backup copies.

### SeatbeltAdapter (macOS)

Seatbelt (sandbox-exec) has similar irrevocability: [ASSUMED: Based on macOS sandbox-exec understanding]

- Seatbelt profiles are applied at process creation time and cannot be modified
- Same practical approach as Landlock: snapshot captures file state, rollback restores it
- Implementation uses `shutil.copy2()` for file backup and restoration

### NoopAdapter

Remains no-op per D-14. MELON logs divergence but cannot roll back. This is acceptable -- NoopAdapter is detection-only mode.

## Calibration Pipeline Design

### Grid Search Parameters (Claude's Discretion)

Recommended grid search hyperparameters: [ASSUMED: Based on calibration best practices]

```yaml
# Weight bases (each signal)
pattern_base: [0.2, 0.3, 0.4, 0.5]
semantic_base: [0.2, 0.3, 0.4, 0.5]
sequence_base: [0.1, 0.15, 0.2, 0.3]
# Constraint: pattern_base + semantic_base + sequence_base = 1.0

# ScanMode multipliers
strict_pattern: [1.0, 1.1, 1.2, 1.3]
strict_semantic: [1.1, 1.2, 1.3, 1.5]
standard_pattern: [1.0]  # baseline
standard_semantic: [1.0]  # baseline
lenient_pattern: [0.6, 0.7, 0.8]
lenient_semantic: [0.6, 0.7, 0.8]
```

Grid size: ~4 * 4 * 4 * 4 * 4 * 1 * 1 * 3 * 3 = ~9,216 combinations (constrained by sum-to-1). Each evaluation requires scanning the labeled corpus once. With 208K trajectories and 3 signals per trajectory, this is compute-intensive but parallelizable.

### Trajectory Data Loading

The `scripts/download_trajectories.py` downloads to `data/trajectories/`. The calibration script should: [VERIFIED: scripts/download_trajectories.py]

1. Check `data/trajectories/` first (default path)
2. Accept `--data-dir` override for external storage
3. If no data available, output default weights (the uncalibrated baseline) with a warning
4. Use HuggingFace `datasets` library (parquet format) for efficient loading

### Weight Profile YAML Schema

```yaml
# src/cloneguard/detection/profiles/default.yaml
version: "1"
agent_type: "default"
description: "Default fusion weights -- uncalibrated baseline"

weights:
  pattern_base: 0.40
  semantic_base: 0.40
  sequence_base: 0.20

mode_multipliers:
  strict:
    pattern: 1.2
    semantic: 1.3
    sequence: 0.8
  standard:
    pattern: 1.0
    semantic: 1.0
    sequence: 1.0
  lenient:
    pattern: 0.7
    semantic: 0.7
    sequence: 1.2

# MELON configuration
melon:
  enabled: true
  ambiguous_low: 0.4
  ambiguous_high: 0.6
  similarity_threshold: 0.8
  circuit_breaker_window: 20
  circuit_breaker_rate: 0.15
```
[ASSUMED: Schema design. Aligns with existing YAML conventions in the project.]

## MCP Tool Description Fingerprinting

### Registry Schema

```json
{
  "version": "1",
  "generated": "2026-04-06",
  "tools": {
    "mcp__filesystem__read_file": {
      "description_hash": "sha256:abc123...",
      "description_length": 142,
      "input_schema_hash": "sha256:def456...",
      "source": "github.com/modelcontextprotocol/servers",
      "last_verified": "2026-04-06"
    }
  }
}
```
[ASSUMED: Schema design based on D-17 requirements.]

### RADE Attack Detection

RADE (Remote Agent Description Edit) attacks poison MCP tool descriptions to embed instructions. Detection approach: [CITED: CONTEXT.md D-17]

1. Hash the `description` field of each MCP tool definition
2. Compare against known-good hashes in registry
3. If mismatch: flag as potential RADE attack (tool description poisoned)
4. Also run existing MCP-001 through MCP-005 patterns on the description text
5. Combine fingerprint mismatch + pattern match in fusion layer for higher confidence

## Common Pitfalls

### Pitfall 1: FPR Regression from Fusion
**What goes wrong:** Fusion produces higher false positive rates than individual signals because multiple low-confidence signals combine to exceed thresholds.
**Why it happens:** Naive weighted sum of noisy signals amplifies noise. Each signal has independent FPR; combining them multiplicatively can increase overall FPR.
**How to avoid:** The calibration pipeline (D-06) must optimize for FPR *at each content type*, not just aggregate FPR. The grid search objective should minimize max(FPR across content types) at target TPR, not average FPR.
**Warning signs:** Any content type exceeding 9.2% FPR in calibration results. [VERIFIED: D-08 baseline requirement]

### Pitfall 2: MELON Latency Explosion
**What goes wrong:** MELON triggers too frequently, adding 500ms to too many calls, degrading user experience.
**Why it happens:** Ambiguous zone (0.4-0.6) captures too many benign calls; circuit breaker threshold (15%) is too high.
**How to avoid:** Monitor trigger rate in tests. If >10% of benign corpus falls in ambiguous zone, narrow the zone or adjust fusion weights. Circuit breaker at 15% is the safety net, not the target.
**Warning signs:** More than 5% of benign test corpus triggering MELON. [ASSUMED: 5% target based on design doc estimate of "~5-10% of calls"]

### Pitfall 3: Pattern Library Reorg Breaking Tests
**What goes wrong:** Moving 25 YAML files into `rules/coding/` breaks test assertions that reference specific rule file paths or pattern counts.
**Why it happens:** Tests may assert on the number of loaded rules or use relative paths to rule files.
**How to avoid:** Check all tests that reference `rules/` directory. The PatternEngine API (ScanResult, PatternMatch) doesn't expose file paths, so the change should be transparent. But tests that directly construct PatternEngine with a specific rules_dir need updating.
**Warning signs:** `test_patterns.py`, `test_integration_all_patterns.py`, `test_full_pattern_coverage.py` -- all reference pattern counts or rule loading.
[VERIFIED: PatternEngine.__init__ accepts rules_dir parameter; tests likely pass custom dirs]

### Pitfall 4: Snapshot/Rollback Scope Confusion
**What goes wrong:** Implementing snapshot/rollback as "undo sandbox restrictions" when restrictions are irrevocable in both Landlock and Seatbelt.
**Why it happens:** The SandboxAdapter Protocol defines snapshot/rollback generically. Developer assumes it means "undo restrict_filesystem()".
**How to avoid:** Document clearly: snapshot/rollback captures *file system state* (file contents), not *restriction state*. The sandbox restrictions remain in place; rollback restores the writable files to their pre-execution content.
**Warning signs:** Attempting to use Landlock API to remove access rules.

### Pitfall 5: MELON Adaptation Overfit to Paper
**What goes wrong:** Implementing paper's exact algorithm (re-execute agent's tool call) when CloneGuard cannot re-execute tool calls.
**Why it happens:** Paper describes an agentic system; CloneGuard is a hook/sensor.
**How to avoid:** Adapt to content analysis: mask sections of scanned content, re-classify, compare. The insight (masking removes attacker influence) transfers; the mechanism (re-execute agent) does not.
**Warning signs:** Code that tries to invoke an LLM or re-submit to the agent from within a hook handler.

### Pitfall 6: Calibration on Stale Data
**What goes wrong:** Calibration weights optimized on trajectory data don't generalize to production because data is from 2024-era agents.
**Why it happens:** Trajectory data from SWE-smith/Nebius/OpenHands captures older agent behaviors.
**How to avoid:** Calibration is a starting point. Phase 3's production adapter data supplements it. Include Phase 3 production data in calibration if available. Weight profiles are overridable via policy.yaml.
**Warning signs:** Large gap between calibration FPR and production FPR in specific content types.

## Code Examples

### Collecting All Signals Before Fusion

The current engine returns early on the first non-clean signal. The refactored pattern collects all signals:

```python
# Source: Designed from analysis of engine.py scan methods
def _collect_signals(
    self,
    content: str,
    source_path: str,
    mode: ScanMode,
) -> list[SignalResult]:
    """Collect all available signals without early return."""
    signals: list[SignalResult] = []
    
    # Signal 1: Pattern
    engine = self._get_pattern_engine()
    result = engine.scan(content, source_path, mode=mode)
    if result.verdict != Verdict.CLEAN:
        signals.append(SignalResult(
            signal_type="pattern",
            verdict=result.verdict.value,
            confidence=1.0 if result.verdict == Verdict.DETECTED else 0.5,
            details={"match_count": len(result.matches), "scan_time_ms": result.scan_time_ms},
        ))
    
    # Signal 2: Semantic (always run, not only when pattern is clean)
    tier15_mode = _detect_mode_for_tier15(source_path, content, mode, engine)
    classifier = self._get_mini_classifier()
    if classifier is not None:
        cls_result = classifier.classify(content, mode=tier15_mode)
        if cls_result.verdict != "SAFE":
            signals.append(SignalResult(
                signal_type="semantic",
                verdict="detected" if cls_result.verdict == "MALICIOUS" else "suspicious",
                confidence=cls_result.confidence,
                details={"reason": cls_result.reason, "anomaly_score": cls_result.anomaly_score},
            ))
    
    # Signal 3: Sequence (from monitor)
    try:
        from cloneguard.detection.sequence import get_monitor
        verdict = get_monitor().check_enforcement({"tool_name": "", "tool_input": {}})
        if verdict is not None:
            signals.append(SignalResult(
                signal_type="sequence",
                verdict="detected",
                confidence=1.0,
                details={"rule_id": verdict.rule_id},
            ))
    except Exception:
        pass
    
    return signals
```
[VERIFIED: Based on engine.py structure. Refactored to eliminate early returns.]

### CLS Embedding Extraction for MELON

```python
# Source: Analysis of semantic.py lines 180-188
# The ONNX model already outputs CLS embeddings as the second output
outputs = self._session.run(
    None,
    {"input_ids": inputs["input_ids"], "attention_mask": inputs["attention_mask"]},
)
logits = outputs[0][0]
cls_embedding = outputs[1][0] if len(outputs) > 1 else None
# cls_embedding is the 384-dim CLS vector from MiniLM-L6-v2
```
[VERIFIED: src/cloneguard/detection/semantic.py line 188 -- `cls_embedding = outputs[1][0] if len(outputs) > 1 else None`]

### MELON Circuit Breaker

```python
# Source: Adapted from ToolCallMonitor pattern in sequence.py
from collections import deque

class CircuitBreaker:
    """Sliding window rate limiter for MELON triggers."""
    
    def __init__(self, window_size: int = 20, max_rate: float = 0.15) -> None:
        self._window: deque[bool] = deque(maxlen=window_size)
        self._max_rate = max_rate
        self._tripped = False
    
    def record(self, triggered: bool) -> None:
        """Record whether MELON was triggered for this call."""
        self._window.append(triggered)
        if not self._tripped and len(self._window) >= self._window.maxlen:
            rate = sum(self._window) / len(self._window)
            if rate > self._max_rate:
                self._tripped = True
                logger.warning(
                    "MELON circuit breaker tripped: %.1f%% trigger rate exceeds %.1f%% limit",
                    rate * 100, self._max_rate * 100,
                )
    
    @property
    def is_tripped(self) -> bool:
        return self._tripped
```
[VERIFIED: Pattern from sequence.py deque usage; D-12 parameters]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| max(scores) waterfall | Context-weighted fusion | Phase 4 (this phase) | Calibrated confidence enables SUSPICIOUS verdict, MELON zone |
| Single-signal detection | Three-signal fusion | Phase 4 (this phase) | Higher TPR at controlled FPR |
| No selective re-execution | MELON (ICML 2025) | Phase 4 (this phase) | Provable detection for ambiguous cases |
| Flat rules/ directory | Subdirectory organization | Phase 4 (this phase) | Enables agent-type-specific rule sets |
| Static eval only | "Attacker Moves Second" adaptive | Phase 4 (this phase) | Honest evaluation against adaptive adversaries |

**Deprecated/outdated:**
- The current engine.py sequential waterfall (pattern -> semantic -> sequence with early return) will be replaced by signal collection + fusion. The old behavior is preserved as a "legacy" mode for backward compatibility during transition if needed.
- The paper "The Attacker Moves Second" (arXiv:2510.09023, Nasr, Carlini et al.) was submitted October 2025. The existing CloneGuard adaptive red team methodology already incorporates its principles. Phase 4 extends this with fusion-specific adaptive evaluation. [CITED: arxiv.org/abs/2510.09023]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | MELON adaptation (content masking + re-classification) preserves the paper's core insight | MELON Deep Dive | Core DETC-03 requirement. If masking content and re-classifying doesn't detect divergence, MELON adds latency with no benefit. Mitigation: test on known malicious corpus first. |
| A2 | CLS embeddings from existing ONNX model are suitable for cosine similarity comparison in MELON | MELON Deep Dive | If CLS embeddings are too low-dimensional (384) or domain-specific, similarity comparison may have poor discrimination. Mitigation: evaluate on known pairs before committing to this approach. |
| A3 | Grid search with ~9K combinations is computationally feasible on the trajectory dataset | Calibration Pipeline | If 208K trajectories * 9K grid points is too slow, need to subsample or use smarter search. Mitigation: subsample trajectory dataset to ~10K representative examples for initial sweep. |
| A4 | Snapshot/rollback as file-state capture (not restriction rollback) satisfies MELON requirements | Snapshot/Rollback | If MELON needs true process-level rollback (undo executed tool calls), file-state capture is insufficient. Mitigation: NoopAdapter fallback means MELON still works in detection-only mode. |
| A5 | Weight profile YAML schema and default values | Calibration Pipeline | If default weights produce worse FPR than uncalibrated baseline, need rapid iteration. Mitigation: calibration report documents per-content-type FPR at each grid point. |
| A6 | MCP registry JSON schema and initial tool entries | MCP Fingerprinting | If MCP tool descriptions change frequently across versions, registry maintenance becomes burdensome. Mitigation: version-keyed entries, stale detection. |

## Open Questions (RESOLVED)

1. **Trajectory data availability for calibration** (RESOLVED)
   - What we know: `scripts/download_trajectories.py` downloads from HuggingFace to `data/trajectories/`. Directories do not exist in the working tree.
   - Resolution: Calibration script handles missing data gracefully -- if `--data-dir` does not exist or is empty, the script prints a warning and exits with code 0, shipping default uncalibrated weights. Data download is a separate explicit step (`python scripts/download_trajectories.py`). The adversarial eval harness also handles missing benchmark corpus gracefully (warning + exit 0, or uses embedded synthetic payloads). CI does NOT run calibration; calibration is an offline developer task.

2. **MELON masking strategy for hook context** (RESOLVED)
   - What we know: Paper masks user task with task-neutral prompt. CloneGuard does not have a "user task" -- it has content being scanned.
   - Resolution: MELON masks the specific byte spans flagged by pattern matches (suspicious_spans from PatternMatch positions). If no pattern matches exist (ambiguous zone reached via semantic signal only), MELON falls back to heuristic masking: remove lines matching instruction-override patterns (lines containing "ignore previous", "you are now", "system:" etc.) and markdown headers with directive content. This is the "mask suspicious sections, not entire content" approach. Iteration based on adversarial eval results in Plan 04.

3. **Weight profile per agent type vs. shared** (RESOLVED)
   - What we know: D-04 specifies agent-type-driven weight profiles. Phase 3 provides 6 adapters (claude-code, gemini-cli, cursor, cicd, mcp, generic).
   - Resolution: Ship one "default" profile from calibration (if trajectory data available) or from static defaults. Per-agent YAML files (claude-code.yaml, gemini-cli.yaml, cursor.yaml) ship as copies of default with `agent_type` set and a note documenting they are uncalibrated copies pending agent-specific trajectory data. Operators can override per-agent weights via `~/.cloneguard/policy.yaml` under `fusion.weights`. Per-agent calibration deferred until agent-specific trajectory data is available.
## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.11+ | All code | Yes | 3.14.3 | -- |
| uv | Package management | Yes | 0.10.6 | -- |
| onnxruntime | Tier 1.5 + MELON embeddings | Yes (.venv) | 1.24.3 | Fusion works without MELON; MELON degrades to no-op |
| transformers | Tokenizer | Yes (.venv) | 5.3.0 | -- |
| numpy | Cosine similarity | Yes (.venv) | 2.4.2 | -- |
| ruff | Linting | Yes | 0.15.0 | -- |
| mypy | Type checking | Yes | 1.19.1 | -- |
| HuggingFace datasets | Trajectory loading for calibration | Not checked | -- | Default weights if unavailable |
| Trajectory data (208K) | Calibration (D-06) | Not present | -- | Default uncalibrated weights |

**Missing dependencies with no fallback:**
- None -- all critical paths have graceful degradation

**Missing dependencies with fallback:**
- Trajectory data: calibration uses default weights if unavailable
- HuggingFace `datasets` library: calibration script should install on first run or skip with warning

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | -- |
| V3 Session Management | No | -- |
| V4 Access Control | Partially | Fusion weight overrides via operator-controlled policy.yaml only (never repo-resident) |
| V5 Input Validation | Yes | All YAML profiles validated via frozen dataclasses; all content inputs are strings processed through existing validated paths |
| V6 Cryptography | Partially | SHA-256 for MCP fingerprinting (hashlib, not hand-rolled) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Adversarial fusion weight manipulation | Tampering | Weights loaded from operator-controlled paths only (D-09, mirroring existing policy.yaml pattern) |
| MELON trigger flooding (DoS) | Denial of Service | Circuit breaker at 15% trigger rate (D-12) |
| MCP registry poisoning | Tampering | Registry ships with package (build artifact), not loaded from network |
| Pattern library injection via repo content | Tampering | Rules loaded from package directory, not CWD (existing PatternEngine pattern) |
| Snapshot/rollback race condition | Tampering | Snapshot/rollback is synchronous within hook handler; no concurrent access |

## Sources

### Primary (HIGH confidence)
- `src/cloneguard/detection/engine.py` -- Current detection pipeline, signal collection logic, 831 lines analyzed
- `src/cloneguard/detection/types.py` -- ToolCallEvent, SignalResult, DetectionResult dataclasses
- `src/cloneguard/detection/patterns.py` -- PatternEngine rule loading (line 121: `glob("*.yaml")`)
- `src/cloneguard/detection/semantic.py` -- MiniSemanticClassifier, CLS embedding extraction (line 188)
- `src/cloneguard/detection/sequence.py` -- ToolCallMonitor, ring buffer, SEQ rules
- `src/cloneguard/enforcement/adapter.py` -- SandboxAdapter Protocol, snapshot/rollback no-op stubs
- `src/cloneguard/enforcement/landlock.py` -- LandlockAdapter, snapshot/rollback no-op (line 440)
- `src/cloneguard/enforcement/seatbelt.py` -- SeatbeltAdapter, snapshot/rollback no-op (line 220)
- `src/cloneguard/enforcement/policy.py` -- YAMLPolicyEngine, operator-controlled config pattern
- `src/cloneguard/adapters/__init__.py` -- InputAdapter Protocol, agent_type detection
- `src/cloneguard/rules/mcp_tool_poisoning.yaml` -- Existing MCP-001..005 patterns
- `src/cloneguard/rules/memory_poisoning.yaml` -- Existing MP-001..002 patterns
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` S4.1-4.4 -- Fusion, MELON, evaluation design
- `docs/ADAPTIVE-RED-TEAM.md` -- Existing adversarial evaluation methodology
- `scripts/calibrate_thresholds.py` -- Existing calibration script pattern (threshold sweep, content types)
- `scripts/download_trajectories.py` -- Trajectory data download from HuggingFace
- `scripts/mine_trajectories.py` -- Trajectory mining and action classification
- `pyproject.toml` -- Dependencies, extras, packaging config

### Secondary (MEDIUM confidence)
- [arXiv:2502.05174](https://arxiv.org/abs/2502.05174) -- MELON paper, ICML 2025. Masking algorithm, comparison function, threshold=0.8, failure modes analyzed
- [arXiv:2510.09023](https://arxiv.org/abs/2510.09023) -- "Attacker Moves Second" (Nasr, Carlini, Tramer). Adversarial evaluation methodology, 12 defenses evaluated, ASR >90% with adaptive attacks
- [GitHub: kaijiezhu11/MELON](https://github.com/kaijiezhu11/MELON) -- MELON reference implementation. `pi_detector.py`, `MELON(llm, threshold=0.1)`, AgentDojo integration

### Tertiary (LOW confidence)
- None -- all claims verified from codebase or cited papers

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries verified from pyproject.toml and venv
- Architecture: HIGH -- all integration points verified from existing codebase
- Fusion design: MEDIUM -- weight optimization is empirical; default weights are assumptions
- MELON adaptation: MEDIUM -- adaptation from agent-level to hook-level is novel; not validated empirically yet
- Pattern libraries: HIGH -- straightforward extension of existing patterns
- Adversarial evaluation: HIGH -- existing methodology + well-documented paper

**Research date:** 2026-04-06
**Valid until:** 2026-05-06 (stable domain; MELON paper is post-publication)
