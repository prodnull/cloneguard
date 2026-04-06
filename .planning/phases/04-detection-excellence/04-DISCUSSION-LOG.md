# Phase 4: Detection Excellence - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-04-06
**Phase:** 04-detection-excellence
**Mode:** auto
**Areas discussed:** Fusion scoring strategy, Calibration pipeline, MELON re-execution design, Cross-agent pattern libraries, Adversarial evaluation framework

---

## Fusion Scoring Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Context-weighted rule table | ScanMode-aware multipliers, deterministic, auditable | ✓ |
| Trained ML model | Logistic regression or small NN on signal features | |
| Simple weighted average | Fixed weights, no context sensitivity | |

**User's choice:** [auto] Context-weighted rule table with ScanMode-aware multipliers (recommended default)
**Notes:** Matches v2 design doc section 4.1. Avoids ML training overhead and FPR regression risk (IPI Arena retraining showed 9% to 20-42% FPR).

| Option | Description | Selected |
|--------|-------------|----------|
| New FusionLayer module | Between signal scans and DetectionResult construction | ✓ |
| Inline in DetectionEngine | Modify existing scan methods directly | |

**User's choice:** [auto] New FusionLayer module (recommended default)
**Notes:** Keeps engine scan methods stable, fusion is a composable layer.

| Option | Description | Selected |
|--------|-------------|----------|
| Single float + breakdown | Calibrated confidence plus per-signal SignalResult list | ✓ |
| Single float only | Simpler but loses debuggability | |
| Structured verdict object | New type with confidence per signal | |

**User's choice:** [auto] Both single float and per-signal breakdown (recommended default)

| Option | Description | Selected |
|--------|-------------|----------|
| Agent-type weight profiles | InputAdapter provides agent_type, selects weight set | ✓ |
| Single universal profile | Same weights for all agent types | |

**User's choice:** [auto] Per-agent-type weight profiles (recommended default)

---

## Calibration Pipeline

| Option | Description | Selected |
|--------|-------------|----------|
| Offline grid search script | Runs signals against trajectory data, optimizes weights | ✓ |
| Online calibration | Runtime weight adjustment based on session data | |
| Manual tuning | Expert-set weights without automated optimization | |

**User's choice:** [auto] Offline calibration script (recommended default)
**Notes:** Simple, reproducible, no ML framework dependency. Produces versioned weight artifacts.

| Option | Description | Selected |
|--------|-------------|----------|
| Build-time YAML artifact | Shipped in package, operator-overridable | ✓ |
| Runtime config only | Loaded from policy.yaml each session | |

**User's choice:** [auto] Build-time artifact with operator override (recommended default)

| Option | Description | Selected |
|--------|-------------|----------|
| Per content-type FPR tracking | CI configs, security docs, test fixtures, MCP, source | ✓ |
| Aggregate FPR only | Single FPR number across all content | |

**User's choice:** [auto] Per content-type tracking (recommended default)
**Notes:** Matches success criteria #2: each category below 9.2% baseline.

---

## MELON Re-Execution Design

| Option | Description | Selected |
|--------|-------------|----------|
| Masked re-execution (ICML 2025) | Remove sections, re-submit, compare divergence | ✓ |
| Full re-execution | Re-run entire tool call without masking | |
| Output-only comparison | Compare tool output across sessions | |

**User's choice:** [auto] Masked re-execution per ICML paper (recommended default)

| Option | Description | Selected |
|--------|-------------|----------|
| Post-fusion, pre-enforcement | Only in ambiguous zone (0.4-0.6) | ✓ |
| Post-detection, pre-fusion | Before fusion scoring | |
| Separate pipeline | Independent from main detection | |

**User's choice:** [auto] Post-fusion, pre-enforcement (recommended default)

| Option | Description | Selected |
|--------|-------------|----------|
| Sliding window rate limiter | >15% trigger rate disables for session | ✓ |
| Fixed per-session budget | N total MELON calls allowed | |
| No circuit breaker | Always trigger in ambiguous zone | |

**User's choice:** [auto] Sliding window rate limiter (recommended default)

---

## Cross-Agent Pattern Libraries

| Option | Description | Selected |
|--------|-------------|----------|
| Subdirectories under rules/ | rules/coding/, rules/memory/, rules/mcp/ | ✓ |
| Flat directory with prefixes | memory_*.yaml, mcp_*.yaml in rules/ | |
| Separate package | cloneguard.rules.memory package | |

**User's choice:** [auto] Subdirectories (recommended default)
**Notes:** PatternEngine already loads from directory; extend to subdirectories.

| Option | Description | Selected |
|--------|-------------|----------|
| Hash-based fingerprinting | Known-good registry with hash comparison | ✓ |
| Semantic similarity | Embedding comparison of tool descriptions | |
| Keyword blocklist | Flag specific terms in descriptions | |

**User's choice:** [auto] Hash-based fingerprinting (recommended default)
**Notes:** Deterministic, fast, no ML dependency in the fingerprinting path.

---

## Adversarial Evaluation Framework

| Option | Description | Selected |
|--------|-------------|----------|
| Attacker Moves Second methodology | Full defense knowledge, adaptive adversary | ✓ |
| Standard benchmark suite | Fixed datasets only | |
| Red team exercise | Manual adversarial testing | |

**User's choice:** [auto] Attacker Moves Second (recommended default)
**Notes:** Matches design doc section 4.4 and existing methodology in ADAPTIVE-RED-TEAM.md.

| Option | Description | Selected |
|--------|-------------|----------|
| Structured markdown with honest rates | Per-class bypass, FPR regression, delta analysis | ✓ |
| Summary scorecard | Single detection rate number | |
| SARIF-based report | Machine-readable eval results | |

**User's choice:** [auto] Structured markdown with honest rates (recommended default)
**Notes:** Consistent with existing disclosure approach (16.7% bypass rate).

---

## Claude's Discretion

- Weight grid search hyperparameters
- Circuit breaker internals
- MELON masking strategy details
- MCP registry JSON schema
- Calibration report formatting
- Test organization

## Deferred Ideas

- OPA/Cedar policy backends for fusion -- Phase 5
- Browser/autonomous/financial/CI-CD agent pattern libraries -- Phase 5
- Adaptive constraint generation -- advanced, beyond Phase 4
- User-provided ONNX model support -- v2 XDET-04
