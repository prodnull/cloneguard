# CloneGuard

## What This Is

Pre-execution defense layer that raises the cost of prompt injection attacks against AI coding agents (Claude Code, GitHub Copilot, Cursor, Gemini CLI, Codex CLI). Scans repository files, tool output, and agent configurations before agents process them. Multi-tier detection: 197 regex patterns across 25 categories (Tier 0), adversarially hardened ONNX semantic classifier with per-ScanMode context-aware thresholds (Tier 1.5, v4 FreeLB+PWWS), Mahalanobis anomaly scoring, CaMeL-lite behavioral monitoring of tool call sequences, and Ollama LLM fallback (Tier 2).

## Core Value

Make prompt injection attacks against AI coding agents expensive enough that attackers move on to easier targets.

## Requirements

### Validated

- v0.2.3: 193 regex patterns across 24 categories (Tier 0)
- v0.2.3: 4-layer hook defense (L0 wrapper, L1 InstructionsLoaded, L2 PostToolUse, L3 PreToolUse)
- v0.2.3: SHA-256 trust cache, content-hash allowlist
- v0.2.3: MCP Gateway plugin
- v0.2.3: Multi-agent hook support (Claude Code, Gemini CLI, Cursor, Windsurf, VS Code Copilot)
- v0.2.3: Mode-restricted patterns (strict/standard/lenient)
- v0.2.3: Ollama qwen2.5:7b fallback (Tier 2)
- ✓ Transferability gate — empirically validated ensemble approach (58.0% transfer, CI 47.5%-67.7%) — v0.3
- ✓ PWWS adversarial augmentation + FreeLB AT — ASR reduced from 65.7% to 9.7% — v0.3
- ✓ Mahalanobis anomaly detector — integrated, 2.7% detection (marginal orthogonal signal) — v0.3
- ✓ Hardened pipeline benchmark — recall 90.3%, latency p95 16.61ms — v0.3
- ✓ Adaptive attacks measured — 20.3% ASR ceiling (CI 14.6%-27.5%) — v0.3
- ✓ Correlated failure analysis — 18/185 structural both-miss samples identified — v0.3
- ✓ Honest "raises attacker cost" framing enforced via automated audit — v0.3
- ✓ v4 ONNX model (dual-output logits + cls_embedding, 6,472-sample dataset) — v0.3
- ✓ Authorization paradox confirmed: +12.7pp Tier 1.5 FPR from auth preambles (Campbell et al. 2026 cited) — v0.4
- ✓ Strict-only pattern audit against defensive security corpus (CI-004, CI-006, SC-001, MCP-005) — v0.4
- ✓ Structural FPR limits documented with empirical evidence — v0.4
- ✓ Per-ScanMode context-aware thresholds (STRICT/STANDARD/LENIENT) threaded end-to-end — v0.4
- ✓ Workflow FPR reduced from 30.2% to 18.9% (CI-001 restricted to strict, agent_instructions 18.4%) — v0.4
- ✓ 197 patterns across 25 categories including Log-To-Leak exfiltration (LTL-001–LTL-004) — v0.4
- ✓ CaMeL-lite behavioral monitoring: ToolCallMonitor with SEQ-001–SEQ-004, JSONL logging, <0.5ms overhead — v0.4

### Active

(None — next milestone requirements TBD via `/gsd:new-milestone`)

### Out of Scope

- Full multilingual coverage — deferred to GitHub issue #5
- Randomized smoothing — incompatible with 20ms latency budget (100-5000x multiplier)
- IBP certified training — 3-8% clean accuracy cost, MiniLM attention bounds too loose
- Defensive distillation — broken for text (Carlini & Wagner 2016)
- DeBERTa ensemble — gate failed: structural attacks transfer at 88-100% regardless of architecture
- Retraining MiniLM-L6-v2 base model
- Tier 2 (Ollama) changes
- Subsuming mcp-guard as sub-project

## Context

- 1,261 tests passing, CI green
- v4 adversarially hardened MiniLM ONNX model (FreeLB + 2 rounds PWWS augmentation)
- Dataset: v4, 6,472 samples (v3 base + 132 PWWS adversarial augmentation), published on HuggingFace (gated)
- 197 regex patterns across 25 categories (Tier 0), including Log-To-Leak exfiltration
- Per-ScanMode context-aware thresholds: STRICT=(0.5,0.8), STANDARD=(0.65,0.88), LENIENT=(0.75,0.92)
- Workflow combined FPR (STANDARD): 18.9%, agent_instructions FPR: 18.4%
- Combined pipeline: recall 90.3%, false block rate 3.8%, latency p95 16.61ms
- CaMeL-lite ToolCallMonitor: SEQ-001–SEQ-004 rules, JSONL logging, <0.5ms overhead
- Adaptive ASR ceiling: 20.3% (PWWS against hardened model)
- Both-miss structural limit: 18/185 samples (fragmentation 55%, implicit_instruction 25%)
- White-box attack surface remains: ONNX model is public, architecture documented
- Tech stack: Python, ONNX Runtime, transformers tokenizer, scikit-learn (Mahalanobis)
- ~25,192 LOC Python (src + tests + scripts)

## Constraints

- **ONNX-only inference**: No PyTorch at runtime. Classifier must export to ONNX for CPUExecutionProvider.
- **Dependency budget**: Minimize new dependencies. onnxruntime + transformers tokenizer already present.
- **Latency**: Combined pipeline must stay under ~25ms/sample on Apple M-series CPU.
- **Clean accuracy floor**: Any model changes must not drop 5-fold CV below 94.5%.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Transferability experiment as gate | Don't trust theory — validate empirically before committing | ✓ Good — gate failed at 58%, saved months of wasted ensemble work |
| Ensemble over perturbation detection | Architecturally diverse models defeat transfer attacks | ⚠️ Invalidated — structural attacks transfer at 88-100% regardless |
| Adversarial hardening over second classifier | AT + Mahalanobis: higher ROI, lower complexity, +1-5ms vs +40-60ms | ✓ Good — ASR 9.7%, latency p95 16.61ms |
| Literature projections as targets, not guarantees | ASR ≤35% from A2T extrapolation — must validate experimentally | ✓ Good — exceeded target (9.7% vs ≤35%) |
| Mahalanobis on single-layer CLS | Literature projected 60% detection; single-layer CLS is cheaper | ⚠️ Revisit — 2.7% detection, CLS distributions overlap |
| Dual-output ONNX (logits + cls_embedding) | Enable downstream anomaly detection without separate inference | ✓ Good — clean architecture, negligible latency cost |
| dynamo=False for ONNX export | PyTorch 2.9 dynamo fails on LayerNorm dynamic axes | — Workaround, monitor future PyTorch releases |
| Publish negative results honestly | Mahalanobis miss, adaptive ceiling, both-miss — all disclosed | ✓ Good — credibility over marketing |

| Campbell et al. FPR investigation before pattern expansion | Embedding-space structural limits are information-theoretic — investigate before tuning | ✓ Good — confirmed +12.7pp auth paradox, informed per-ScanMode thresholds |
| Per-ScanMode context-aware thresholds | Single global threshold can't serve defensive security (STRICT) and CI/workflows (LENIENT) | ✓ Good — workflow FPR 30.2%→18.9%, agent_instructions 33%→18.4% |
| CI-001 restricted to strict mode | 23.9% workflow FPR floor from CI-001 in STANDARD mode — CI-002 covers run-context detection | ✓ Good — eliminated structural Tier 0 floor |
| CaMeL-lite log-only (not blocking) | FPR risk for sequence rules too high for blocking enforcement at v0.4 | ✓ Good — <0.5ms overhead, no false blocks |
| Cross-phase FPR collaboration | Workflow FPR target required Phase 5 (thresholds) + Phase 6 (CI-001 fix) | ✓ Good — honest negative result documented |

---
*Last updated: 2026-03-12 after v0.4 milestone*
