# CloneGuard

## What This Is

Pre-execution defense layer that raises the cost of prompt injection attacks against AI coding agents (Claude Code, GitHub Copilot, Cursor, Gemini CLI, Codex CLI). Scans repository files, tool output, and agent configurations before agents process them. Multi-tier detection: regex patterns (Tier 0), ONNX semantic classifier (Tier 1.5), Ollama LLM fallback (Tier 2).

## Core Value

Make prompt injection attacks against AI coding agents expensive enough that attackers move on to easier targets.

## Requirements

### Validated

- v0.2.3: 193 regex patterns across 24 categories (Tier 0)
- v0.2.3: MiniLM-L6-v2 ONNX classifier with sliding window (Tier 1.5, CV F1=95.51%)
- v0.2.3: Ollama qwen2.5:7b fallback (Tier 2)
- v0.2.3: 4-layer hook defense (L0 wrapper, L1 InstructionsLoaded, L2 PostToolUse, L3 PreToolUse)
- v0.2.3: SHA-256 trust cache, content-hash allowlist
- v0.2.3: MCP Gateway plugin
- v0.2.3: Multi-agent hook support (Claude Code, Gemini CLI, Cursor, Windsurf, VS Code Copilot)
- v0.2.3: Mode-restricted patterns (strict/standard/lenient)
- v0.2.3: Combined pipeline recall 80.5%, false block rate 3.8%

### Active

See `.planning/REQUIREMENTS.md`

### Out of Scope

- Full multilingual coverage — deferred to GitHub issue #5
- Perturbation detection / randomized smoothing — defer unless ensemble proves insufficient
- Retraining MiniLM-L6-v2 base model
- Tier 2 (Ollama) changes
- Subsuming mcp-guard as sub-project

## Context

- 978 tests passing, CI green
- Adversarial security review (3 agents) identified H8: white-box attacks against the public MiniLM model are estimated 70-90% successful for a skilled adversarial ML practitioner
- The ONNX model is public on HuggingFace, architecture is documented — attacker can compute exact gradients
- Phase 1 transferability experiment: 58.0% transfer rate MiniLM→DeBERTa (CI: 47.5%–67.7%). Structural attacks transfer at 88-100%. Ensemble approach abandoned.
- Dataset: 6,340 samples (v3), published on HuggingFace (gated)
- Current Tier 1.5 latency: ~16ms/sample. Budget for hardened pipeline: ~25ms total

## Constraints

- **ONNX-only inference**: No PyTorch at runtime. Classifier must export to ONNX for CPUExecutionProvider.
- **Dependency budget**: Minimize new dependencies. onnxruntime + transformers tokenizer already present.
- **Latency**: Hardened pipeline (Tier 0 + Tier 1.5 + Mahalanobis) must stay under ~25ms/sample on Apple M-series CPU.
- **Same dataset**: Adversarial augmentation extends the existing 6,340-sample dataset, does not replace it.
- **Clean accuracy floor**: Adversarial training must not drop 5-fold CV F1 below 94.5% (currently 95.51%).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Transferability experiment as gate | Don't trust theory — validate empirically on our domain before committing | Gate failed: 58% transfer. Ensemble abandoned. |
| Ensemble over perturbation detection | Architecturally diverse models defeat transfer attacks | Invalidated: structural attacks transfer at 88-100% regardless of architecture |
| Adversarial hardening over second classifier | AT + Mahalanobis: higher ROI, lower complexity, +1-5ms vs +40-60ms latency | Adopted post-pivot |
| Literature projections as targets, not guarantees | ASR ≤35% target from A2T (Yoo & Qi 2021) extrapolation — must validate experimentally | Pending Phase 2 |

## Current Milestone: v0.3.0 White-Box Adversarial Resilience

**Goal:** Harden Tier 1.5 against white-box adversarial attacks through adversarial training (data augmentation + FreeLB) and Mahalanobis anomaly detection. Publish results with honest framing.

**Target features:**
- Adversarial data augmentation (PWWS-generated examples, 2-3 rounds)
- FreeLB embedding perturbation AT in training loop
- Mahalanobis anomaly detector on CLS embeddings
- Adversarial benchmark with adaptive attacks and honest publication

---
*Last updated: 2026-03-10 after Phase 1 gate failure and pivot*
