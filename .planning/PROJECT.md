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
- Theory (Papernot et al. 2016, Tramer et al. 2017) suggests cross-architecture transfer is lower but not zero — needs empirical validation on our domain
- Dataset: 6,340 samples (v3), published on HuggingFace (gated)
- Current Tier 1.5 latency: ~16ms/sample. Budget for ensemble: ~70-120ms total acceptable

## Constraints

- **ONNX-only inference**: No PyTorch at runtime. Both classifiers must export to ONNX for CPUExecutionProvider.
- **Dependency budget**: Minimize new dependencies. onnxruntime + transformers tokenizer already present.
- **Latency**: Combined ensemble must stay under ~120ms/sample on Apple M-series CPU.
- **Same dataset**: Second classifier trains on same 6,340-sample dataset for fair comparison.
- **Architecture dissimilarity**: Second model must use fundamentally different tokenization and embedding approach from MiniLM-L6-v2.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Parallel vote (option B) over cascade | GitHub issue title injection scenario — cascade misses adversarial evasions on non-file content | — Pending |
| Ensemble over perturbation detection | Architecturally diverse models defeat transfer attacks; perturbation detection less proven for text | — Pending |
| Transferability experiment as gate | Don't trust theory — validate empirically on our domain before committing | — Pending |

## Current Milestone: v0.3.0 White-Box Adversarial Resilience

**Goal:** Defend Tier 1.5 against white-box adversarial attacks by adding an architecturally diverse ensemble classifier with parallel voting.

**Target features:**
- Transferability experiment (adversarial examples against MiniLM, measure transfer to second architecture)
- Second ONNX classifier on architecturally different base (DeBERTa or ModernBERT)
- Parallel vote integration — both classifiers on all content
- Ensemble adversarial benchmark with published results

---
*Last updated: 2026-03-10 after milestone v0.3.0 initialization*
