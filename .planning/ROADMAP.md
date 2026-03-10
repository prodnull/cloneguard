# Roadmap: CloneGuard v0.3.0 — White-Box Adversarial Resilience

## Overview

This milestone adds a second ONNX classifier (DeBERTa-v3-small) to the existing MiniLM Tier 1.5 in a parallel-vote ensemble, targeting white-box adversarial attacks against the public MiniLM weights. The work proceeds through four phases under a hard empirical gate: if cross-architecture transfer rate exceeds 40%, the milestone pivots before any training investment is made. Phases execute sequentially because each phase's artifact is a prerequisite for the next.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, 4): Planned milestone work for v0.3.0
- Decimal phases: Urgent insertions if needed (marked INSERTED)

- [ ] **Phase 1: Transferability Gate** - Empirically validate that white-box adversarial examples against MiniLM do not transfer effectively to DeBERTa (hard gate: >40% = pivot)
- [ ] **Phase 2: DeBERTa Training and ONNX Export** - Fine-tune DeBERTa-v3-small on differentially augmented dataset and export to INT8 ONNX with automated sanity check
- [ ] **Phase 3: Ensemble Integration** - Wire parallel-vote ensemble into hooks, scanner, and MCP plugin with four-state graceful degradation
- [ ] **Phase 4: Adversarial Benchmark and Publication** - Run full ensemble adversarial benchmark (non-adaptive + adaptive attacks), publish results with honest framing

## Phase Details

### Phase 1: Transferability Gate
**Goal**: Empirically determine whether the ensemble approach is worth pursuing — if white-box adversarial examples against MiniLM transfer to DeBERTa at >40%, the approach pivots before any training investment
**Depends on**: Nothing (first phase)
**Requirements**: XFER-01, XFER-02, XFER-03
**Success Criteria** (what must be TRUE):
  1. TextAttack (PWWS + TextFooler) generates adversarial examples against MiniLM on the 185-sample held-out adversarial benchmark and results are saved to `docs/results/`
  2. Transfer rate to ProtectAI DeBERTa proxy model is measured and recorded as a numeric percentage with methodology documented
  3. Gate decision is made and documented: transfer rate at or below 40% = proceed to Phase 2; above 40% = pivot path documented and published regardless
  4. Results published honestly — transfer rate, attack method, proxy model identity, and limitations of proxy-vs-fine-tuned comparison all disclosed
**Plans**: TBD

> **HARD GATE:** If transfer rate >40%, Phase 2 does not begin. Pivot options and published results replace the remainder of this milestone. Document and publish regardless of outcome.

### Phase 2: DeBERTa Training and ONNX Export
**Goal**: Produce a validated, deployable DeBERTa-v3-small ONNX classifier trained on data that is augmented differently from MiniLM's training set, with latency verified under 60ms
**Depends on**: Phase 1 (gate must pass: transfer rate <= 40%)
**Requirements**: DBERT-01, DBERT-02, DBERT-03, DBERT-04
**Success Criteria** (what must be TRUE):
  1. DeBERTa-v3-small is fine-tuned on a dataset augmented via a pipeline (back-translation or character perturbation) that does not overlap with the augmentation rounds used for MiniLM v3 training
  2. ONNX export completes via `ORTModelForSequenceClassification(..., export=True)` programmatically (not optimum-cli) and passes automated sanity check: 50 balanced samples produce non-constant, non-degenerate predictions with ONNX/PyTorch logit agreement atol <= 0.001
  3. INT8 quantized model runs inference under 60ms per sample on Apple M-series CPUExecutionProvider, empirically measured
  4. Model is published to a separate HuggingFace repo with SHA-256 checksum verified by `fetch_ensemble_model.py`
**Plans**: TBD

> **NOTE:** `use_fast=False` tokenizer (SentencePiece backend) is required. `pipeline()` must not be used — pass `input_ids` and `attention_mask` directly. If INT8 latency exceeds 80ms, fall back to `deberta-v3-xsmall`.

### Phase 3: Ensemble Integration
**Goal**: Both classifiers run on every scanned input via a centralized voting module, with four-state graceful degradation and WARNING-on-disagreement semantics, wired into hooks, scanner, and MCP plugin
**Depends on**: Phase 2 (needs validated ONNX artifact)
**Requirements**: ENS-01, ENS-02, ENS-03, ENS-04, ENS-05
**Success Criteria** (what must be TRUE):
  1. `cloneguard scan` invokes both classifiers on every input and reports one of four states: BLOCK (both flag), WARNING (disagree), SAFE (both clear), or DEGRADED (one or both unavailable — falls back to Tier 0)
  2. JSON hook output from hooks.py includes the disagree state as a distinct field, observable in Claude Code and Gemini CLI hook payloads
  3. Ensemble WARNING rate on the held-out benign eval set is at or below 10% disagreement, measured and recorded before Phase 4 begins
  4. All four graceful degradation states (both available, MiniLM only, DeBERTa only, neither) are exercised and produce correct output without crashing
**Plans**: TBD

> **NOTE:** Voting logic lives entirely in `ensemble.py`. `mini_semantic.py` is not modified. Classifiers run sequentially (no threading). OR-vote is mode-gated: STRICT mode only in standard scan context; confidence threshold p > 0.65 required in other modes.

### Phase 4: Adversarial Benchmark and Publication
**Goal**: Publish empirical evidence of ensemble effectiveness against both non-adaptive and adaptive adversarial attacks, with honest "raises attacker cost" framing that satisfies NIST AI 100-2e2025 adaptive evaluation requirements
**Depends on**: Phase 3 (needs integrated, operational ensemble)
**Requirements**: BENCH-01, BENCH-02, BENCH-03, BENCH-04
**Success Criteria** (what must be TRUE):
  1. Adversarial benchmark (185 malicious + 234 benign) is re-run with the full ensemble pipeline and produces a results table showing recall, FPR, and attack success rate (ASR) before and after ensemble, published to `docs/results/`
  2. Adaptive ensemble-targeting attacks (Stage 2 — attacks crafted against both models simultaneously) are run and reported alongside non-adaptive results; results are not presented without Stage 2
  3. Correlated failure analysis identifies which samples both models get wrong simultaneously, documented as a known limitation
  4. All published results use "raises attacker cost" framing — words "prevents," "blocks," and "secure" do not appear in benchmark writeup, HuggingFace model card, or release notes
**Plans**: TBD

## Progress

**Execution Order:** 1 → 2 → 3 → 4 (sequential, each phase gates the next)

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Transferability Gate | 0/TBD | Not started | - |
| 2. DeBERTa Training and ONNX Export | 0/TBD | Not started | - |
| 3. Ensemble Integration | 0/TBD | Not started | - |
| 4. Adversarial Benchmark and Publication | 0/TBD | Not started | - |
