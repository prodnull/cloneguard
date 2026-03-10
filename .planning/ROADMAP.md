# Roadmap: CloneGuard v0.3.0 — White-Box Adversarial Resilience

## Overview

This milestone hardens Tier 1.5 against white-box adversarial attacks through adversarial training and anomaly detection. The original plan (cross-architecture ensemble with DeBERTa) was abandoned after Phase 1's transferability gate failed: 58.0% transfer rate (CI: 47.5%–67.7%) exceeded the 40% threshold, with structural attack categories transferring at 88–100%. The pivot survey (`docs/results/pivot-alternatives-survey-2026-03-10.md`) evaluated 12 alternative defenses and recommended adversarial hardening of the existing MiniLM classifier plus a Mahalanobis anomaly detector.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work for v0.3.0
- Phase 1 is the original transferability gate (complete, triggered pivot)
- Phases 2-3 replace the original Phases 2-4 post-pivot
- Decimal phases: Urgent insertions if needed (marked INSERTED)

- [x] **Phase 1: Transferability Gate** - Empirically validate that white-box adversarial examples against MiniLM do not transfer effectively to DeBERTa (hard gate: >40% = pivot) (completed 2026-03-10)
- [ ] **Phase 2: Adversarial Hardening** - Harden MiniLM via adversarial data augmentation + FreeLB embedding AT, add Mahalanobis anomaly detector, re-benchmark
- [ ] **Phase 3: Adversarial Benchmark and Publication** - Run full hardened pipeline benchmark with adaptive attacks, publish results with honest framing

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
**Plans:** 2/2 plans complete
**Result:** PIVOT — 58.0% transfer rate. Ensemble abandoned. See `docs/results/transfer-experiment-analysis-2026-03-10.md`

Plans:
- [x] 01-01-PLAN.md — Create isolated venv and transfer experiment script (ONNX wrapper, PWWS + TextFooler attacks, DeBERTa proxy scoring)
- [x] 01-02-PLAN.md — Run full experiment on 185 samples, produce gate decision, user review

> **GATE RESULT:** Transfer rate 58.0% (>40%). Original Phases 2-4 (DeBERTa training, ensemble integration, ensemble benchmark) replaced with adversarial hardening approach per pivot survey.

### Phase 2: Adversarial Hardening
**Goal**: Reduce PWWS attack success rate from 58% to ≤35% on vocabulary-attack categories through adversarial training, and add Mahalanobis anomaly detection as an orthogonal defense signal. All improvement targets are projections from literature that must be validated experimentally (see survey citation audit).
**Depends on**: Phase 1 (pivot survey complete)
**Requirements**: HARD-01, HARD-02, HARD-03, HARD-04, HARD-05
**Success Criteria** (what must be TRUE):
  1. PWWS attack success rate ≤35% on vocabulary-attack categories (synonym_substitution, social_engineering, counter_defensive), measured on the 185-sample adversarial benchmark
  2. Clean accuracy (5-fold CV) does not drop below 94.5% (currently 95.51% ± 0.53%)
  3. Mahalanobis detector flags ≥60% of successful adversarial examples at ≤5% FPR on the 234-sample benign eval set
  4. Combined pipeline latency (Tier 0 + hardened Tier 1.5 + Mahalanobis) under 25ms per sample on Apple M-series CPU
**Plans:** 1/3 plans executed

Plans:
- [ ] 02-01-PLAN.md — Create PWWS augmentation script + FreeLB training modifications + dual-output ONNX export
- [ ] 02-02-PLAN.md — Execute 2-3 augmentation rounds with ASR gate, produce hardened v4 model
- [ ] 02-03-PLAN.md — Mahalanobis detector + pipeline integration + benchmark + latency verification

> **NOTE:** Success criteria are targets derived from literature projections (A2T, Yoo & Qi 2021; Lee et al. 2018; Yoo et al. 2022). If empirical results fall short, document actual improvement and proceed to Phase 3 with honest numbers. Do not cherry-pick thresholds post-hoc.

### Phase 3: Adversarial Benchmark and Publication
**Goal**: Publish empirical evidence of adversarial hardening effectiveness with honest "raises attacker cost" framing, including adaptive attacks against the hardened model
**Depends on**: Phase 2 (needs hardened model + Mahalanobis detector)
**Requirements**: BENCH-01, BENCH-02, BENCH-03, BENCH-04
**Success Criteria** (what must be TRUE):
  1. Adversarial benchmark (185 malicious + 234 benign) is re-run with the full hardened pipeline (Tier 0 + hardened Tier 1.5 + Mahalanobis) and produces a results table showing recall, FPR, and ASR before and after hardening, published to `docs/results/`
  2. Adaptive attacks — PWWS generated against the hardened model (not just the original) — are run and reported alongside non-adaptive results; the improvement ceiling is documented
  3. Correlated failure analysis between Tier 0 and hardened Tier 1.5 identifies which samples remain undetected by both, documented as known limitations
  4. All published results use "raises attacker cost" framing — words "prevents," "blocks," and "secure" do not appear in benchmark writeup, HuggingFace model card, or release notes

> **NOTE:** If Phase 2 doesn't achieve ≤35% ASR, Phase 3 publishes actual results honestly. A TF-IDF + XGBoost ensemble (Tier 1.6) is a contingency option evaluated in the pivot survey but not currently phased.

## Superseded Phases (Original Plan)

The following phases from the original roadmap were replaced after the Phase 1 gate failure:

- ~~Phase 2: DeBERTa Training and ONNX Export~~ → Replaced by Phase 2: Adversarial Hardening
- ~~Phase 3: Ensemble Integration~~ → Eliminated (no second classifier)
- ~~Phase 4: Adversarial Benchmark and Publication~~ → Replaced by Phase 3: Adversarial Benchmark and Publication (scoped to hardening, not ensemble)

**Rationale:** 58.0% adversarial transfer rate proved that structural attacks (fragmentation, implicit instruction, truncation, dilution) transfer at 88–100% regardless of architecture. Adding a second transformer classifier provides marginal gain on vocabulary attacks that Tier 0 already handles at 95–100%. Adversarial hardening of the existing model is higher ROI with lower operational complexity.

## Progress

**Execution Order:** 1 → 2 → 3 (sequential)

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Transferability Gate | 2/2 | Complete (PIVOT) | 2026-03-10 |
| 2. Adversarial Hardening | 1/3 | In Progress|  |
| 3. Adversarial Benchmark and Publication | 0/TBD | Not started | - |
