# Requirements: CloneGuard v0.3.0

**Defined:** 2026-03-10
**Pivoted:** 2026-03-10 (ensemble → adversarial hardening)
**Core Value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on

## v0.3.0 Requirements

### Transferability Experiment (Complete)

- [x] **XFER-01**: Generate adversarial examples against MiniLM using TextAttack (PWWS + TextFooler) on held-out adversarial benchmark (185 samples)
- [x] **XFER-02**: Measure transfer rate to ProtectAI DeBERTa proxy model as early signal before fine-tuning investment
- [x] **XFER-03**: Hard gate: transfer rate >40% = pivot to alternative defense; document and publish results regardless of outcome

### Adversarial Hardening (Replaces Second Classifier + Ensemble)

- [ ] **HARD-01**: Generate PWWS adversarial examples against MiniLM v3 using TextAttack, add to training set with correct labels, retrain (2-3 augmentation rounds)
- [ ] **HARD-02**: Implement FreeLB embedding perturbation AT in `scripts/train_mini_model.py` training loop (configurable ε, K=3 PGD steps)
- [ ] **HARD-03**: Fit per-class Mahalanobis detector on MiniLM CLS embeddings from training data, integrate into scan pipeline (`mini_semantic.py` or new module) with configurable threshold
- [ ] **HARD-04**: Re-run adversarial benchmark (185 malicious + 234 benign) with hardened pipeline, publish before/after comparison to `docs/results/`
- [ ] **HARD-05**: Verify combined pipeline latency (Tier 0 + hardened Tier 1.5 + Mahalanobis) under 25ms per sample on Apple M-series CPU

### Adversarial Benchmark

- [ ] **BENCH-01**: Re-run adversarial benchmark (185 malicious + 234 benign) with full hardened pipeline, publish results
- [ ] **BENCH-02**: Run adaptive attacks (PWWS against hardened model, not just original) and report alongside non-adaptive results
- [ ] **BENCH-03**: Correlated failure analysis — identify which samples Tier 0 AND hardened Tier 1.5 both miss
- [ ] **BENCH-04**: Publish results with honest "raises attacker cost" framing, not "prevents" or "blocks"

### Superseded Requirements

The following requirements were part of the original ensemble plan and are superseded by the pivot:

- ~~**DBERT-01** through **DBERT-04**~~: DeBERTa training and ONNX export — eliminated (gate failed)
- ~~**ENS-01** through **ENS-05**~~: Ensemble integration and voting — eliminated (no second classifier)

**Rationale:** Phase 1 gate failure (58.0% transfer rate) invalidated the ensemble approach. Structural attacks transfer at 88-100% regardless of architecture. See `docs/results/pivot-alternatives-survey-2026-03-10.md`.

## Future Requirements

### Deferred from v0.3.0

- **TFIDF-01**: TF-IDF + XGBoost gradient-free classifier as Tier 1.6 (contingency if AT doesn't achieve ≤35% ASR)
- **DIV-01**: Diversity training (iGAT / negative correlation learning) — no NLP validation in literature
- **WEIGHT-01**: Weighted / confidence-calibrated voting (requires calibration data post-deployment)
- **MULTI-01**: Expanded multilingual training data and benchmark (GitHub issue #5)
- **SMOOTH-01**: Randomized smoothing — eliminated for v0.3.0 (incompatible with 20ms latency budget)
- **IBP-01**: Certified robustness via interval bound propagation — eliminated for v0.3.0 (3-8% clean accuracy cost, MiniLM attention makes bounds too loose)

## Out of Scope

| Feature | Reason |
|---------|--------|
| DeBERTa ensemble | Gate failed: 58% transfer rate. Structural attacks transfer at 88-100% regardless of architecture. |
| Randomized smoothing | 100-5000x latency multiplier incompatible with 20ms budget (SAFER, Ye et al. 2020) |
| IBP certified training | 3-8% clean accuracy cost + MiniLM attention bounds too loose (ICLR 2024) |
| Defensive distillation | Broken for text (Carlini & Wagner 2016; Springer 2019) |
| Gradient masking | Irrelevant — PWWS/TextFooler are gradient-free (Athalye et al. 2018) |
| NCL/DVERGE diversity | Zero NLP validation — all results vision-only |
| Retraining MiniLM base model | Adversarial hardening fine-tunes the classification head, not the base encoder |
| Tier 2 (Ollama) changes | Orthogonal to hardening; unchanged |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| XFER-01 | Phase 1 | Complete |
| XFER-02 | Phase 1 | Complete |
| XFER-03 | Phase 1 | Complete |
| HARD-01 | Phase 2 | Pending |
| HARD-02 | Phase 2 | Pending |
| HARD-03 | Phase 2 | Pending |
| HARD-04 | Phase 2 | Pending |
| HARD-05 | Phase 2 | Pending |
| BENCH-01 | Phase 3 | Pending |
| BENCH-02 | Phase 3 | Pending |
| BENCH-03 | Phase 3 | Pending |
| BENCH-04 | Phase 3 | Pending |

**Coverage:**
- v0.3.0 requirements: 12 total (3 complete + 9 pending)
- Mapped to phases: 12
- Unmapped: 0
- Superseded: 9 (DBERT-01–04, ENS-01–05)

---
*Requirements defined: 2026-03-10*
*Pivoted: 2026-03-10 after Phase 1 gate failure*
