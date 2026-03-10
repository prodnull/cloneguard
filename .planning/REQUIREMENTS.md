# Requirements: CloneGuard v0.3.0

**Defined:** 2026-03-10
**Core Value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on

## v0.3.0 Requirements

### Transferability Experiment

- [ ] **XFER-01**: Generate adversarial examples against MiniLM using TextAttack (PWWS + TextFooler) on held-out adversarial benchmark (185 samples)
- [ ] **XFER-02**: Measure transfer rate to ProtectAI DeBERTa proxy model as early signal before fine-tuning investment
- [ ] **XFER-03**: Hard gate: transfer rate >40% = pivot to alternative defense; document and publish results regardless of outcome

### Second Classifier

- [ ] **DBERT-01**: Train DeBERTa-v3-small on differentially augmented dataset (back-translation, character perturbation — NOT identical to MiniLM's v3 dataset)
- [ ] **DBERT-02**: Export to ONNX via ORTModel programmatically (not optimum-cli), with automated sanity check (50 balanced samples, non-constant predictions)
- [ ] **DBERT-03**: INT8 quantization, latency verified under 60ms on Apple M-series CPUExecutionProvider
- [ ] **DBERT-04**: Separate HuggingFace repo, separate fetch script with SHA-256 verification

### Ensemble Integration

- [ ] **ENS-01**: New `ensemble_semantic.py` module (DeBERTa classifier, separate from `mini_semantic.py`)
- [ ] **ENS-02**: New `ensemble.py` voting module — single voting policy, called by hooks.py, scanner.py, mcp_plugin.py
- [ ] **ENS-03**: Voting policy: agree-malicious BLOCK, disagree WARNING, agree-safe SAFE
- [ ] **ENS-04**: 4-state graceful degradation (both available, MiniLM only, DeBERTa only, neither — Tier 0 only)
- [ ] **ENS-05**: Benchmark ensemble FPR on benign eval set; WARNING rate ceiling <10% disagreement on benign inputs

### Adversarial Benchmark

- [ ] **BENCH-01**: Re-run adversarial benchmark (185 malicious + 234 benign) with ensemble pipeline, publish results
- [ ] **BENCH-02**: Include adaptive ensemble-targeting attacks (not just static transfer experiments)
- [ ] **BENCH-03**: Correlated failure analysis — identify which samples BOTH models get wrong simultaneously
- [ ] **BENCH-04**: Publish results with honest "raises attacker cost" framing, not "prevents" or "blocks"

## Future Requirements

### Deferred from v0.3.0

- **DIV-01**: Diversity training (iGAT / negative correlation learning) for ensemble members
- **WEIGHT-01**: Weighted / confidence-calibrated voting (requires calibration data post-deployment)
- **MULTI-01**: Expanded multilingual training data and benchmark (GitHub issue #5)
- **PERT-01**: Input perturbation detection (embedding density analysis)
- **SMOOTH-01**: Randomized smoothing (classify perturbed variants, majority vote)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Perturbation detection / randomized smoothing | Defer unless ensemble proves insufficient |
| Retraining MiniLM-L6-v2 | Stays as-is; ensemble adds defense without modifying existing model |
| Diversity training (iGAT) | Complex; differential augmentation is the pragmatic v0.3.0 alternative |
| ModernBERT | ONNX optimization immature (optimum #2177), closer to standard BERT, 7x larger |
| ProtectAI model as production classifier | Unknown training data; fair experiment needs same training corpus |
| Weighted voting / calibration | Ship majority vote first, tune post-deployment with real data |
| Tier 2 (Ollama) changes | Orthogonal to ensemble; unchanged |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| XFER-01 | Phase 1 | Pending |
| XFER-02 | Phase 1 | Pending |
| XFER-03 | Phase 1 | Pending |
| DBERT-01 | Phase 2 | Pending |
| DBERT-02 | Phase 2 | Pending |
| DBERT-03 | Phase 2 | Pending |
| DBERT-04 | Phase 2 | Pending |
| ENS-01 | Phase 3 | Pending |
| ENS-02 | Phase 3 | Pending |
| ENS-03 | Phase 3 | Pending |
| ENS-04 | Phase 3 | Pending |
| ENS-05 | Phase 3 | Pending |
| BENCH-01 | Phase 4 | Pending |
| BENCH-02 | Phase 4 | Pending |
| BENCH-03 | Phase 4 | Pending |
| BENCH-04 | Phase 4 | Pending |

**Coverage:**
- v0.3.0 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0

---
*Requirements defined: 2026-03-10*
*Last updated: 2026-03-10 after roadmap creation*
