# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v0.3 — White-Box Adversarial Resilience

**Shipped:** 2026-03-11
**Phases:** 3 | **Plans:** 8 | **Sessions:** ~5

### What Was Built
- Transferability gate experiment (PWWS + TextFooler-BERTScore against DeBERTa proxy) — correctly triggered pivot
- Adversarial data augmentation pipeline (2 rounds PWWS, 132 samples added to v4 dataset)
- FreeLB embedding perturbation AT integrated into training loop
- Mahalanobis anomaly detector on CLS embeddings (dual-output ONNX model)
- Adaptive attack benchmark with Wilson CIs and correlated failure analysis
- Automated framing audit (8 tests enforcing "raises attacker cost" language)
- Publication drafts: Medium Part 2, LinkedIn, venue assessment, HF model card update, release notes

### What Worked
- **Empirical gating before investment:** The transferability gate saved months of wasted DeBERTa fine-tuning work. Validate-before-committing is the right default for ML research.
- **Pivot survey depth:** Evaluating 12 alternatives systematically produced a well-reasoned pivot. The survey doc remains a valuable reference.
- **ASR gate in augmentation:** Stopping after round 2 (ASR 20% < 35% target) prevented unnecessary rounds. PWWS generation success rate declining (65.7% → 31.7%) confirmed hardening.
- **Honest negative results:** Publishing Mahalanobis at 2.7% (vs 60% target) as "marginal orthogonal signal" builds credibility. The framing audit automation prevents future regression.
- **Intensive single-day execution:** All 3 phases completed in one day. High context retention, no session handoff overhead.

### What Was Inefficient
- **Phase directory naming:** Phase 2 directory is `02-deberta-training-and-onnx-export` but Phase 2 was Adversarial Hardening (post-pivot). Directory name doesn't match content.
- **Nyquist validation retrofitting:** Phases 1-2 have stub VALIDATION.md files that were never properly filled. The retroactive validation workflow was available but not prioritized.
- **STATE.md drift:** STATE.md showed 88% progress and "Phase 2" current focus even after all phases completed. Manual state tracking drifts without discipline.
- **TextFooler silent failure:** BERTScore constraint failed silently on sample 0. Better error handling in transfer_experiment.py would have surfaced this immediately.

### Patterns Established
- **Gate decisions require Wilson 95% CI:** Point estimates cannot support binary go/no-go decisions
- **Per-category breakdown mandatory:** Aggregate metrics hide structural failure modes
- **Dual-output ONNX models:** Export (logits, embeddings) enables downstream anomaly detection without separate inference
- **Isolated venvs for attack tooling:** .venv-transfer prevents TextAttack/transformers version conflicts
- **Framing audit automation:** Prohibited words checked in CI prevent marketing language in security publications
- **Measurement scripts are never training scripts:** Adaptive benchmark scripts don't write to training data directories

### Key Lessons
1. **Structural attacks are an information-theoretic limit, not a model problem.** Sub-30-char fragments and implicit instructions transfer at 88-100% regardless of architecture. ML cannot solve this; Tier 0 heuristics are the right defense.
2. **Literature projections are targets, not guarantees.** ASR ≤35% was a projection (we got 9.7%), but Mahalanobis 60% was also a projection (we got 2.7%). Always frame as "will validate experimentally."
3. **Negative results are publishable.** The Mahalanobis miss is as valuable as the ASR improvement. The gap between literature estimates and domain-specific reality is itself a finding.
4. **Adversarial augmentation is attack-specific.** PWWS hardening may not generalize to TextFooler/BERT-Attack. Future work should evaluate cross-attack transfer.

### Cost Observations
- Model mix: ~70% opus, ~25% sonnet, ~5% haiku (sub-agents)
- Sessions: ~5 (intensive)
- Notable: Single-day milestone execution is efficient but demands high sustained attention. Context window management was critical — phase summaries kept handoffs clean.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v0.3 | ~5 | 3 | Empirical gating, pivot survey, adversarial training pipeline |

### Cumulative Quality

| Milestone | Tests | Dataset | Key Metric |
|-----------|-------|---------|------------|
| v0.3 | 1,053 | 6,472 (v4) | ASR 9.7%, recall 90.3%, latency p95 16.61ms |

### Top Lessons (Verified Across Milestones)

1. Validate empirically before committing — theory is insufficient for security claims
2. Publish negative results honestly — credibility compounds
