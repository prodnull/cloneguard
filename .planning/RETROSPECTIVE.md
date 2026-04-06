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

## Milestone: v0.4 — FPR Investigation, Pattern Expansion & Tool Call Monitoring

**Shipped:** 2026-03-12
**Phases:** 4 | **Plans:** 8 | **Sessions:** ~6

### What Was Built
- FPR investigation infrastructure: 757-sample benign corpus, defensive security corpus, paired-corpus benchmark
- Authorization paradox measurement: +12.7pp Tier 1.5 FPR from auth preambles confirmed empirically
- Per-ScanMode context-aware thresholds (STRICT/STANDARD/LENIENT) threaded through hooks and scanner end-to-end
- Calibration script for threshold sweep on benign corpus
- Log-To-Leak exfiltration category (LTL-001–LTL-004), 197 total patterns across 25 categories
- CI-001 restricted to strict mode — eliminated 23.9% workflow Tier 0 FPR floor
- CaMeL-lite ToolCallMonitor: SEQ-001–SEQ-004 sequence rules, JSONL logging, singleton pattern
- Campbell et al. 2026 citation in SECURITY.md with honest framing

### What Worked
- **Investigation-first architecture:** Phase 4's empirical FPR data directly informed Phase 5's threshold choices. No guessing — STANDARD=(0.65,0.88) derived from calibration sweep on actual corpus.
- **Cross-phase collaboration documented honestly:** Workflow FPR target required Phase 5 (thresholds) + Phase 6 (CI-001 fix). The 30.2% intermediate result was reported as structural, not a failure.
- **Three-signal mode detection:** Path primary, hook_default fallback, content markers upgrade-only. Clean separation of concerns, easy to reason about.
- **Log-only monitor design:** Avoided false-block risk by making ToolCallMonitor advisory. <0.5ms overhead validates the non-blocking architecture.
- **CI-001 strict restriction:** Simple mode restriction eliminated a structural FPR floor that Tier 1.5 tuning couldn't address.

### What Was Inefficient
- **SUMMARY frontmatter drift:** 04-02-SUMMARY.md had empty `requirements_completed: []` despite body text confirming INV-03, DOC-01, DOC-02. Required tech debt fix commit.
- **06-02-SUMMARY inaccurate claim:** "Tier 0 standalone FPR = 0.0%" was wrong (actual 10.7%). Internal metrics need the same rigor as external claims.
- **Stale comments:** calibrate_thresholds.py still referenced "deferred to Phase 6" after Phase 6 resolved it. Comments that reference future work become stale tech debt.
- **Nyquist validation not prioritized:** All 4 phases have draft VALIDATION.md but none are compliant. Same pattern as v0.3.

### Patterns Established
- **Per-ScanMode threshold architecture:** Different scanning contexts need different sensitivity — one threshold cannot serve both security auditors and CI pipelines
- **Paired-corpus benchmarking:** Run identical benign content with/without a text feature variant to isolate FPR impact
- **Mode restriction on patterns:** `modes: [strict]` field in YAML rules prevents high-FPR patterns from firing in non-agent contexts
- **CaMeL-lite log-only pattern:** Behavioral monitoring at hook layer, JSONL append-only, never blocking — validate rules before enforcing
- **Three-signal mode detection:** path (primary) → hook_default (fallback) → content markers (upgrade only)

### Key Lessons
1. **FPR reduction often requires cross-tier collaboration.** Tier 1.5 threshold tuning alone couldn't fix a Tier 0 pattern FPR floor. Defense layers must be tuned together.
2. **Authorization paradox is real and measurable.** +12.7pp FPR increase from auth preambles — security-context framing pushes benign content toward the malicious embedding space. Campbell et al. independently validated.
3. **Internal metrics need the same rigor as external claims.** "Tier 0 FPR = 0.0%" was wrong and could have propagated to external docs. Always verify with actual measurement.
4. **Log-only monitoring is the right v1.** Behavioral sequence rules need extensive FP tuning before they can block. Ship advisory, iterate to enforcement.
5. **Nyquist validation is consistently deprioritized.** Two milestones with partial compliance suggests the workflow is too heavy for the current pace. Consider lighter-weight approach.

### Cost Observations
- Model mix: ~65% opus, ~30% sonnet, ~5% haiku (sub-agents)
- Sessions: ~6 (spread over 3 days)
- Notable: Phase dependency chain (4→5→6→7) prevented parallelization but produced cleaner handoffs. Each phase consumed prior phase's empirical results.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v0.3 | ~5 | 3 | Empirical gating, pivot survey, adversarial training pipeline |
| v0.4 | ~6 | 4 | Investigation-first architecture, cross-phase FPR collaboration, behavioral monitoring |

### Cumulative Quality

| Milestone | Tests | Dataset | Key Metric |
|-----------|-------|---------|------------|
| v0.3 | 1,053 | 6,472 (v4) | ASR 9.7%, recall 90.3%, latency p95 16.61ms |
| v0.4 | 1,261 | 6,472 (v4) | Workflow FPR 18.9%, 197 patterns/25 categories, ToolCallMonitor <0.5ms |

### Top Lessons (Verified Across Milestones)

1. Validate empirically before committing — theory is insufficient for security claims
2. Publish negative results honestly — credibility compounds
3. FPR reduction requires cross-tier collaboration — single-layer tuning hits structural limits
4. Internal metrics need the same rigor as external claims — wrong numbers propagate
