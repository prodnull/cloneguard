# Milestones

## v0.3 White-Box Adversarial Resilience (Shipped: 2026-03-11)

**Phases completed:** 3 phases, 8 plans, 19 tasks
**Git range:** `feat(01-01)` → `docs(phase-02)` (49 commits, 54 files, +22,075/-254 lines)
**Timeline:** 2026-03-10 (intensive single-day milestone)
**LOC:** ~21,071 Python (project total)
**Dataset:** v3 (6,340) → v4 (6,472 samples, +132 PWWS adversarial augmentation)

**Delivered:** Hardened Tier 1.5 against white-box adversarial attacks through empirical transferability gating, PWWS+FreeLB adversarial training, and Mahalanobis anomaly detection. Published all results with honest "raises attacker cost" framing.

**Key accomplishments:**
1. Transferability gate correctly triggered pivot at 58.0% transfer rate (CI: 47.5%-67.7%) — ensemble abandoned empirically, not speculatively
2. PWWS ASR reduced from ~65.7% to 9.7% via 2 rounds adversarial augmentation + FreeLB embedding AT (target ≤35% exceeded by 25.3pp)
3. Mahalanobis anomaly detector integrated and honestly reported as marginal (2.7% vs 60% target) — published as negative result with full methodology
4. Adaptive attacks measured at 20.3% ASR ceiling (CI: 14.6%-27.5%) — distinct from training-time ASR
5. Correlated failure analysis identified 18/185 structural both-miss samples — information-theoretic limit documented
6. Automated framing audit (8 tests) enforces "raises attacker cost" language across all publication channels

**Known tech debt:**
- Nyquist validation partial for Phases 1-2 (stubs, not retroactively filled)
- Mahalanobis SC3 miss: CLS embedding distributions overlap — experimental result, not code defect
- Pre-existing test_latency.py intermittent failure under load (not introduced by milestone)

**Superseded:** 9 requirements (DBERT-01-04, ENS-01-05) abandoned after Phase 1 gate failure — ensemble approach invalidated empirically

---

