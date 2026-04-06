# Milestones

## v0.4 FPR Investigation, Pattern Expansion & Tool Call Monitoring (Shipped: 2026-03-12)

**Phases completed:** 4 phases (4-7), 8 plans
**Git range:** `feat(04-01)` → `feat(07-02)` (68 commits, 107 files, +15,221/-536 lines)
**Timeline:** 3 days (2026-03-10 → 2026-03-12)
**LOC:** ~25,192 Python (project total)
**Tests:** 1,261 passing

**Delivered:** Empirically characterized FPR behavior (Campbell et al. authorization paradox confirmed at +12.7pp), implemented per-ScanMode context-aware thresholds, expanded pattern coverage to 197 patterns across 25 categories, and added CaMeL-lite behavioral monitoring at the hook layer.

**Key accomplishments:**
1. Authorization paradox confirmed: +12.7pp FPR increase from auth preambles in Tier 1.5 (9.25% → 21.93%), Campbell et al. 2026 cited in SECURITY.md
2. Context-aware FPR thresholds: per-ScanMode (STRICT/STANDARD/LENIENT) threaded end-to-end through hooks and scanner
3. Workflow FPR reduced from 30.2% to 18.9%: CI-001 restricted to strict mode, eliminating 23.9% Tier 0 floor
4. Log-To-Leak exfiltration category: 4 new patterns (LTL-001–LTL-004), 197 total patterns across 25 categories
5. CaMeL-lite behavioral monitoring: ToolCallMonitor with SEQ-001–SEQ-004 rules, JSONL logging, <0.5ms overhead

**Known tech debt:**
- 06-02-SUMMARY.md claims "Tier 0 standalone FPR = 0.0%" — actual 10.7% (residual EX-001, CI-002, PE-005, CH-009, VP-007)
- Nyquist validation partial for Phases 4-7 (draft status, not compliant)
- 2 human verification items pending for calibration script

---

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

