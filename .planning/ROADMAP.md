# Roadmap: CloneGuard

## Milestones

- ✅ **v0.3 White-Box Adversarial Resilience** — Phases 1-3 (shipped 2026-03-11)
- 🚧 **v0.4 FPR Investigation, Pattern Expansion & Tool Call Monitoring** — Phases 4-7 (in progress)

## Phases

<details>
<summary>✅ v0.3 White-Box Adversarial Resilience (Phases 1-3) — SHIPPED 2026-03-11</summary>

- [x] Phase 1: Transferability Gate (2/2 plans) — completed 2026-03-10 (PIVOT at 58.0%)
- [x] Phase 2: Adversarial Hardening (3/3 plans) — completed 2026-03-10
- [x] Phase 3: Adversarial Benchmark & Publication (3/3 plans) — completed 2026-03-10

See: `.planning/milestones/v0.3-ROADMAP.md` for full details.

</details>

### 🚧 v0.4 FPR Investigation, Pattern Expansion & Tool Call Monitoring (In Progress)

**Milestone Goal:** Empirically characterize FPR behavior informed by Campbell et al. 2026, reduce sliding-window FPR in high-noise contexts, expand pattern coverage to 11 identified gaps, and add tool call behavioral monitoring at the hook layer.

- [x] **Phase 4: FPR Investigation & Documentation** — Audit the authorization paradox in our pipeline, measure security-context marker FPR impact, document structural limits, cite Campbell et al. (completed 2026-03-11)
- [x] **Phase 5: FPR Tuning** — Implement context-aware thresholds and reduce sliding-window FPR in agent_instructions and workflows, informed by Phase 4 findings (completed 2026-03-11)
- [ ] **Phase 6: Pattern Expansion** — Add 51 new patterns covering 11 identified gaps plus Log-To-Leak exfiltration patterns
- [ ] **Phase 7: Tool Call Monitoring** — Implement CaMeL-lite behavioral monitoring at hook layer to detect anomalous tool call sequences

## Phase Details

### Phase 4: FPR Investigation & Documentation
**Goal**: Users can see empirically grounded findings on whether the authorization paradox manifests in CloneGuard's pipeline, with Campbell et al. cited in the threat model
**Depends on**: Phase 3 (v0.3 shipped)
**Requirements**: INV-01, INV-02, INV-03, DOC-01, DOC-02
**Plans:** 2/2 plans complete

Plans:
- [ ] 04-01-PLAN.md — Build investigation infrastructure, run FPR benchmark (INV-01 + INV-02)
- [ ] 04-02-PLAN.md — Write findings document, update SECURITY.md and Medium draft (INV-03 + DOC-01 + DOC-02)

**Success Criteria** (what must be TRUE):
  1. A benchmark result exists comparing FPR with and without security-context markers (authorization preambles, blue-team framing) on Tier 0+1.5
  2. All 4 strict-only patterns (CI-004, CI-006, SC-001, MCP-005) have been audited against a corpus of legitimate defensive security content and findings are recorded
  3. SECURITY.md cites Campbell et al. 2026 with accurate framing of asymmetric burden and embedding-space structural limits
  4. Medium Part 2 draft is updated to contextualize FPR results using Campbell findings
  5. INV-03 findings document is written: structural FPR limits are characterized and authorization paradox presence/absence in our pipeline is stated with supporting data

### Phase 5: FPR Tuning
**Goal**: Users operating CloneGuard in agent_instructions and workflow contexts experience materially lower false positive rates via per-context thresholds derived from Phase 4 empirical findings
**Depends on**: Phase 4
**Requirements**: FPR-01, FPR-02
**Plans:** 2/2 plans complete

Plans:
- [ ] 05-01-PLAN.md — Calibration script and per-ScanMode threshold table in mini_semantic.py (FPR-01 + FPR-02)
- [ ] 05-02-PLAN.md — Thread ScanMode through hooks.py and scanner.py, verify combined pipeline FPR (FPR-01 + FPR-02)

**Success Criteria** (what must be TRUE):
  1. Per-context thresholds are implemented and configurable — not a single global threshold
  2. Sliding-window FPR on agent_instructions drops below 33% (current baseline)
  3. Sliding-window FPR on workflows drops below 24% (current baseline)
  4. All existing 1,053 tests continue to pass with context-aware threshold changes in place

### Phase 6: Pattern Expansion
**Goal**: CloneGuard's Tier 0 coverage includes 51 new patterns across 11 previously identified gaps and a new Log-To-Leak exfiltration category
**Depends on**: Phase 5
**Requirements**: PAT-01, PAT-02
**Success Criteria** (what must be TRUE):
  1. 51 new patterns are merged into the pattern library and correctly categorized across 11 gap categories
  2. Log-To-Leak exfiltration patterns exist as a distinct category and fire on known log-injection exfiltration payloads
  3. Pattern test suite passes with no regressions on the existing 193 patterns
  4. New patterns carry mode restrictions where appropriate (strict/standard/lenient) consistent with existing convention
**Plans**: TBD

### Phase 7: Tool Call Monitoring
**Goal**: CloneGuard's hook layer detects anomalous tool call sequences consistent with prompt-injection-driven lateral movement or exfiltration, raising attacker cost without adding blocking latency to the hot path
**Depends on**: Phase 6
**Requirements**: TCM-01
**Success Criteria** (what must be TRUE):
  1. A CaMeL-lite behavioral monitor is implemented at the hook layer and fires on known anomalous tool call sequences (e.g., unexpected network calls following file reads)
  2. The monitor does not add blocking latency above the 25ms budget for the existing Tier 0+1.5 pipeline
  3. Monitor events are logged with sufficient context for a security analyst to reconstruct the sequence
  4. All existing 1,053 tests continue to pass with the monitor integrated
**Plans**: TBD

## Progress

**Execution Order:** 4 → 5 → 6 → 7

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Transferability Gate | v0.3 | 2/2 | Complete (PIVOT) | 2026-03-10 |
| 2. Adversarial Hardening | v0.3 | 3/3 | Complete | 2026-03-10 |
| 3. Adversarial Benchmark & Publication | v0.3 | 3/3 | Complete | 2026-03-10 |
| 4. FPR Investigation & Documentation | 2/2 | Complete   | 2026-03-11 | - |
| 5. FPR Tuning | 2/2 | Complete   | 2026-03-11 | - |
| 6. Pattern Expansion | v0.4 | 0/TBD | Not started | - |
| 7. Tool Call Monitoring | v0.4 | 0/TBD | Not started | - |
