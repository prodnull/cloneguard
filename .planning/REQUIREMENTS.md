# Requirements: CloneGuard v0.4

**Defined:** 2026-03-10
**Core Value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on

## v0.4 Requirements

### Investigation

- [ ] **INV-01**: Empirically measure whether security-context markers (authorization preambles, blue-team framing) increase Tier 0+1.5 FPR vs identical content without markers
- [ ] **INV-02**: Audit 4 strict-only patterns (CI-004, CI-006, SC-001, MCP-005) against corpus of legitimate defensive security content (pentest frameworks, IR playbooks, hardening scripts)
- [ ] **INV-03**: Document findings — structural FPR limits, authorization paradox presence/absence in our pipeline

### FPR Tuning

- [ ] **FPR-01**: Implement context-aware thresholds (per-context rather than global threshold, informed by INV-01/INV-02 findings)
- [ ] **FPR-02**: Reduce sliding-window FPR on agent_instructions (currently 33%) and workflows (currently 24%)

### Pattern Expansion

- [ ] **PAT-01**: Add 51 new patterns covering 11 identified gaps
- [ ] **PAT-02**: Add Log-To-Leak exfiltration patterns

### Documentation

- [ ] **DOC-01**: Cite Campbell et al. 2026 in SECURITY.md threat model (asymmetric burden, embedding-space structural limits)
- [ ] **DOC-02**: Update Medium Part 2 draft with Campbell findings to contextualize FPR results

### Tool Call Monitoring

- [ ] **TCM-01**: Implement tool call behavioral monitoring at hook layer (CaMeL-lite)

## Future Requirements

- **MULTI-01**: Full multilingual pattern and classifier coverage (GitHub issue #5)

## Out of Scope

| Feature | Reason |
|---------|--------|
| MicroVM sandbox | Wrong threat model for semantic attacks (v0.4 research) |
| eBPF integration | Unsound verifier, can't see guest syscalls (v0.4 research) |
| Retraining MiniLM base model | Out of scope since v0.3 |
| DeBERTa ensemble | Invalidated by transferability gate (v0.3) |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INV-01 | Phase 4 | Pending |
| INV-02 | Phase 4 | Pending |
| INV-03 | Phase 4 | Pending |
| DOC-01 | Phase 4 | Pending |
| DOC-02 | Phase 4 | Pending |
| FPR-01 | Phase 5 | Pending |
| FPR-02 | Phase 5 | Pending |
| PAT-01 | Phase 6 | Pending |
| PAT-02 | Phase 6 | Pending |
| TCM-01 | Phase 7 | Pending |

**Coverage:**
- v0.4 requirements: 10 total
- Mapped to phases: 10
- Unmapped: 0

---
*Requirements defined: 2026-03-10*
*Last updated: 2026-03-10 after roadmap creation*
