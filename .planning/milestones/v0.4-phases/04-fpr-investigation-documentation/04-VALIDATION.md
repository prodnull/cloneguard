---
phase: 4
slug: fpr-investigation-documentation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x |
| **Config file** | `pyproject.toml` (project root) |
| **Quick run command** | `pytest tests/ -x -q --tb=short` |
| **Full suite command** | `pytest tests/ --tb=short` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -x -q --tb=short`
- **After every plan wave:** Run `pytest tests/ --tb=short`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 4-01-01 | 01 | 1 | INV-01 | benchmark script | `python scripts/fpr_investigation.py --output docs/results/fpr-investigation-2026-03-10.json` | ❌ W0 | ⬜ pending |
| 4-01-02 | 01 | 1 | INV-02 | benchmark + schema test | `pytest tests/test_fpr_investigation.py -x` | ❌ W0 | ⬜ pending |
| 4-02-01 | 02 | 2 | INV-03 | manual (file existence) | `test -f docs/results/fpr-investigation-findings.md` | ❌ W0 | ⬜ pending |
| 4-02-02 | 02 | 2 | DOC-01 | grep assertion | `pytest tests/test_security_doc.py::test_campbell_citation -x` | ❌ W0 | ⬜ pending |
| 4-02-03 | 02 | 2 | DOC-02 | manual (local file) | `test -f docs/publications/2026-03-10-medium-adversarial-hardening.md` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `scripts/fpr_investigation.py` — INV-01 benchmark + INV-02 strict-pattern audit, outputs structured JSON
- [ ] `tests/test_fpr_investigation.py` — schema validation for `docs/results/fpr-investigation-2026-03-10.json`
- [ ] `tests/test_security_doc.py::test_campbell_citation` — verify SECURITY.md contains Campbell citation with required text fragments
- [ ] `data/benchmark/defensive_security_corpus.json` — ~80-120 samples of legitimate pentest/IR/hardening content for INV-02

*Existing infrastructure covers pytest framework — Wave 0 adds test files and benchmark script only.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| INV-03 findings document content quality | INV-03 | Findings doc requires human judgment on framing accuracy | Review `docs/results/fpr-investigation-findings.md` for accurate characterization of structural FPR limits and authorization paradox presence/absence |
| Medium Part 2 draft update | DOC-02 | Local file, gitignored, content review is editorial | Review `docs/publications/2026-03-10-medium-adversarial-hardening.md` for Campbell et al. contextualization section |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
