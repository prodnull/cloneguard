---
phase: "04"
plan: "02"
subsystem: documentation
tags: [fpr, authorization-paradox, campbell, security-doc, medium-publication, inv-03, doc-01, doc-02]
dependency_graph:
  requires: ["04-01"]
  provides: ["INV-03", "DOC-01", "DOC-02"]
  affects: ["docs/SECURITY.md", "docs/results/fpr-investigation-findings.md", "docs/publications/2026-03-10-medium-adversarial-hardening.md"]
tech_stack:
  added: []
  patterns: ["grep assertion tests for SECURITY.md citation", "gitignored findings doc pattern"]
key_files:
  created:
    - docs/results/fpr-investigation-findings.md
    - tests/test_security_doc.py
  modified:
    - docs/SECURITY.md
decisions:
  - "Frame Campbell citation as independent empirical test, not validation of CloneGuard — honest framing per RESEARCH.md Pitfall 5"
  - "Add 4 test assertions in test_security_doc.py including INV-01 measured values, not just citation presence"
  - "Medium draft update rephrases 'less secure' to 'detection regression' to satisfy framing violation test"
metrics:
  duration: "~15 minutes"
  completed: "2026-03-11"
  tasks_completed: 2
  files_changed: 3
---

# Phase 4 Plan 02: Documentation Deliverables Summary

Authorization paradox confirmed in Tier 1.5 (+12.7pp FPR increase from auth preambles); INV-03 findings doc written, SECURITY.md updated with Campbell et al. ICLR 2026 citation, and Medium Part 2 draft extended with structural FPR limits section.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Write INV-03 findings doc, SECURITY.md Campbell citation, test_security_doc.py | 80a3b69 | docs/SECURITY.md, tests/test_security_doc.py (docs/results/fpr-investigation-findings.md gitignored) |
| 2 | Update Medium Part 2 draft with Campbell contextualization | (gitignored — no commit) | docs/publications/2026-03-10-medium-adversarial-hardening.md (local only) |

## What Was Built

### INV-03 Findings Document (docs/results/fpr-investigation-findings.md)

Internal findings record (~230 lines) covering:
- INV-01: Authorization paradox CONFIRMED — Tier 1.5 FPR 9.25% → 21.93% (+12.7pp) across all 8 content types. Tier 0 unaffected (delta = 0.0pp all types). Largest delta: env_config +41.8pp, build_script +38.2pp, config +14.5pp.
- INV-02: Strict-pattern audit — MCP-005 21% FPR, CI-006 11% FPR, SC-001 3%, CI-004 1% on 100 defensive security corpus samples. MCP-005 and CI-006 flagged as Phase 5 priority candidates.
- Structural FPR categorization: regex FPR (pattern-driven, auth-framing immune), semantic FPR (embedding proximity, auth-amplified), information-theoretic FPR (design-space ceiling).
- Campbell et al. relevance section with honest framing — independent test, not a replication.

### SECURITY.md Update (docs/SECURITY.md)

New section "Structural FPR Limits and the Authorization Paradox" added before "Known Limitations." Contains:
- Campbell et al. (ICLR 2026, arXiv:2603.01246) citation with mechanism description (embedding-space proximity AUC 0.827 vs keyword AUC 0.572)
- INV-01 measured finding: +12.7pp Tier 1.5 FPR increase (9.25% → 21.93%)
- INV-02 summary: MCP-005 21%, CI-006 11% FPR on defensive security content
- Explicit framing distinction: Campbell describes general mechanism; INV-01 is an independent test of whether it applies to CloneGuard's pipeline. No over-claim.

### test_security_doc.py (tests/test_security_doc.py)

4 test assertions:
1. `test_campbell_citation`: citation text, arXiv ID, "authorization paradox," "embedding" all present
2. `test_security_doc_no_overclaim`: "validates cloneguard" and "proves cloneguard" absent
3. `test_inv01_finding_present`: measured values (12.7, 9.25%/9.2%, 21.93%/21.9%) present
4. `test_honest_framing_independent_test`: "independent" or "our" present to distinguish CloneGuard investigation from Campbell's study

All 4 pass. Full suite: 1095 passed, 16 skipped.

### Medium Part 2 Draft Update (docs/publications/2026-03-10-medium-adversarial-hardening.md)

New section added near end of article: "The Structural Limits of Detection: Why False Positives Are Not Just a Tuning Problem." Covers:
- Campbell et al. authorization paradox mechanism in accessible (Medium-appropriate) language
- INV-01 measured results: +12.7pp Tier 1.5 FPR increase for all 8 content types
- Honest framing: usability concern, not detection regression; does not lower attacker bar
- Per-context thresholds as the Phase 5 mitigation path
- INV-02 strict-pattern audit summary (MCP-005 21%, CI-006 11%)
- Framing section: "raises attacker cost" positioning for Phase 5 communication

File is local-only (gitignored). Not committed per project rules. User publishes manually.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Framing violation test failure**
- **Found during:** Task 2 verification (full test suite run)
- **Issue:** The phrase "This does not make CloneGuard less secure" in the Medium draft triggered `tests/test_framing.py::test_all_publications_no_prohibited_framing` — "secure" is in the prohibited framing word list per project conventions
- **Fix:** Replaced with "This is a usability concern, not a detection regression" — equivalent meaning, framing-compliant
- **Files modified:** docs/publications/2026-03-10-medium-adversarial-hardening.md
- **Commit:** Not applicable (file is gitignored)

**2. [Rule 1 - Bug] Ruff lint: unused pytest import + unsorted import block**
- **Found during:** Task 1 first commit attempt
- **Issue:** `import pytest` was unused; import block sorting violated ruff I001
- **Fix:** Removed `pytest` import; ruff format applied
- **Files modified:** tests/test_security_doc.py
- **Commit:** Fixed before Task 1 commit (80a3b69)

## Self-Check

- [x] `docs/results/fpr-investigation-findings.md` exists: YES
- [x] `docs/SECURITY.md` contains "Campbell et al.": YES
- [x] `docs/SECURITY.md` contains "arXiv:2603.01246": YES
- [x] `docs/SECURITY.md` contains "authorization paradox": YES
- [x] `tests/test_security_doc.py` passes (4/4): YES
- [x] Medium draft contains "Campbell" and "authorization paradox": YES
- [x] Full suite (1095 passed, 16 skipped, 0 failures): YES
- [x] Commit 80a3b69 exists: YES

## Self-Check: PASSED
