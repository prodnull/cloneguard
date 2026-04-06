---
phase: 04-fpr-investigation-documentation
verified: 2026-03-11T05:10:00Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 4: FPR Investigation & Documentation — Verification Report

**Phase Goal:** Users can see empirically grounded findings on whether the authorization paradox manifests in CloneGuard's pipeline, with Campbell et al. cited in the threat model
**Verified:** 2026-03-11T05:10:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A benchmark result exists comparing FPR with and without security-context markers on Tier 0+1.5 | VERIFIED | `docs/results/fpr-investigation-2026-03-10.json` — Tier 0 and Tier 1.5 FPR reported separately with baseline vs auth-marker deltas for all content types |
| 2 | All 4 strict-only patterns (CI-004, CI-006, SC-001, MCP-005) audited against legitimate defensive security content with findings recorded | VERIFIED | INV-02 in results JSON: CI-004 1%, SC-001 3%, CI-006 11%, MCP-005 21% FPR on 100-sample corpus |
| 3 | SECURITY.md cites Campbell et al. 2026 with accurate framing of asymmetric burden and embedding-space structural limits | VERIFIED | Lines 329-352 of `docs/SECURITY.md` — "Structural FPR Limits and the Authorization Paradox" section; arXiv:2603.01246 cited; explicit framing distinction stating Campbell does not validate CloneGuard |
| 4 | Medium Part 2 draft is updated to contextualize FPR results using Campbell findings | VERIFIED | `docs/publications/2026-03-10-medium-adversarial-hardening.md` contains "The Structural Limits of Detection" section with Campbell reference and +12.7pp INV-01 finding |
| 5 | INV-03 findings document is written: structural FPR limits characterized and authorization paradox presence/absence stated with supporting data | VERIFIED | `docs/results/fpr-investigation-findings.md` (282 lines) — covers INV-01 (+12.7pp Tier 1.5 delta), INV-02 per-pattern table, structural FPR categorization, and explicit paradox determination |

**Score: 5/5 truths verified**

---

## Required Artifacts

### Plan 01 Artifacts

| Artifact | min_lines | Actual Lines | Status | Details |
|----------|-----------|--------------|--------|---------|
| `scripts/fpr_investigation.py` | 150 | 435 | VERIFIED | INV-01 + INV-02 logic present; loads `benign_eval_751.json` and `defensive_security_corpus.json`; imports `PatternEngine` and `MiniSemanticClassifier`; argparse with `--output`; structured JSON output |
| `data/benchmark/defensive_security_corpus.json` | 50 | 702 | VERIFIED | 100 samples, all `content_type: agent_instructions`, 6 categories (pentest, ir, hardening, cicd_in_instructions, security_tooling, mcp_config), required fields present |
| `tests/test_fpr_investigation.py` | 40 | 280 | VERIFIED | 13 tests covering schema validation (gated on file existence) + always-run corpus structure assertions |
| `docs/results/fpr-investigation-2026-03-10.json` | — | 6313 bytes | VERIFIED | All required schema keys present; all FPR floats in [0.0, 1.0]; `authorization_paradox_detected: true`; both `inv_01` and `inv_02` sections complete |

### Plan 02 Artifacts

| Artifact | Requirement | Status | Details |
|----------|-------------|--------|---------|
| `docs/results/fpr-investigation-findings.md` | INV-03, min_lines: 80 | VERIFIED | 282 lines; structured INV-01/INV-02 analysis; Campbell relevance section with honest framing; paradox confirmed present |
| `docs/SECURITY.md` | DOC-01, contains: "Campbell et al." | VERIFIED | Contains "Campbell et al.", "arXiv:2603.01246", "authorization paradox", "embedding" — all assertions pass |
| `docs/publications/2026-03-10-medium-adversarial-hardening.md` | DOC-02, contains: "authorization paradox" | VERIFIED | New section added; "Campbell" and "authorization paradox" present; framing-compliant (no prohibited words) |
| `tests/test_security_doc.py` | DOC-01 test, min_lines: 15 | VERIFIED | 53 lines; 4 assertions — citation presence, no over-claim, measured values, honest framing |

---

## Key Link Verification

### Plan 01 Key Links

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `scripts/fpr_investigation.py` | `data/benchmark/benign_eval_751.json` | loads existing benign corpus as baseline | WIRED | Line 355: default path set to `benign_eval_751.json` |
| `scripts/fpr_investigation.py` | `data/benchmark/defensive_security_corpus.json` | loads defensive security corpus for INV-02 | WIRED | Line 361: default path set to `defensive_security_corpus.json` |
| `scripts/fpr_investigation.py` | `src/cloneguard/scanner.py` | PatternEngine.scan() for Tier 0 | WIRED | Line 65: `from cloneguard.patterns import PatternEngine` |
| `scripts/fpr_investigation.py` | `src/cloneguard/mini_semantic.py` | MiniSemanticModel for Tier 1.5 | WIRED | Line 70: `from cloneguard.mini_semantic import MiniSemanticClassifier` |
| `tests/test_fpr_investigation.py` | `docs/results/fpr-investigation-2026-03-10.json` | validates output schema | WIRED | Line 23: `_RESULTS_PATH` set; pytest.skip used if file absent |

### Plan 02 Key Links

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `docs/results/fpr-investigation-findings.md` | `docs/results/fpr-investigation-2026-03-10.json` | references and summarizes investigation data | WIRED | Line 5 of findings doc: data source declared; concrete numbers (+12.7pp, 9.25%, 21.93%) throughout |
| `docs/SECURITY.md` | `docs/results/fpr-investigation-findings.md` | condensed public version of internal findings | WIRED | Campbell section contains measured values from investigation |
| `tests/test_security_doc.py` | `docs/SECURITY.md` | grep assertion for citation text | WIRED | `SECURITY_MD = Path(...) / "docs" / "SECURITY.md"` — 4 assertions directly read file |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| INV-01 | 04-01 | Measure FPR with/without security-context markers on Tier 0 and Tier 1.5 separately | SATISFIED | Results JSON contains `tier0` and `tier15` sub-objects with `baseline_fpr_by_content_type`, `auth_marker_fpr_by_content_type`, `delta_by_content_type`; Tier 0 unaffected (delta ~0), Tier 1.5 +12.7pp |
| INV-02 | 04-01 | Audit CI-004, CI-006, SC-001, MCP-005 against defensive security corpus | SATISFIED | `per_pattern` object covers all 4 patterns; per-pattern FPR computed over 100-sample corpus |
| INV-03 | 04-02 | Document structural FPR limits and authorization paradox finding | SATISFIED | `docs/results/fpr-investigation-findings.md` (282 lines) with explicit "paradox confirmed present" determination |
| DOC-01 | 04-02 | Cite Campbell et al. 2026 in SECURITY.md with accurate framing | SATISFIED | Section added; `test_campbell_citation` and `test_security_doc_no_overclaim` both pass |
| DOC-02 | 04-02 | Update Medium Part 2 draft with Campbell contextualization | SATISFIED | New section "The Structural Limits of Detection" added to draft; contains measured INV-01 data |

**Orphaned requirements check:** No additional Phase 4 requirements found in REQUIREMENTS.md beyond the 5 claimed. FPR-01, FPR-02, PAT-01, PAT-02, TCM-01 are correctly mapped to Phases 5-7.

---

## Anti-Patterns Found

No anti-patterns detected. Scan of all phase-modified files (`scripts/fpr_investigation.py`, `tests/test_fpr_investigation.py`, `tests/test_security_doc.py`, `docs/SECURITY.md`) returned no TODO/FIXME/placeholder comments, no empty implementations, and no stub returns.

---

## Commit Verification

| Commit | Hash | Status | Tracked Files |
|--------|------|--------|---------------|
| feat(04-01): defensive corpus + investigation script | `aa73f50` | EXISTS | `data/benchmark/defensive_security_corpus.json`, `scripts/fpr_investigation.py`, `tests/test_fpr_investigation.py` (3 files, 1417 insertions) |
| feat(04-02): INV-03 findings, SECURITY.md citation, test_security_doc.py | `80a3b69` | EXISTS | `docs/SECURITY.md`, `tests/test_security_doc.py` (2 files, 87 insertions) |

Gitignored files confirmed NOT committed: `docs/results/fpr-investigation-2026-03-10.json`, `docs/results/fpr-investigation-findings.md`, `docs/publications/2026-03-10-medium-adversarial-hardening.md` — all confirmed via `.gitignore` rules.

---

## Human Verification Required

### 1. SECURITY.md Section Placement and Readability

**Test:** Open `docs/SECURITY.md` and read the "Structural FPR Limits and the Authorization Paradox" section in context
**Expected:** Section reads naturally in the document flow, framing is defensively honest (describes what the investigation found, not what Campbell proves about CloneGuard), and is appropriate for a public-facing security document
**Why human:** Prose quality, tone consistency, and framing nuance cannot be verified programmatically

### 2. Medium Draft Section Quality

**Test:** Read the "The Structural Limits of Detection" section in `docs/publications/2026-03-10-medium-adversarial-hardening.md`
**Expected:** Accessible to a technical-but-not-academic Medium audience; +12.7pp number is contextualized clearly; section integrates smoothly with preceding content
**Why human:** Editorial judgment on accessibility, flow, and audience appropriateness cannot be automated

---

## Gaps Summary

No gaps. All 5 success criteria from ROADMAP.md are satisfied. All 5 requirement IDs (INV-01, INV-02, INV-03, DOC-01, DOC-02) have implementation evidence. Key links are wired at all three levels. Tests pass (17/17 in the affected test files; full suite 1095 passed, 16 skipped per SUMMARY). No anti-patterns found.

---

_Verified: 2026-03-11T05:10:00Z_
_Verifier: Claude (gsd-verifier)_
