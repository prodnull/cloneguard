---
phase: 03-adversarial-benchmark-and-publication
verified: 2026-03-10T23:55:00Z
status: gaps_found
score: 3/4 success criteria verified
gaps:
  - truth: "Adaptive attacks reported alongside non-adaptive results, improvement ceiling documented"
    status: partial
    reason: "REQUIREMENTS.md still shows BENCH-02 as '[ ] Pending' and the traceability table as 'Pending' — the checkbox was never updated after plan 03-01 completed. The artifact and results exist and are correctly cited in SECURITY.md, but the requirements document is inconsistent."
    artifacts:
      - path: ".planning/REQUIREMENTS.md"
        issue: "BENCH-02 checkbox is unchecked ([ ]) and traceability row shows 'Pending' — not updated after completion"
    missing:
      - "Update BENCH-02 checkbox to [x] in REQUIREMENTS.md"
      - "Update BENCH-02 traceability row from 'Pending' to 'Complete' in REQUIREMENTS.md"
---

# Phase 3: Adversarial Benchmark and Publication — Verification Report

**Phase Goal:** Publish empirical evidence of adversarial hardening effectiveness with honest "raises attacker cost" framing, including adaptive attacks against the hardened model.
**Verified:** 2026-03-10T23:55:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Adversarial benchmark (185 mal + 234 benign) re-run with full hardened pipeline; results table with recall/FPR/ASR before and after hardening published to `docs/results/` | VERIFIED | `docs/results/hardened-benchmark-phase3-2026-03-10.json` exists (1596 bytes), contains `recall.overall=0.9027`, `asr`, `fpr`, `delta_from_v3`. Phase 2 baseline preserved at `hardened-benchmark-2026-03-10.json`. |
| 2 | Adaptive attacks (PWWS against hardened model) run and reported alongside non-adaptive results; improvement ceiling documented | PARTIAL | Artifact exists: `adaptive-pwws-benchmark-2026-03-10.json` with `adaptive_asr=0.2027`, CI 14.6-27.5%, per-category breakdown, `distinguishing_note` clearly separating from round-2 ASR. Ceiling documented in SECURITY.md (line 270: "adaptive ASR 20.3% is higher than training-time benchmark ASR 9.7%"). HOWEVER: REQUIREMENTS.md BENCH-02 checkbox remains `[ ]` (unchecked) and traceability table still shows "Pending" — documentation inconsistency. |
| 3 | Correlated failure analysis identifies samples undetected by both Tier 0 and Tier 1.5; documented as known limitations | VERIFIED | `docs/results/correlated-failures-2026-03-10.json` exists with 18 both-miss samples. Structural categories dominate: fragmentation 11/20, implicit_instruction 5/20, truncation 2/20. Documented in SECURITY.md (line 307) as known limitations with narrative context. |
| 4 | All published results use "raises attacker cost" framing; "prevents," "blocks," "secure" absent from benchmark writeup, HuggingFace model card, release notes | VERIFIED | `tests/test_framing.py` (8 tests) passes. Compound-pattern audit allows technical operational "blocks" (e.g. "hook blocks writes") but catches CloneGuard-attributed prevention claims. All 8 framing tests pass. SECURITY.md line 18: "raises the cost, skill, and risk of discovery." |

**Score:** 3/4 truths verified (1 partial due to requirements documentation gap)

---

### Required Artifacts

#### Plan 03-01 Artifacts

| Artifact | Min Lines | Status | Details |
|----------|-----------|--------|---------|
| `scripts/adaptive_pwws_benchmark.py` | 80 | VERIFIED | 482 lines. Loads `mini_semantic.onnx` via `_DEFAULT_MODEL_PATH`. References `malicious_corpus.json`. Measurement-only, no training data writes. |
| `tests/test_adaptive_benchmark.py` | 30 | VERIFIED | 270 lines. 23 tests. Contains fixture + 2 integration tests against live output. All pass. |
| `docs/results/adaptive-pwws-benchmark-2026-03-10.json` | — | VERIFIED | 1839 bytes. Contains `adaptive_asr`, `per_category` (10 categories), `confidence_interval`, `metadata.model_version="v4"`, `metadata.distinguishing_note`. |

#### Plan 03-02 Artifacts

| Artifact | Requirement | Status | Details |
|----------|-------------|--------|---------|
| `docs/results/hardened-benchmark-phase3-2026-03-10.json` | contains "recall" | VERIFIED | 1596 bytes. `recall.overall=0.9027`, `fpr`, `asr`, `delta_from_v3` all present. Exact delta=0.0000 from Phase 2 confirms reproducibility. |
| `docs/results/correlated-failures-2026-03-10.json` | contains "both_miss_samples" | VERIFIED | 7121 bytes. 18 both-miss samples, each with: `id`, `category`, `text_preview`, `tier0_detected=False`, `tier15_verdict="SAFE"`, `tier15_score`, `anomaly_score`, `anomaly_flagged`. |
| `tests/test_correlated_failures.py` | 25 lines | VERIFIED | 112 lines. 7 schema validation tests covering required fields, tier verdict correctness, count consistency, per-category breakdown. All pass. |

#### Plan 03-03 Artifacts

| Artifact | Min Lines | Status | Details |
|----------|-----------|--------|---------|
| `docs/SECURITY.md` | contains "raises attacker cost" | VERIFIED | 366 lines. Contains "raises the cost" (line 18). v0.3.0 Adversarial Hardening section present. v3/v4 comparison table at line 251. Adaptive ASR and correlated failure summary both present. |
| `docs/publications/2026-03-10-medium-adversarial-hardening.md` | 150 | VERIFIED | 319 lines. Gate failure narrative through adaptive ceiling. Adaptive ASR 20.3% at line 190. Per-category breakdown. Mahalanobis negative result. Correlated failures. |
| `docs/publications/2026-03-10-linkedin-adversarial-hardening.md` | 20 | VERIFIED | 48 lines. v4 headline numbers, honest framing, links to Medium and GitHub. |
| `docs/publications/venue-assessment.md` | 40 | VERIFIED | 157 lines. arXiv + IEEE SecDev/NDSS workshop recommendation. Strengths/weaknesses for peer review. Reproducibility assessment. |
| `docs/publications/hf-model-card-v4-draft.md` | 40 | VERIFIED | 273 lines. Adaptive ASR 20.3% at line 86. "raises the cost" framing at line 44. FPR caveat, Mahalanobis negative result. |
| `docs/publications/v0.3.0-release-notes.md` | 20 | VERIFIED | 147 lines. Hardening summary, key metrics, adaptive ASR, honest framing. |
| `tests/test_framing.py` | 20 | VERIFIED | 347 lines. 8 tests. Compound-pattern prohibited word scan across SECURITY.md, MINI-SEMANTIC-MODEL.md, all docs/publications/ files. All 8 pass. |

---

### Key Link Verification

#### Plan 03-01 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `scripts/adaptive_pwws_benchmark.py` | `src/cloneguard/model/mini_semantic.onnx` | `MiniLMOnnxWrapper loads v4 ONNX` | WIRED | Line 52: `_DEFAULT_MODEL_PATH = str(_REPO_ROOT / "src" / "cloneguard" / "model" / "mini_semantic.onnx")` |
| `scripts/adaptive_pwws_benchmark.py` | `data/benchmark/malicious_corpus.json` | `PWWS attacks this corpus` | WIRED | Line 53: `_DEFAULT_CORPUS = str(_REPO_ROOT / "data" / "benchmark" / "malicious_corpus.json")` |

#### Plan 03-02 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `scripts/hardened_benchmark.py` | `docs/results/correlated-failures-2026-03-10.json` | `--correlated-failures arg` | WIRED | Line 462: `"both_miss_samples": both_miss_samples` in output dict. `--correlated-failures` CLI arg at line 173. |
| `scripts/hardened_benchmark.py` | `src/cloneguard/mini_semantic.py` | `MiniSemanticClassifier` | WIRED | Line 206: `from cloneguard.mini_semantic import MiniSemanticClassifier`. Line 208: `classifier = MiniSemanticClassifier()` |
| `scripts/hardened_benchmark.py` | `data/benchmark/malicious_corpus.json` | `malicious_corpus` | WIRED | Line 168: `default=_ROOT / "data/benchmark/malicious_corpus.json"` |
| `scripts/hardened_benchmark.py` | `data/benchmark/benign_eval_751.json` | `benign_eval_751` | WIRED | Line 173: `default=_ROOT / "data/benchmark/benign_eval_751.json"` |

#### Plan 03-03 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `docs/SECURITY.md` | `docs/results/hardened-benchmark-phase3-2026-03-10.json` | `Numbers copied from authoritative JSON` | VERIFIED | Lines 251-254: v3/v4 comparison table with recall 90.3%, Tier 1.5 FPR 9.2%, ASR 9.7% — all match JSON `recall.overall=0.9027`, `fpr.tier15=0.092`, `asr.all=0.097`. |
| `docs/SECURITY.md` | `docs/results/correlated-failures-2026-03-10.json` | `Correlated failure summary` | VERIFIED | Lines 307, 324: both_miss referenced. Line 324 explicitly names the source file. |
| `docs/publications/2026-03-10-medium-adversarial-hardening.md` | `docs/results/adaptive-pwws-benchmark-2026-03-10.json` | `Adaptive ASR from Plan 01` | VERIFIED | Line 190: "Adaptive ASR: 20.3%" (CI: 14.6%-27.5%) matches JSON `adaptive_asr=0.2027`, CI values exact. |
| `tests/test_framing.py` | `docs/SECURITY.md` | `Grep for prohibited words` | VERIFIED | Test suite scans SECURITY.md explicitly. 8/8 tests pass, confirming no prohibited words. |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| BENCH-01 | 03-02 | Re-run adversarial benchmark (185 malicious + 234 benign) with full hardened pipeline | SATISFIED | `hardened-benchmark-phase3-2026-03-10.json` exists, delta=0.0000 from Phase 2 confirms reproducibility. 03-02-SUMMARY marks `requirements-completed: [BENCH-01, BENCH-03]`. |
| BENCH-02 | 03-01 | Run adaptive attacks (PWWS against hardened model) and report alongside non-adaptive results | SATISFIED (artifact) / DOCUMENTATION GAP | Adaptive benchmark runs, results in `adaptive-pwws-benchmark-2026-03-10.json`, reported in SECURITY.md alongside non-adaptive (9.7%). 03-01-SUMMARY marks `requirements-completed: [BENCH-02]`. BUT: REQUIREMENTS.md checkbox still `[ ]` and traceability row still "Pending". |
| BENCH-03 | 03-02 | Correlated failure analysis — identify samples Tier 0 AND Tier 1.5 both miss | SATISFIED | `correlated-failures-2026-03-10.json`: 18/185 both-miss samples identified. Structural categories dominate (fragmentation 55%, implicit_instruction 25%). |
| BENCH-04 | 03-03 | Publish results with honest "raises attacker cost" framing | SATISFIED | Framing audit 8/8 passes. "raises the cost" in SECURITY.md line 18. No prohibited CloneGuard-attributed prevention claims in any scanned file. |

**Orphaned requirements check:** No Phase 3 requirements exist in REQUIREMENTS.md beyond BENCH-01 through BENCH-04. All 4 are accounted for.

---

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `.planning/REQUIREMENTS.md` | `[ ] BENCH-02` — checkbox unchecked; traceability row "Pending" | Warning | Documentation inconsistency only. Artifact exists and works. No functional impact. |

No stub implementations, TODO markers, or empty handlers detected in any committed code artifact. All benchmark scripts have real implementations; all test files have substantive assertions.

---

### Human Verification Required

The phase plan (03-03 Task 3) included a blocking human review checkpoint, and the SUMMARY records it as approved. The following items have already been human-reviewed per the SUMMARY:

1. Narrative accuracy of Medium Part 2 article
2. Tone and conciseness of LinkedIn post
3. Honesty of venue assessment
4. v4 number accuracy in SECURITY.md
5. v4 model details in MINI-SEMANTIC-MODEL.md
6. HuggingFace model card framing accuracy
7. v0.3.0 release notes framing

No additional human verification items identified programmatically.

---

### Gaps Summary

**One gap found:** The REQUIREMENTS.md file was not updated after Plan 03-01 completed BENCH-02. The checkbox `[ ] BENCH-02` should be `[x] BENCH-02` and the traceability table row should read "Complete" rather than "Pending". This is a documentation-only inconsistency — the adaptive benchmark artifact exists, the tests pass (30/30), the numbers appear correctly in SECURITY.md and all publication drafts, and the 03-01-SUMMARY correctly records `requirements-completed: [BENCH-02]`.

This gap does not block the phase goal ("publish empirical evidence of adversarial hardening effectiveness"). The publication artifacts are complete and correct. The gap is limited to requirements traceability bookkeeping.

**Fix required:** Update `.planning/REQUIREMENTS.md` lines referencing BENCH-02 to mark as complete.

---

### Test Suite Health

Full test suite: **1053 passed, 16 skipped** (no failures).
- `tests/test_adaptive_benchmark.py`: 23/23 pass
- `tests/test_correlated_failures.py`: 7/7 pass
- `tests/test_framing.py`: 8/8 pass

Note: 1 pre-existing latency test failure (`test_latency.py`, p95 27-32ms vs 25ms limit) was present before Phase 3 and is out of scope. The 1053 count excludes this test (18 skipped includes pre-existing skips).

---

_Verified: 2026-03-10T23:55:00Z_
_Verifier: Claude (gsd-verifier)_
