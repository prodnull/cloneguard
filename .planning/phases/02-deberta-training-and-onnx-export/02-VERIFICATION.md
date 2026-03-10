---
phase: 02-deberta-training-and-onnx-export
verified: 2026-03-10T20:30:00Z
status: human_needed
score: 3/4 success criteria numerically met; SC3 Mahalanobis detection rate misses literature projection (2.7% vs 60% target) — experimentally disclosed, per-ROADMAP expected behavior
re_verification: false
human_verification:
  - test: "Review SC3 miss before Phase 3 publication"
    expected: "Phase 3 publication explicitly reports Mahalanobis detection rate as 2.7%, not 60%, with 'marginal orthogonal signal' framing — not 'anomaly detection layer'"
    why_human: "The ROADMAP permits SC3 miss with honest reporting. A human must confirm the Phase 3 publication plan acknowledges this honestly before the benchmark writeup is finalized."
---

# Phase 2: Adversarial Hardening Verification Report

**Phase Goal:** Reduce PWWS attack success rate from 58% to ≤35% on vocabulary-attack categories through adversarial training, and add Mahalanobis anomaly detection as an orthogonal defense signal. All improvement targets are projections from literature that must be validated experimentally.
**Verified:** 2026-03-10T20:30:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | PWWS ASR ≤35% on vocabulary-attack categories (synonym_substitution, social_engineering, counter_defensive) | VERIFIED | `hardened-benchmark-2026-03-10.json`: `asr.vocabulary_attacks = 0.0` (0% — exceeds target); overall ASR 9.7% |
| 2 | Clean accuracy (5-fold CV) ≥94.5% | VERIFIED | `hardening-rounds-2026-03-10.json`: `kfold_cv.accuracy_mean = 0.9451` (94.51%); `target_met = true` |
| 3 | Mahalanobis detector flags ≥60% of adversarial examples at ≤5% FPR | PARTIAL | FPR target met: 1.19% ≤ 5%. Detection rate missed: 2.7% vs 60% target. Score distributions overlap (benign mean 17.59, malicious mean 17.21). Explicitly disclosed in 02-03-SUMMARY.md as "expected given distribution overlap." ROADMAP permits miss with honest reporting. |
| 4 | Combined pipeline latency (Tier 0 + hardened Tier 1.5 + Mahalanobis) under 25ms per sample | VERIFIED | `hardened-benchmark-2026-03-10.json`: `latency.p95_ms = 18.46` (PASS); `latency.gate_pass = true` |

**Score:** 3.5/4 truths verified (SC3 FPR sub-criterion passes; detection rate sub-criterion is a measured experimental shortfall, not a code/integration failure)

---

### Required Artifacts

| Artifact | Plan | Status | Details |
|----------|------|--------|---------|
| `scripts/generate_pwws_augmentation.py` | 02-01 | VERIFIED | 457 lines (min_lines: 80 met); contains `MiniLMOnnxWrapper`, provenance generation, `build_augmentation_record()` |
| `scripts/train_mini_model.py` | 02-01 | VERIFIED | Contains `freelb_step()` at line 304, `--freelb` CLI flag, `output_names=["logits", "cls_embedding"]` at line 196 |
| `tests/test_augmentation.py` | 02-01 | VERIFIED | 6 unit tests for schema and CLI validation |
| `tests/test_train_freelb.py` | 02-01 | VERIFIED | 7 tests covering optimizer step count, ONNX output names/shapes, smoke test, backward compat |
| `data/training/pwws_adversarial_r1.jsonl` | 02-02 | VERIFIED | 88 samples; all contain `provenance.round=1`, `provenance.method="pwws"`, `provenance.original_id` |
| `data/training/pwws_adversarial_r2.jsonl` | 02-02 | VERIFIED | 44 samples; provenance round=2 confirmed |
| `data/training/dataset_v4_r1.jsonl` | 02-02 | VERIFIED | 2.5MB (6,428 samples per SUMMARY) |
| `data/training/dataset_v4_r2.jsonl` | 02-02 | VERIFIED | 2.5MB (6,472 samples per SUMMARY) |
| `src/cloneguard/model/mini_semantic.onnx` | 02-02 | VERIFIED | Binary; v4 hash `e7fb93a...` pinned in `fetch_model.py` |
| `scripts/fetch_model.py` | 02-02 | VERIFIED | `EXPECTED_SHA256 = "e7fb93add94c4eb3c7e094bc3ce466573aad3ac7433fbab29aa19a694c40edcf"` present |
| `docs/results/hardening-rounds-2026-03-10.json` | 02-02 | VERIFIED | 3 entries: round 1, round 2, summary with ASR gate decision and 5-fold CV data |
| `src/cloneguard/mahalanobis.py` | 02-03 | VERIFIED | 197 lines (min_lines: 60 met); `fit`, `score`, `is_anomalous`, `fit_threshold`, `save`, `load` all present |
| `src/cloneguard/model/mahalanobis_params.npz` | 02-03 | VERIFIED | 2.3MB; LedoitWolf-fitted per-class parameters with threshold=20.78 |
| `scripts/fit_mahalanobis.py` | 02-03 | VERIFIED | 8KB fitting script; uses v4 dual-output ONNX, 757-sample benign eval |
| `scripts/hardened_benchmark.py` | 02-03 | VERIFIED | 15KB; full hardened pipeline benchmark with before/after delta from v3 |
| `tests/test_mahalanobis.py` | 02-03 | VERIFIED | 9 unit tests; all pass |
| `tests/test_hardened_benchmark.py` | 02-03 | VERIFIED | 9 tests for HARD-04 benchmark schema; all pass |
| `tests/test_latency.py` | 02-03 | VERIFIED | 6 tests for HARD-05 latency gate + ONNX shape; all pass |
| `docs/results/hardened-benchmark-2026-03-10.json` | 02-03 | VERIFIED | All required keys present: `recall`, `fpr`, `mahalanobis`, `asr`, `latency`, `delta_from_v3` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `scripts/generate_pwws_augmentation.py` | `.venv-transfer` attack corpus | `MiniLMOnnxWrapper` reuse | WIRED | Class copied at line 148; used at line 337 |
| `scripts/train_mini_model.py` | `src/cloneguard/model/mini_semantic.onnx` | dual-output ONNX export | WIRED | `output_names=["logits", "cls_embedding"]` at line 196; assertion on output names at lines 261-262 |
| `src/cloneguard/mini_semantic.py` | `src/cloneguard/mahalanobis.py` | `MahalanobisDetector` scored at inference | WIRED | `mahalanobis.score()` at line 180; `is_anomalous()` at line 181 |
| `src/cloneguard/mini_semantic.py` | `src/cloneguard/model/mahalanobis_params.npz` | `MahalanobisDetector.load()` at classifier init | WIRED | `MAHALANOBIS_PARAMS = MODEL_DIR / "mahalanobis_params.npz"` at line 30; `MahalanobisDetector.load(MAHALANOBIS_PARAMS)` at line 95 |
| `src/cloneguard/mini_semantic.py` | `src/cloneguard/model/mini_semantic.onnx` | `outputs[1]` for cls_embedding (v4 dual-output) | WIRED | `cls_embedding = outputs[1][0] if len(outputs) > 1 else None` at line 149 |
| `src/cloneguard/mini_semantic.py` | `src/cloneguard/semantic.py` | `SemanticFinding` receives `anomaly_score` from `MiniClassification` | WIRED | Lines 354-358: `SemanticFinding(anomaly_score=result.anomaly_score, anomaly_flagged=result.anomaly_flagged)` |
| `scripts/hardened_benchmark.py` | `docs/results/hardened-benchmark-2026-03-10.json` | benchmark script produces results JSON | WIRED | JSON output confirmed to exist with all required fields |
| `scripts/fetch_model.py` | `src/cloneguard/model/mini_semantic.onnx` | SHA-256 hash pinning for v4 | WIRED | `EXPECTED_SHA256 = "e7fb93a..."` at line 28 |

---

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HARD-01 | 02-01, 02-02 | Generate PWWS adversarial examples against MiniLM v3, add to training set, retrain (2-3 rounds) | SATISFIED | 2 rounds executed; 88 r1 + 44 r2 samples with provenance; model retrained with FreeLB |
| HARD-02 | 02-01, 02-02 | Implement FreeLB embedding perturbation AT in `train_mini_model.py` (configurable ε, K=3 PGD steps) | SATISFIED | `freelb_step()` at lines 304-370; `--freelb` flag; K=3 PGD, ε=0.01, MPS float32 stability |
| HARD-03 | 02-03 | Fit per-class Mahalanobis detector on CLS embeddings, integrate into scan pipeline with configurable threshold | SATISFIED | `mahalanobis.py` 197 lines; fitted on 6,472 training samples; threshold=20.78 at 5% FPR; integrated with SAFE→SUSPICIOUS escalation |
| HARD-04 | 02-03 | Re-run adversarial benchmark with hardened pipeline, publish before/after comparison | SATISFIED | `hardened-benchmark-2026-03-10.json` with `delta_from_v3`; recall +9.8pp, ASR -10.3pp |
| HARD-05 | 02-03 | Verify combined pipeline latency under 25ms per sample on Apple M-series CPU | SATISFIED | p95 = 18.46ms (PASS); 50 measurement iterations, 5 warmup |

**Note on orphaned requirements:** BENCH-01 through BENCH-04 are mapped to Phase 3 in REQUIREMENTS.md, not Phase 2. They are not orphaned — they are deferred to the next phase as designed.

---

### Anti-Patterns Found

No blockers or stubs detected in phase 2 artifacts. Key scanned files:
- `src/cloneguard/mahalanobis.py` — no TODOs, no placeholder returns
- `scripts/generate_pwws_augmentation.py` — no stubs
- `src/cloneguard/mini_semantic.py` — SAFE→SUSPICIOUS escalation is real logic, not a placeholder

**Confirmed real implementations:** `freelb_step()` implements Zhu et al. 2020 Algorithm 1 with K=3 PGD steps, gradient accumulation, single optimizer step. `MahalanobisDetector.fit()` uses LedoitWolf covariance with shrinkage fallback.

---

### Human Verification Required

#### 1. Phase 3 publication must honestly report SC3 miss

**Test:** Review Phase 3 benchmark writeup draft before publishing to HuggingFace model card or release notes.
**Expected:** Mahalanobis section explicitly states detection rate is 2.7% (not 60%), explains that benign/malicious score distributions overlap nearly completely (means 17.59 vs 17.21), uses "marginal orthogonal signal" framing, and does not claim anomaly detection is a primary defense layer.
**Why human:** The code and integration are correct. The experimental result is an honest shortfall from a literature projection. The ROADMAP explicitly permits this: "If empirical results fall short, document actual improvement and proceed to Phase 3 with honest numbers." A human reviewer must confirm this framing is used in the Phase 3 publication before it ships, to preserve the project's intellectual honesty posture.

---

### Benchmark Results Summary

| Metric | v3 Baseline | v4 Hardened | Target | Gate |
|--------|------------|-------------|--------|------|
| Vocab ASR | ~65.7% gen rate | 0.0% | ≤35% | PASS |
| Overall ASR | 20.0% (r2 gate) | 9.7% | — | — |
| Clean accuracy (CV) | 95.51% ± 0.53% | 94.51% ± 0.67% | ≥94.5% | PASS |
| Mahalanobis detection | — | 2.7% | ≥60% | MISS (expected, disclosed) |
| Mahalanobis FPR | — | 1.19% | ≤5% | PASS |
| Latency p95 | — | 18.46ms | <25ms | PASS |
| Recall | 80.5% | 90.3% | — | +9.8pp |

**Test suite:** 1015 tests pass (from 978 at phase start, +37 new tests for phase 2 artifacts).

---

### Gaps Summary

No blocking gaps. All 5 requirements (HARD-01 through HARD-05) are satisfied per their requirement text. All artifacts exist, are substantive, and are correctly wired.

The SC3 detection rate miss (2.7% vs 60% target) is an empirical result from a literature projection that the ROADMAP explicitly permits to miss. It is properly disclosed in 02-03-SUMMARY.md with technical explanation (distribution overlap, calibration domain constraints). It does not block Phase 3 — Phase 3 should publish the actual numbers honestly. The requirement (HARD-03) is satisfied: the detector is fitted, integrated, and calibrated. The performance target was over-optimistic given single-layer CLS embedding discriminative limits.

The `anomaly_score` and `anomaly_flagged` fields reach hook consumers via `SemanticFinding` in `semantic.py`, not `scanner.py` — the PLAN named `scanner.py` as the target, but the actual wiring is through `mini_semantic.py -> semantic.SemanticFinding`. The wiring is correct and complete; the file name in the plan was an approximation.

---

_Verified: 2026-03-10T20:30:00Z_
_Verifier: Claude (gsd-verifier)_
