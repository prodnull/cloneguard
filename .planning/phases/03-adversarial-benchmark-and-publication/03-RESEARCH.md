# Phase 3: Adversarial Benchmark and Publication — Research

**Researched:** 2026-03-10
**Domain:** Adversarial ML benchmarking, NLP robustness evaluation, scientific publication framing
**Confidence:** HIGH (work builds directly on complete Phase 2 artifacts; no new external dependencies)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| BENCH-01 | Re-run adversarial benchmark (185 malicious + 234 benign) with full hardened pipeline; publish results | `scripts/hardened_benchmark.py` already implements this; needs re-run with confirmed v4 ONNX + Mahalanobis and output to dated JSON in `docs/results/` |
| BENCH-02 | Run adaptive attacks (PWWS against hardened model v4, not original) and report alongside non-adaptive results; document improvement ceiling | `scripts/generate_pwws_augmentation.py` in `.venv-transfer` is the attack driver; needs to run against v4 ONNX and produce a new ASR measurement distinct from the hardening-round ASR |
| BENCH-03 | Correlated failure analysis — identify samples Tier 0 AND hardened Tier 1.5 both miss | `hardened_benchmark.py` already tracks per-tier flags per sample; add per-sample analysis to identify the intersection of Tier 0 miss AND Tier 1.5 miss |
| BENCH-04 | Publish results with honest "raises attacker cost" framing; "prevents," "blocks," "secure" never appear | Framing discipline; affects HuggingFace model card, SECURITY.md, release notes, Medium article, LinkedIn post, and any academic writeup |
</phase_requirements>

---

## Summary

Phase 3 is an analysis and publication phase built entirely on Phase 2 artifacts. No new model training, no new architectural changes. The deliverables are: (1) a clean benchmark with adaptive attacks that honestly reports the hardened pipeline's limits, (2) a correlated failure analysis that identifies the undefended residual, and (3) updated public-facing documentation at multiple audience levels (HuggingFace model card, SECURITY.md, Medium article, LinkedIn, and optionally an academic pre-print).

The key technical challenge is designing the adaptive attack experiment correctly. The PWWS adaptive attack must run against the v4 hardened ONNX (the current production model), not the v3 baseline — and the result must be reported separately from the ASR measured during Phase 2 hardening rounds. The hardening-round ASR (20.0% after round 2) is not a valid adaptive attack number: it was measured on the same model iteration that had just been trained on those PWWS examples, which conflates training distribution and test-time adversary.

The Mahalanobis detector's 2.7% detection rate is an honest number that must be reported clearly — the benign/malicious CLS score distributions overlap substantially (means 17.59 vs 17.21), so the detector adds marginal signal, not a meaningful layer. This is a known limitation documented in Phase 2 SUMMARY and must be framed as such in all publications.

The publication side involves two layers: updating existing channels (HuggingFace model card, SECURITY.md, existing Medium draft, LinkedIn draft) and a new analytical writeup covering the adversarial hardening story. The user has explicitly expressed interest in assessing peer-review viability and appropriate venue selection. This research addresses that directly.

**Primary recommendation:** Run the adaptive attack benchmark first (produces the honest ceiling number), then do the correlated failure analysis (produces the known-gap narrative), then update all publication channels in a single coordinated pass so the numbers are consistent everywhere.

---

## Standard Stack

No new dependencies for Phase 3. All tooling is in place from Phases 1-2.

### Core (inherited from Phase 2)

| Library | Version | Purpose | Venv |
|---------|---------|---------|------|
| textattack | existing | PWWS adaptive attack generation | `.venv-transfer` |
| onnxruntime | existing | v4 ONNX inference | `.venv` |
| numpy / scipy | existing | Mahalanobis scoring | `.venv` |
| pytest | existing | Benchmark schema validation tests | `.venv` |
| transformers | existing | Tokenizer for ONNX wrapper | both venvs |

### Supporting (for publication outputs)

| Tool | Purpose | Notes |
|------|---------|-------|
| Markdown | HuggingFace model card, SECURITY.md, Medium article, RESEARCH writeup | Existing drafts at `docs/publications/` |
| JSON | Benchmark results artifacts | All output to `docs/results/` (gitignored) |
| Python dataclasses + json module | Correlated failure analysis output | Extend `hardened_benchmark.py` |

### Installation

No new installation required. All dependencies exist in `.venv` and `.venv-transfer`.

---

## Architecture Patterns

### BENCH-01: Canonical Benchmark Re-Run

`scripts/hardened_benchmark.py` is the production benchmark script. It already:
- Runs Tier 0 + hardened Tier 1.5 + Mahalanobis on the 185-malicious + 757-benign eval set
- Measures per-category recall, combined FPR, ASR, Mahalanobis detection rate, and latency
- Computes deltas from v3 baseline
- Writes structured JSON to `docs/results/`

For BENCH-01, this script should be run as-is and its output treated as the definitive "Phase 3 benchmark." The benchmark already ran as HARD-04 and produced `docs/results/hardened-benchmark-2026-03-10.json`. Phase 3's BENCH-01 task is to verify these numbers are still valid (v4 ONNX and Mahalanobis params are unchanged since Phase 2), confirm the result file exists with correct schema, and publish/document these numbers. A fresh re-run is recommended to confirm reproducibility on the same machine.

**Key parameter:** The benchmark uses `data/benchmark/benign_eval_751.json` (757 samples) for v4 — distinct from the 234-sample benign eval used for v3. The delta comparison between v3 FPR (3.8%) and v4 FPR (19%) is not apples-to-apples. Only the Tier 1.5 FPR comparison (v3: 15.4% vs v4: 9.2%) is directly comparable. This caveat must appear in all published results.

### BENCH-02: Adaptive Attack Design

This is the analytically critical task. The correct design:

1. **Attack target:** The v4 hardened ONNX model (current production). Run `generate_pwws_augmentation.py --round 3` (or a dedicated `adaptive_benchmark.py`) in `.venv-transfer` against v4.
2. **What to measure:** PWWS generation ASR against v4 (how many adversarial examples PWWS can successfully generate). This is the "improvement ceiling" — the fraction of inputs PWWS can still evade the hardened model.
3. **What NOT to conflate:** The hardening-round ASR (20.0% after round 2, measured on the benchmark corpus using the just-trained model) is a training-domain measure. The adaptive attack ASR must be measured on the **benchmark corpus** using the **final v4 model**, treating PWWS as a test-time adversary with full white-box access.
4. **Expected result:** PWWS adaptive ASR against v4 will be materially lower than 65.7% (v3 baseline) because the model has been hardened against PWWS specifically. But it will be nonzero — PWWS can still generate adversarial examples against hardened models on samples with sufficient synonym substitution options. A realistic range is 15-35% generation ASR.
5. **The ceiling narrative:** Even with adaptive PWWS attacks, structural categories (fragmentation, implicit_instruction, truncation) remain at 0% PWWS generation ASR — these are not vocabulary attacks and PWWS does not generate adversarial examples for them. Their 100% transfer rate from Phase 1 remains the honest ceiling.

**Script decision:** Use `generate_pwws_augmentation.py` with `--round 3` and `--limit` to avoid actual training augmentation (or create `scripts/adaptive_benchmark.py` as a dedicated measurement-only variant that does not merge results into training data). The latter is cleaner for publication.

### BENCH-03: Correlated Failure Analysis

Pattern: extend `hardened_benchmark.py` to output per-sample results for the malicious corpus, then filter for `tier0_detected=False AND tier15_verdict=SAFE AND anomaly_flagged=False`.

The existing per-category dict already tracks `tier0` and `tier15` counts per category. What's missing is a per-sample record of which specific samples both tiers missed. Output format: JSONL or JSON array with fields `{id, category, difficulty, text_preview, tier0_detected, tier15_verdict, anomaly_flagged}` for the "both-miss" subset.

Expected findings based on Phase 2 data:
- `fragmentation`: 10 samples at 45% recall → ~10 missed by combined pipeline
- `implicit_instruction`: ~6 samples at 75% recall → ~5 missed by Tier 1.5, some caught by Tier 0
- `truncation_padding`: ~2-3 samples at 90% recall

The correlated failure set will be dominated by structural attack categories — the exact attack classes identified as information-theoretic limits in Phase 1. This is the clean narrative: the gap is not a model quality issue, it is a fundamental limit of finite-vocabulary classifiers on structurally ambiguous inputs.

### BENCH-04: Framing Discipline

Prohibited words in all outputs: "prevents," "blocks," "secure," "protection against," "immune to."
Required framing: "raises attacker cost," "makes attacks harder," "requires more effort from an attacker," "increases the probability of detection."

This applies to:
- `docs/results/` JSON files (notes fields)
- HuggingFace model card (`prodnull/minilm-prompt-injection-classifier`)
- `docs/SECURITY.md`
- `docs/publications/2026-03-09-medium-article.md` (update to v4 numbers)
- `docs/publications/2026-03-09-linkedin-post.md` (update to v4 numbers)
- Any academic writeup abstract/conclusion
- Version tag/release notes for v0.3.0

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PWWS adversarial example generation | Custom word substitution engine | `PWWSRen2019` in TextAttack (.venv-transfer) | TextAttack implements WordNet synonym lookup, syntactic constraints, and attack scoring correctly |
| Benchmark metrics (TP/FP/TN/FN) | Custom metric computation | Existing `compute_metrics()` in `scripts/adversarial_benchmark.py` | Already verified correct across phases |
| Per-category recall tracking | New tracking code | Extend `hardened_benchmark.py`'s existing `per_category` dict | Avoid duplicating the scoring loop |
| Confidence intervals | Manual binomial CI code | `scipy.stats.proportion_confint` with Wilson method (already used in Phase 1) | Wilson CI is standard for proportions; implementation already in repo |
| JSON schema validation for benchmark output | Custom validator | Existing `tests/test_hardened_benchmark.py` test stubs | 9 schema tests already pass; extend rather than replace |

**Key insight:** This phase is analysis-and-publication, not implementation. Every tool needed is already in the repo. The risk is producing inconsistent numbers across publication channels, not building wrong code.

---

## Common Pitfalls

### Pitfall 1: Conflating Hardening-Round ASR with Adaptive Attack ASR

**What goes wrong:** Reporting the round-2 benchmark ASR (20.0%) as the adaptive attack result. It is not — it was measured during training augmentation on a model just trained on PWWS examples, and it measures the detection rate of the evolved model on the original benchmark, not a fresh adaptive attack on the final model.

**Why it happens:** Both numbers describe "PWWS success rate against v4 model" but measure different things.

**How to avoid:** Run a fresh PWWS attack against the final v4 ONNX as a one-time measurement, don't reuse the round-2 numbers. Label results clearly: "PWWS adaptive ASR (post-hardening, test-time attack)" vs "benchmark ASR at end of round 2 (training-time gate)."

**Warning signs:** If the adaptive attack ASR equals exactly 20.0%, the wrong numbers are being reported.

### Pitfall 2: Incomparable FPR Metrics

**What goes wrong:** Claiming "FPR improved from 3.8% (v3) to X% (v4)" without noting the benign eval sets are different sizes (234 samples vs 757 samples with different content-type distribution).

**Why it happens:** Both numbers exist in `hardened-benchmark-2026-03-10.json` under `delta_from_v3` but the note field explicitly flags incomparability.

**How to avoid:** Always use Tier 1.5 FPR for the v3/v4 comparison (15.4% → 9.2%, same logical path, same threshold). Report combined FPR separately with the caveat that eval sets differ.

**Warning signs:** Any table showing v3 FPR = 3.8% and v4 FPR = 19% without a caveat is incorrect framing.

### Pitfall 3: Mahalanobis Over-Claim

**What goes wrong:** Describing Mahalanobis as a meaningful "anomaly detection layer" when detection rate is 2.7%.

**Why it happens:** The detector was designed for 60% detection rate (Phase 2 target) but achieved 2.7% due to overlapping CLS distributions (benign mean 17.59 vs malicious mean 17.21). The component is in the pipeline and technically functioning but not providing meaningful lift.

**How to avoid:** Use "marginal orthogonal signal" language. Report the distribution overlap as the cause. Do not lead any benchmark table with Mahalanobis numbers. Do mention it as an honest negative result for publication credibility.

**Warning signs:** Any description calling Mahalanobis a "defense layer" or citing its FPR (1.2%) without mentioning the 2.7% detection rate.

### Pitfall 4: Numeric Drift Across Publication Channels

**What goes wrong:** Medium article says 90.3% recall; LinkedIn says 91%; SECURITY.md says 90%; model card says 90.3%. Minor differences look like careless errors to reviewers.

**Why it happens:** Numbers get copied and rounded differently across files during separate editing passes.

**How to avoid:** Establish one authoritative JSON source (`docs/results/hardened-benchmark-2026-03-10.json`) and copy numbers from it exactly. Update all channels in the same task/commit.

### Pitfall 5: Structural Attack Framing Confusion

**What goes wrong:** Presenting 45% recall on fragmentation as a "model weakness to improve" when it is an information-theoretic limit.

**Why it happens:** Low recall numbers look bad. The temptation is to frame them as future work.

**How to avoid:** Always pair the per-category recall table with the explanation that fragmentation/implicit_instruction/truncation are structural attacks — their payloads are indistinguishable from benign text at the token level by any finite-vocabulary classifier. Tier 0 compensates for fragmentation at 95-100% recall (Tier 0 contribution: 33%).

### Pitfall 6: Publication Overclaim on Peer-Review Viability

**What goes wrong:** Framing the work as novel enough for a top-tier venue (ACL, USENIX Security) when the contribution is primarily applied/empirical.

**Why it happens:** Genuine enthusiasm for the work.

**How to avoid:** Assess the contribution accurately (see Venue Assessment section below). The work is strong enough for industry track / workshop / blog / pre-print; it requires additional novelty for top-tier ML security venues.

---

## Code Examples

### Running the Canonical Benchmark

```bash
# BENCH-01: run in .venv
.venv/bin/python scripts/hardened_benchmark.py \
    --malicious data/benchmark/malicious_corpus.json \
    --benign data/benchmark/benign_eval_751.json \
    --output docs/results/hardened-benchmark-2026-03-10.json
```

### Running Adaptive PWWS Attack Against v4 (BENCH-02)

```bash
# Run in .venv-transfer — attacks the current v4 ONNX
.venv-transfer/bin/python scripts/generate_pwws_augmentation.py \
    --round 3 \
    --model-path src/cloneguard/model/mini_semantic.onnx \
    --corpus data/benchmark/malicious_corpus.json \
    --output docs/results/pwws_adaptive_v4_benchmark.jsonl \
    --time-limit 90

# The output JSONL contains the adversarial examples that evaded v4.
# ASR = len(output_jsonl) / pre_filtered_corpus_size
```

NOTE: The `generate_pwws_augmentation.py` script writes adversarial examples but is designed for training augmentation (round 1, 2). For an adaptive benchmark, a dedicated script that reads the JSONL and computes ASR against the current model without merging into training data is cleaner. The planner should create `scripts/adaptive_pwws_benchmark.py`.

### Correlated Failure Analysis Pattern (BENCH-03)

Extend `hardened_benchmark.py` to collect per-sample failure records:

```python
# Inside the malicious corpus loop in hardened_benchmark.py
# Add after per_category tracking:
if combined == "CLEAN":  # both tiers missed this sample
    both_miss_samples.append({
        "id": sample.get("id", f"mal-{i:04d}"),
        "category": category,
        "difficulty": sample.get("difficulty", "unknown"),
        "text_preview": text[:120],
        "tier0_detected": tier0_detected,
        "tier15_verdict": tier15_verdict,
        "anomaly_score": anomaly_score,
    })
```

Write `both_miss_samples` to `docs/results/correlated-failures-2026-03-10.json`.

### Confidence Interval (per Phase 1 pattern)

```python
from scipy.stats import proportion_confint

# Wilson CI for recall (n_detected successes out of n_total trials)
ci_low, ci_high = proportion_confint(n_detected, n_total, alpha=0.05, method="wilson")
# Report as: f"{recall:.1%} (95% CI: {ci_low:.1%}–{ci_high:.1%})"
```

---

## Venue Assessment (BENCH-04 Publication Scope)

This is a first-principles assessment of where the work sits in the publication landscape. It is high-confidence for framing decisions.

### What the Work Is

An applied empirical study of adversarial hardening for a binary text classifier deployed as a security defense layer. Contributions:
- Empirical measurement of white-box PWWS adversarial example transfer across model architectures (Phase 1, novel dataset and threat model)
- Adversarial data augmentation + FreeLB AT applied to prompt injection detection (novel application; AT on standard NLP tasks is well-studied, PI detection is new)
- Honest measurement of Mahalanobis anomaly detection on a security classification task (negative result: 2.7% detection rate, distribution overlap documented)
- "Raises attacker cost" framing with evidence for a production-deployed security tool

### Venue Fit Assessment

| Venue | Tier | Fit | Reason |
|-------|------|-----|--------|
| **Blog post / Medium** | Public | Excellent | Existing draft ready; strong audience-topic match; no novelty bar |
| **LinkedIn technical post** | Public | Excellent | Existing draft ready; update numbers to v4 |
| **arXiv pre-print** | Pre-print | Good | Citable; establishes priority; no review bar; recommended for talk submissions |
| **IEEE S&P / USENIX Security** | Top-tier security | Weak | Requires stronger threat model novelty or formal analysis; AT + Mahalanobis alone not sufficient |
| **ACL / EMNLP** | Top-tier NLP | Weak | Domain focus is NLP robustness; PI detection is application-specific; paper lacks algorithmic novelty |
| **LLM Security Workshop (co-located ICLR/NeurIPS/ACL)** | Workshop | Good | Application-focused workshops accept empirical results; 2026 deadlines need to be checked |
| **AISec (ACM CCS Workshop)** | Security workshop | Good | AISec explicitly accepts applied adversarial ML work; deadline typically August |
| **USENIX WOOT** | Security workshop | Moderate | Attacker-cost framing fits WOOT; needs stronger attack novelty or system contribution |
| **Industry track (ACL Industry / EMNLP Industry)** | Industry | Good | Industry tracks explicitly accept deployed-system empirical work; lower novelty bar |
| **Talk (DEF CON, BSides, local security conf)** | Talk | Excellent | Adversarial ML on real tools is directly relevant to security practitioner audience |

### Peer-Review Viability (Honest Assessment)

**Strengths for review:**
- Empirical results on a real deployed tool (not a toy dataset)
- Honest reporting of negative results (Mahalanobis 2.7%, structural attack limits)
- Clear before/after comparison with documented methodology
- Phase 1 transferability gate has scientific integrity (hard gate, pivot on failure, not post-hoc rationalization)
- Citation quality: CITED vs PROJECTED claims tracked in survey (a rare honesty discipline)

**Weaknesses for top-tier review:**
- Sample size is modest: 185 malicious samples is small by ML standards (though realistic for this threat model)
- PWWS augmentation is a well-known technique; applying it to PI detection is novel application but not novel algorithm
- Mahalanobis negative result is interesting but not unexpected given the mechanism
- No comparison against alternative defenses at deployment scale

**Recommended path:** Publish to arXiv for citeability and conference/talk submission credibility. Target LLM Security Workshop or AISec for peer-reviewed venue. Update Medium/LinkedIn with v4 numbers. The research contribution is real and citable; it is not NeurIPS/USENIX main-track material without additional work.

---

## State of the Art (Adversarial ML for Text Security)

| Old Approach | Current Approach | Impact on This Work |
|---|---|---|
| Single-layer regex or LLM-as-judge | Multi-tier: regex + fine-tuned classifier + anomaly detection | CloneGuard already implements current approach |
| Adversarial training as one-shot | Iterative augmentation rounds with ASR gate | Phase 2 implemented this correctly |
| Mahalanobis on multi-layer features (Yoo et al. 2022) | Single-layer CLS only | Phase 2 took the simpler path; full RDE would require multi-layer extraction, out of scope |
| Report ASR only | Report ASR + adaptive ASR + correlated failures | Phase 3 adds the adaptive and correlated views |
| "Defends against" framing | "Raises attacker cost" framing | CloneGuard project rule since founding |

**Currently deferred / not in scope:**
- Multi-layer Mahalanobis (RDE): would need feature extraction from multiple transformer layers; ~2x inference overhead
- BERT-Attack / genetic attack hardening: PWWS hardening does not generalize (<5% improvement per ACL Findings 2023)
- Multilingual hardening: GitHub issue #5, explicitly deferred

---

## Open Questions

1. **Adaptive attack script design**
   - What we know: `generate_pwws_augmentation.py` exists and works but writes to training JSONL; using it for adaptive benchmark requires either a `--no-merge` flag or a dedicated script
   - What's unclear: whether reusing `--round 3` with a different output path is sufficient or whether measurement-only semantics require a new script
   - Recommendation: Create `scripts/adaptive_pwws_benchmark.py` as a thin wrapper around the attack loop that writes a `docs/results/adaptive-pwws-benchmark-YYYY-MM-DD.json` with ASR + per-category breakdown rather than a JSONL for training. This is ~50 lines.

2. **Benchmark date in filenames**
   - What we know: existing benchmark is dated `2026-03-10`; if Phase 3 re-runs on a different date, file names diverge from `_V3_RECALL` hardcoded constants in `hardened_benchmark.py`
   - What's unclear: whether the planner should update `_V3_RECALL` and `_V3_TIER15_FPR` constants or treat the 2026-03-10 file as the authoritative baseline
   - Recommendation: Treat `hardened-benchmark-2026-03-10.json` as the authoritative Phase 2 artifact; if Phase 3 re-runs produce a new file, name it `hardened-benchmark-phase3-{date}.json` and document both files. Do not overwrite Phase 2 results.

3. **HuggingFace model card update scope**
   - What we know: HF model card (`prodnull/minilm-prompt-injection-classifier`) exists; last updated with v3 CV metrics (per MEMORY.md: "HF model card updated: v3 CV metrics in frontmatter, 193 patterns, v3 CV section added")
   - What's unclear: whether the model card should reflect v4 numbers (90.3% recall, 9.7% ASR, 94.51% CV accuracy) or whether this requires a new model upload
   - Recommendation: Update model card metadata and narrative with v4 numbers; no new model upload needed (v4 is available via `fetch_model.py`); update the `model-index` YAML frontmatter accuracy field and add a "Adversarial Hardening (v4)" section

4. **Medium article update vs. new article**
   - What we know: existing draft at `docs/publications/2026-03-09-medium-article.md` describes v3 architecture, 95.8% F1, 191 patterns; Phase 2+3 adds adversarial hardening narrative
   - What's unclear: whether to update the existing article or publish a new "Part 2" covering adversarial hardening
   - Recommendation: New article "Part 2: What Happens When Someone Tries to Break It" is stronger than updating the existing article, which already has a published URL. The adversarial hardening story (Phase 1 gate failure, pivot, hardening results, honest limits) stands alone as a narrative.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (existing) |
| Config file | none — uses default pytest discovery |
| Quick run command | `.venv/bin/python -m pytest tests/test_hardened_benchmark.py tests/test_latency.py -q` |
| Full suite command | `.venv/bin/python -m pytest -q` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BENCH-01 | Benchmark output schema is valid JSON with required keys | schema validation | `.venv/bin/python -m pytest tests/test_hardened_benchmark.py -q` | Yes (15 tests) |
| BENCH-01 | Recall > 0, FPR in [0,1], ASR in [0,1] | bounds check | `.venv/bin/python -m pytest tests/test_hardened_benchmark.py -q` | Yes |
| BENCH-02 | Adaptive benchmark output contains ASR + per-category breakdown | schema validation | `.venv/bin/python -m pytest tests/test_adaptive_benchmark.py -q` | No — Wave 0 gap |
| BENCH-03 | Correlated failure JSON contains samples with tier0_detected=False AND clean Tier 1.5 | schema validation | `.venv/bin/python -m pytest tests/test_correlated_failures.py -q` | No — Wave 0 gap |
| BENCH-04 | Prohibited words absent from all publication markdown files | content check | `.venv/bin/python -m pytest tests/test_framing.py -q` | No — Wave 0 gap |

### Sampling Rate

- **Per task commit:** `.venv/bin/python -m pytest tests/test_hardened_benchmark.py tests/test_latency.py -q`
- **Per wave merge:** `.venv/bin/python -m pytest -q` (full 1031+ test suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_adaptive_benchmark.py` — covers BENCH-02 adaptive benchmark output schema
- [ ] `tests/test_correlated_failures.py` — covers BENCH-03 both-miss sample list schema
- [ ] `tests/test_framing.py` — covers BENCH-04 prohibited word check across markdown files

*(The 15 existing tests in `test_hardened_benchmark.py` and 6 in `test_latency.py` cover BENCH-01 fully — no gap.)*

---

## Sources

### Primary (HIGH confidence)

- Phase 2 SUMMARY files (`02-01-SUMMARY.md`, `02-02-SUMMARY.md`, `02-03-SUMMARY.md`) — direct artifacts
- `docs/results/hardened-benchmark-2026-03-10.json` — authoritative Phase 2 benchmark numbers
- `docs/results/hardening-rounds-2026-03-10.json` — per-round ASR progression
- `docs/results/pivot-alternatives-survey-2026-03-10.md` — citation audit for all projected claims
- `scripts/hardened_benchmark.py` — benchmark implementation; studied directly

### Secondary (MEDIUM confidence)

- Yoo & Qi 2021 (A2T, EMNLP Findings, arxiv:2109.00544) — AT effectiveness on vocabulary attacks; CITED in survey
- Yoo et al. 2022 (ACL Findings, arxiv:2203.01677) — Mahalanobis AUC benchmark; CITED in survey
- ACL Findings 2023 (aclanthology.org/2023.findings-acl.496) — AT generalization limits (<5%); CITED in survey
- Lee et al. 2018 (NeurIPS, arxiv:1807.03888) — Mahalanobis OOD detection; CITED in survey

### Tertiary (LOW — venue assessment, used for planning only)

- AISec workshop scope: based on prior years' accepted papers; check 2026 CfP before committing
- WOOT scope: based on general knowledge of workshop focus areas
- LLM Security Workshop venues: workshop co-location varies by year; verify before submission

---

## Metadata

**Confidence breakdown:**
- Benchmark execution (BENCH-01): HIGH — script exists, data exists, already ran in Phase 2
- Adaptive attack design (BENCH-02): HIGH — script exists, design is clear; runtime outcome unknown
- Correlated failure analysis (BENCH-03): HIGH — straightforward extension to existing script
- Framing discipline (BENCH-04): HIGH — project rule since founding, well-established in all prior work
- Venue assessment: MEDIUM — reflects honest assessment of contribution level; 2026 CfPs not checked

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (stable; no new ML papers expected to materially change this work's positioning in 30 days)
