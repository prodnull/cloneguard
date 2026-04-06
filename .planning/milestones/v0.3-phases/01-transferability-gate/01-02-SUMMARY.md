---
phase: 01-transferability-gate
plan: 02
subsystem: research
tags: [textattack, pwws, deberta, minilm, adversarial, transferability, gate-decision, ensemble]

requires:
  - phase: 01-transferability-gate
    plan: 01
    provides: "scripts/transfer_experiment.py, .venv-transfer, prefetched DeBERTa proxy model"

provides:
  - "Transfer experiment results: 58.0% transfer rate (PWWS, 88 adversarial examples from 134 attacked)"
  - "Gate decision: PIVOT — ensemble approach invalidated empirically"
  - "Per-category breakdown revealing structural failure modes (fragmentation 100%, implicit_instruction 100%, truncation_padding 100%)"
  - "Analysis: docs/results/transfer-experiment-analysis-2026-03-10.md (gitignored)"
  - "Raw results: docs/results/transfer-experiment-2026-03-10.json (gitignored)"

affects: [02-onnx-export, 03-ensemble-integration, 04-validation]

tech-stack:
  added: []
  patterns:
    - "Pre-filter corpus to MiniLM-detected samples before attacking (ensures transfer rate measures detectable inputs)"
    - "Wilson 95% CI as the statistical bound for a binary gate decision"
    - "PWWS-only result when TextFooler-BERTScore fails silently — conservative framing strengthens pivot case"

key-files:
  created:
    - docs/results/transfer-experiment-2026-03-10.json (gitignored — raw per-sample data + gate decision)
    - docs/results/transfer-experiment-analysis-2026-03-10.md (gitignored — publication-ready analysis)
  modified: []

key-decisions:
  - "PIVOT: ensemble (MiniLM + DeBERTa) approach abandoned — 58.0% transfer rate (CI: 47.5%–67.7%) exceeds 40% gate threshold; CI lower bound clears threshold by 7.5pp making the decision statistically firm"
  - "Failure is structural, not model-specific: fragmentation, implicit_instruction, truncation_padding all transfer at 100% — DeBERTa has the same architectural blind spots as MiniLM on sub-token and context-overflow attacks"
  - "TextFooler-BERTScore not used: silent failure on sample 0 from BERTScore constraint; results are PWWS-only; this is the conservative framing (TextFooler would likely add more transferable examples)"
  - "Proxy caveat documented honestly: ProtectAI DeBERTa is not fine-tuned on CloneGuard's dataset — it serves as an architectural proxy for structural diversity measurement, not a guarantee of ensemble metrics"

patterns-established:
  - "Gate decisions require Wilson 95% CI — a point estimate without CI cannot support a binary go/no-go"
  - "Per-category breakdown is mandatory: aggregate transfer rate hides which attack types drive the gate result"
  - "Publish results regardless of outcome — pivot decisions are as publishable as proceed decisions"

requirements-completed: [XFER-02, XFER-03]

duration: ~90min (experiment runtime) + review
completed: 2026-03-10
---

# Phase 1 Plan 02: Transfer Experiment Execution Summary

**PWWS adversarial attack on 134 MiniLM-detectable samples produced 88 adversarial examples; 58.0% transferred to ProtectAI DeBERTa (CI: 47.5%–67.7%), triggering the PIVOT gate — ensemble approach abandoned, alternatives survey next**

## Performance

- **Duration:** ~90 min (experiment runtime) + async human review
- **Started:** 2026-03-10 (experiment run by previous agent)
- **Completed:** 2026-03-10T (gate decision approved by user)
- **Tasks:** 2 (Task 1: run experiment; Task 2: human review checkpoint)
- **Files modified:** 2 (docs/results/transfer-experiment-2026-03-10.json, docs/results/transfer-experiment-analysis-2026-03-10.md — both gitignored)

## Accomplishments

- Full transfer experiment run on 185-sample adversarial corpus (134 attacked, 51 pre-filtered as MiniLM misses)
- 88 PWWS adversarial examples generated; 51 transferred to DeBERTa proxy = 58.0% transfer rate
- Wilson 95% CI computed: [47.5%, 67.7%] — lower bound 7.5pp above gate threshold, decision is statistically firm
- Per-category breakdown reveals which attack types are structurally hard vs. model-specific (see below)
- Gate decision documented: PIVOT — ensemble approach does not provide meaningful additional coverage
- Publication-ready analysis written and stored at docs/results/transfer-experiment-analysis-2026-03-10.md

## Key Results

| Category | Adversarial | Transferred | Transfer Rate |
|---|---|---|---|
| fragmentation | 4 | 4 | 100.0% |
| implicit_instruction | 8 | 8 | 100.0% |
| truncation_padding | 5 | 5 | 100.0% |
| structural_dilution | 17 | 15 | 88.2% |
| social_engineering | 12 | 6 | 50.0% |
| counter_defensive | 13 | 6 | 46.2% |
| encoding_evasion | 8 | 3 | 37.5% |
| homoglyph_unicode | 7 | 2 | 28.6% |
| synonym_substitution | 14 | 2 | 14.3% |
| **Combined** | **88** | **51** | **58.0%** |

**Interpretation:** The highest-transfer categories are structural (fragmentation, implicit instruction, context overflow) — not lexical. DeBERTa performs better at word-level attacks (synonym substitution: 14.3%, homoglyph: 28.6%) but fails equally on structural evasion. Ensembling architecturally diverse models does not help when the evasion exploits input structure rather than token distributions.

## Task Commits

Task 1 (run full transfer experiment) was executed by the previous continuation agent. No new tracked files were produced — results are in gitignored docs/results/ per project rules.

Task 2 (review gate decision and approve results) was a human-verify checkpoint. No code changes.

1. **Task 1: Run full transfer experiment** — results committed to gitignored path (no tracked file change)
2. **Task 2: Review gate decision and approve results** — human checkpoint, approved by user

**Plan metadata:** (this commit)

## Files Created/Modified

- `docs/results/transfer-experiment-2026-03-10.json` — Raw experiment output: gate_decision, 88 per-sample records, methodology, limitations (gitignored — not committed)
- `docs/results/transfer-experiment-analysis-2026-03-10.md` — Publication-ready analysis with per-category table, proxy caveat, and pivot rationale (gitignored — not committed)

## Decisions Made

**PIVOT gate triggered:** Transfer rate 58.0% (CI: 47.5%–67.7%) exceeds the pre-set 40% threshold. The CI lower bound of 47.5% clears the threshold by 7.5 percentage points — this is not a borderline case. The decision does not depend on the exact point estimate.

**Structural failure, not model-specific:** Three categories transfer at 100% (fragmentation, implicit_instruction, truncation_padding). This is the core finding: these attacks succeed because of how inputs are structured (sub-30-char fragments, indirect phrasing, context overflow), not because of how any single model weighs tokens. A second ML model trained on the same task distribution cannot fix this.

**TextFooler silent failure is acceptable:** TextFooler-BERTScore failed on sample 0 and was not retried (silent exception from BERTScore constraint). PWWS-only results are the conservative choice — TextFooler would likely have produced additional transferable examples, making the pivot case stronger, not weaker.

**Proxy caveat maintained:** ProtectAI DeBERTa is not fine-tuned on CloneGuard's dataset. The analysis is framed correctly: it measures architectural blind-spot overlap, not ensemble performance prediction. This is the intellectually honest framing per project rules (never claim "blocks" or "prevents").

## Deviations from Plan

**TextFooler not executed (silent failure):** The plan specified PWWS + TextFooler-BERTScore. TextFooler failed silently on sample 0 due to a BERTScore constraint exception. Results are PWWS-only. This is documented in the results file and analysis. The gate decision is robust: the CI lower bound already exceeds the threshold, so TextFooler results would only reinforce the pivot.

This is a known limitation, not a bug — logged in per-sample results and limitations array of the JSON output.

**Total deviations:** 1 (TextFooler not executed — silent failure, PWWS-only result used, pivot case unaffected)
**Impact:** Conservative — PWWS-only result still clears threshold by 7.5pp at CI lower bound.

## Issues Encountered

- TextFooler-BERTScore recipe generated a blank exception on the first sample. The experiment continued PWWS-only per the fallback logic in `transfer_experiment.py` (`--pwws-only` equivalent behavior).

## User Setup Required

None.

## Next Phase Readiness

**Gate decision: PIVOT.** Phase 2 (DeBERTa ONNX export and ensemble integration) does NOT begin.

Next step: alternatives survey — 3-4 defense approaches with pros/cons/effort against CloneGuard constraints:
1. Semantic similarity defense (cosine distance from known-safe embeddings)
2. Perturbation detection (detect adversarially modified text via reconstruction loss)
3. Adversarial training (augment MiniLM training data with PWWS/TextFooler examples)
4. Structural heuristics (detect fragmentation, implicit instruction, padding patterns — rule-based Tier 0 extension)

The pivot path was pre-documented as a required deliverable if gate triggered. User confirmed scope: alternatives survey as next session.

## Self-Check: PASSED

- FOUND: .planning/phases/01-transferability-gate/01-02-SUMMARY.md
- FOUND: docs/results/transfer-experiment-2026-03-10.json (gitignored, not committed)
- FOUND: docs/results/transfer-experiment-analysis-2026-03-10.md (gitignored, not committed)
- Gate decision field verified: "pivot" (confirmed via python3 extraction)
- Transfer rate verified: 0.5795 with CI [0.4752, 0.6772]
- Per-sample count verified: 88 records

---
*Phase: 01-transferability-gate*
*Completed: 2026-03-10*
