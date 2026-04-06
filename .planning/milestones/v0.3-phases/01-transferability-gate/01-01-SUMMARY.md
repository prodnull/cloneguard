---
phase: 01-transferability-gate
plan: 01
subsystem: research
tags: [textattack, onnx, deberta, minilm, adversarial, transfer-learning, pwws, textfooler, bert-score]

requires: []
provides:
  - Isolated Python 3.11 venv (.venv-transfer) with TextAttack 0.3.10, transformers 4.x
  - scripts/transfer_experiment.py: complete transfer experiment script with ONNX wrapper, PWWS attack, TextFooler-BERTScore attack, DeBERTa proxy scoring, Wilson CI, JSON output
  - ProtectAI/deberta-v3-base-prompt-injection-v2 prefetched to HuggingFace cache
  - DeBERTa id2label verified: {0: SAFE, 1: INJECTION}
affects: [02-onnx-export, 03-ensemble-integration, 04-validation]

tech-stack:
  added:
    - textattack==0.3.10 (in .venv-transfer)
    - torch 2.10.0 (in .venv-transfer)
    - transformers 4.57.6 (in .venv-transfer, <5.0 constraint for TextAttack compat)
    - bert-score (in .venv-transfer)
    - onnxruntime (in .venv-transfer)
    - scipy 1.17.1 (in .venv-transfer, for Wilson CI)
  patterns:
    - "MiniLMOnnxWrapper: TextAttack ModelWrapper subclass wrapping ONNX session directly via _session.run"
    - "Raw ONNX scoring (bypasses classify() thresholds) for adversarial attack target evaluation"
    - "TextFooler-BERTScore: USE replaced with BERTScore(f1, bert-base-uncased, threshold=0.75) for TF-free execution"
    - "Wilson 95% CI for transfer rate statistical bounds"
    - "Pre-filter: attack only samples MiniLM detects (raw_score > 0.5) — measures transfer on detectable samples"

key-files:
  created:
    - scripts/transfer_experiment.py
    - .venv-transfer/ (gitignored)
  modified:
    - .gitignore (added .venv-*/ glob pattern)

key-decisions:
  - "TextFooler-BERTScore: substituted BERTScore(f1, bert-base-uncased, 0.75) for UniversalSentenceEncoder to avoid TensorFlow dependency; semantically approximate, not identical to original TextFooler"
  - "DeBERTa id2label loaded dynamically from model config — not hard-coded — to catch upstream label changes"
  - "Pre-filter corpus to samples MiniLM detects (score > 0.5): transfer experiment measures adversarial transferability, not initial evasion rate"
  - "Attacker + AttackArgs API (not Attack.attack_dataset): TextAttack 0.3.10 requires Attacker class for dataset iteration"

patterns-established:
  - "Transfer experiment: PWWS → adversarial examples → DeBERTa proxy scoring → Wilson CI → gate decision"
  - "Isolated venv (.venv-transfer) for TextAttack to avoid transformers 5.x conflicts with TextAttack 0.3.10"

requirements-completed: [XFER-01, XFER-02]

duration: 8min
completed: 2026-03-10
---

# Phase 1 Plan 01: Transfer Experiment Script + Venv Summary

**TextAttack PWWS + TextFooler-BERTScore attack harness against MiniLM ONNX with DeBERTa proxy transfer scoring, gated by Wilson 95% CI on transfer rate**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-10T14:32:20Z
- **Completed:** 2026-03-10T14:40:01Z
- **Tasks:** 2
- **Files modified:** 2 (scripts/transfer_experiment.py, .gitignore) + .venv-transfer/ (gitignored)

## Accomplishments

- Isolated Python 3.11 venv with TextAttack 0.3.10, transformers 4.x (TF-free), bert-score, onnxruntime, scipy
- Transfer experiment script with full output spec: methodology, per-attack results, combined gate decision, per-sample records
- TextFooler-BERTScore: TF-free TextFooler variant replacing UniversalSentenceEncoder with BERTScore constraint
- DeBERTa proxy integration with dynamic id2label verification (confirmed: {0: SAFE, 1: INJECTION})
- Dry-run verified: PWWS generated adversarial example, DeBERTa scored it, transfer verdict recorded

## Task Commits

1. **Task 1: Create isolated venv and prefetch models** - `d91d913` (chore)
2. **Task 2: Write transfer experiment script** - `e4a2cc3` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `scripts/transfer_experiment.py` — Complete transfer experiment script (986 lines): MiniLMOnnxWrapper, PWWS+TextFooler-BERTScore attacks, DeBERTa proxy scoring, Wilson CI, JSON output, CLI (--dry-run, --limit, --pwws-only, --output)
- `.gitignore` — Added `.venv-*/` glob (previously only `.venv/` was covered)
- `.venv-transfer/` — Isolated Python 3.11 venv (gitignored, not committed)

## Decisions Made

**TextFooler-BERTScore instead of stock TextFooler:** Stock TextFoolerJin2019.build() imports UniversalSentenceEncoder (TensorFlow). Plan explicitly required TF-free. BERTScore(f1, bert-base-uncased, threshold=0.75) used as semantic constraint — retains all other TextFooler components (WordSwapEmbedding, WordEmbeddingDistance, PartOfSpeech, GreedyWordSwapWIR). The threshold 0.75 is an approximate equivalent to the angular similarity 0.840845057 in original TextFooler; semantically approximate, not identical.

**Attacker API fix (Rule 3 - Blocking):** Attack.attack_dataset does not exist in TextAttack 0.3.10. Correct API is `Attacker(attack, dataset, attack_args).attack_dataset()`. Fixed before first run.

**Pre-filtering corpus (>0.5 raw score):** Attack only samples MiniLM already detects. Ensures transfer rate measures how well adversarial mutations against MiniLM also fool DeBERTa — not how often MiniLM misses easy inputs.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] TextAttack 0.3.10 uses Attacker class, not Attack.attack_dataset**
- **Found during:** Task 2 (dry-run verification)
- **Issue:** Plan and initial implementation called `attack.attack_dataset(ta_dataset)` — method does not exist on `Attack` object in TextAttack 0.3.10
- **Fix:** Introduced `AttackArgs` + `Attacker(attack, dataset, attack_args)` wrapper; iterate via `attacker.attack_dataset()`
- **Files modified:** scripts/transfer_experiment.py
- **Verification:** Dry-run `--limit 3` completes successfully, 1 adversarial example generated
- **Committed in:** e4a2cc3 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Required fix — TextAttack API. No scope creep.

## Issues Encountered

- TextFooler stock recipe requires TensorFlow/USE — handled as designed (BERTScore substitution path per plan)
- `.gitignore` covered `.venv/` but not `.venv-transfer/` — added `.venv-*/` glob (minor, caught immediately)

## User Setup Required

None — all models prefetched to HuggingFace cache during Task 1. ONNX model already present at `src/cloneguard/model/mini_semantic.onnx`.

## Next Phase Readiness

- Transfer experiment script is ready to run at full scale (185 samples): `.venv-transfer/bin/python scripts/transfer_experiment.py`
- Expected runtime: 30-60 minutes on M-series CPU (PWWS + TextFooler-BERTScore on 185 samples)
- Results gate Phase 1: transfer_rate > 40% = pivot, <= 40% = proceed to Phase 2

---
*Phase: 01-transferability-gate*
*Completed: 2026-03-10*
