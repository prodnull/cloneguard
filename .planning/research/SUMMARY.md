# Project Research Summary

**Project:** CloneGuard v0.3.0 — White-Box Adversarial Resilience Ensemble
**Domain:** Adversarial-resilient ONNX ensemble text classifier (prompt injection detection)
**Researched:** 2026-03-10
**Confidence:** MEDIUM-HIGH

---

## Executive Summary

CloneGuard v0.3.0 adds a second ONNX classifier (DeBERTa-v3-small) to the existing MiniLM-L6-v2 (Tier 1.5) in a parallel-vote ensemble (Tier 1.6), targeting white-box adversarial attacks against the public MiniLM weights. The approach is directionally sound: five independent research agents converge on DeBERTa-v3-small as the correct second architecture due to its SentencePiece Unigram tokenizer (vs. MiniLM's WordPiece — TokenBreak paper measures 55.62% adversarial success on WordPiece vs. 0% on Unigram), disentangled attention mechanism, and ELECTRA-style pretraining objective. These three divergences maximize the transfer penalty for white-box attacks crafted against MiniLM. ProtectAI already ships a production ONNX model for this exact task (`protectai/deberta-v3-small-prompt-injection-v2`) validating the architecture, toolchain, and export path. All major technical risks are documented and mitigable.

The central risk is not architecture selection — that question is settled — but ensemble effectiveness on a shared 6,340-sample dataset. Both models trained on identical data will learn correlated decision boundaries, and adversarial examples exploiting dataset shortcuts (28% of top features are artifacts per arxiv 2602.14161) will transfer regardless of architecture difference. The mitigation is mandatory: use different augmentation pipelines per model (Pang et al. 2019; NeurIPS 2023 Deng & Mu) to inject decision boundary diversity before fine-tuning. Without this, the ensemble degrades to near-single-model robustness under adaptive attacks. The transferability experiment (TextAttack BERTAttack + TextFooler against MiniLM, measured on DeBERTa) must be a hard gate with a defined pivot threshold (>40% transfer rate = pivot), not a retrospective validation.

The correct security framing is established and must be maintained throughout: this ensemble raises attacker cost, it does not block adaptive attackers who have access to both public ONNX models. An attacker with both model weights can run AdaEA-style ensemble gradient attacks. The multi-tier defense (non-differentiable Tier 0 regex + WARNING escalation + Tier 2 Ollama on inconclusive) provides defense-in-depth that a pure ML ensemble cannot. OR-vote in hard majority mode will inflate FPR from the current 3.8% toward 7-9%; this is manageable with mode-gated voting (OR-vote in STRICT mode only, confidence threshold p > 0.65 in standard modes).

---

## Key Findings

### Recommended Stack

The second classifier is `microsoft/deberta-v3-small` fine-tuned on CloneGuard's v3 dataset (6,340 samples) and exported to ONNX via `ORTModelForSequenceClassification.from_pretrained(..., export=True)`. The CLI export path (`optimum-cli`) is broken for DeBERTa-v3 (GitHub optimum issue #2075 — always predicts same label, unresolved). The tokenizer requires `use_fast=False` (SentencePiece backend; fast Rust tokenizer fails silently). `pipeline()` cannot be used — pass `input_ids` and `attention_mask` directly to avoid `token_type_ids` conflict (optimum issue #968, closed "not planned" June 2025). ModernBERT is explicitly ruled out: ONNX export is fragile (transformers issue #35545), architecture is closer to standard BERT (less diversity from MiniLM), and a Jan 2026 controlled benchmark (arxiv:2504.08716) found DeBERTa-v3 superior on classification.

Training tooling is dev-only: `torch>=2.2.0`, `optimum[onnxruntime]>=1.24.0`, `textattack==0.3.10`, `datasets>=2.0.0`. Zero new runtime dependencies — inference for both classifiers runs through the existing `onnxruntime` + `transformers` tokenizer pipeline. INT8 dynamic quantization via `onnxruntime.quantization.quantize_dynamic` is required post-export to reach deployable size (FP32 export can reach 350MB+ without it).

**Core technologies:**
- `microsoft/deberta-v3-small`: second ONNX classifier — maximizes architecture distance from MiniLM on three independent axes (tokenizer, attention, pretraining objective)
- `optimum[onnxruntime]>=1.24.0`: ONNX export via `ORTModelForSequenceClassification` — programmatic `export=True` path only, not CLI
- `textattack==0.3.10`: transferability experiment (BERTAttack, TextFooler, PWWS) — dev/research use only, not a runtime dependency
- `onnxruntime.quantization`: INT8 dynamic quantization post-export — required for size and latency targets

### Expected Features

The MVP (v0.3.0) is tightly scoped. The transferability experiment gates everything else; if FR(MiniLM→DeBERTa) exceeds 40%, the plan pivots before any fine-tuning investment.

**Must have (table stakes):**
- Transferability experiment with hard gate — empirical proof that cross-architecture transfer is below threshold; required before claiming white-box resilience
- DeBERTa-v3-small fine-tuned on v3 dataset, ONNX-exported, sanity-checked for non-constant predictions — the second classifier
- Hard majority vote (OR) integration in `scan` and hook pipeline — parallel vote on every input
- Disagreement state ("inconclusive") in JSON hook output — zero marginal cost; adversarially significant signal
- Ensemble adversarial benchmark: ASR/FR/robust accuracy table, pre- and post-ensemble recall and FPR — the publishable evidence

**Should have (competitive, v0.3.x):**
- Soft confidence vote with tunable threshold θ — post-deployment FPR/recall dial without retraining
- Temperature calibration of both models against held-out benign set — prerequisite for meaningful soft vote
- Tier 2 Ollama auto-escalation on inconclusive state — use disagreement as a Tier 2 trigger

**Defer (v0.4+):**
- Adversarial fine-tuning of Tier 1.6 with transferred examples from Tier 1.5 — needs transfer rate data first
- ModernBERT as third ensemble member — deferred until ONNX export issues are confirmed resolved
- Multilingual adversarial test cases — deferred per GitHub issue #5
- Automated adversarial example generation in CI

### Architecture Approach

The ensemble integrates via two new modules (`ensemble_semantic.py` for the DeBERTa classifier, `ensemble.py` for voting logic) without touching `mini_semantic.py`. Both callers (`hooks.py` and `scanner.py`) replace their direct `MiniSemanticClassifier` calls with `EnsembleClassifier`. The vote table is conservative: any non-SAFE verdict from either classifier produces at minimum WARNING; disagreement produces WARNING. Classifiers run sequentially, not concurrently — GIL + shared CPU make threading counterproductive for ONNX inference. Total estimated latency: 16ms (MiniLM) + 40-60ms (DeBERTa INT8) = ~56-76ms, within the 120ms hook budget. The second model is distributed via a separate HuggingFace repo (`prodnull/deberta-v3-small-prompt-injection-classifier`) fetched by a new `fetch_ensemble_model.py`; bundling both in the wheel would create a 250+ MB download.

**Major components:**
1. `ensemble_semantic.py` — EnsembleSemanticClassifier (DeBERTa-v3-small ONNX); same interface as MiniSemanticClassifier; `model_ensemble/` directory
2. `ensemble.py` — EnsembleClassifier, VoteResult, voting policy; single entry point for both hooks.py and scanner.py
3. `scripts/train_ensemble_model.py` — DeBERTa-v3-small fine-tuning; separate from train_mini_model.py (different `hidden_size`, `MAX_SEQ_LEN`, `use_fast=False` tokenizer)
4. `scripts/training_utils.py` — shared `load_dataset`, `evaluate`, `select_device`; extracted from train_mini_model.py to avoid duplication
5. `scripts/transferability_experiment.py` — gate experiment; TextAttack against MiniLM, measured on DeBERTa

**Build order (respects dependencies):**
`training_utils.py` → `train_ensemble_model.py` → `fetch_ensemble_model.py` → `ensemble_semantic.py` → `ensemble.py` → `hooks.py` → `scanner.py` → `mcp_plugin.py` → `transferability_experiment.py`

### Critical Pitfalls

1. **DeBERTa ONNX export produces constant predictions (Silent breakage)** — Use `ORTModelForSequenceClassification(..., export=True)` not `optimum-cli`; immediately run 50-sample balanced sanity check as automated CI step; validate ONNX vs. PyTorch logit agreement (atol ≤ 0.001). Warning sign: ONNX file is double the expected size; 100% precision + 0% recall on any balanced split.

2. **Transferability experiment gives misleadingly optimistic verdict** — Run two-stage experiment: Stage 1 = non-adaptive (TextFooler/BERTAttack/PWWS); Stage 2 = adaptive (ensemble-targeting both models simultaneously). Report both. Stage 1 is a lower bound on attacker capability, not a ceiling. Define the gate before running: FR > 40% = pivot. FR > 60% = architecture needs revision.

3. **Correlated decision boundaries from shared training data** — Use different augmentation pipelines per model (NeurIPS 2023 Deng & Mu; Pang et al. 2019). This is non-optional: without augmentation diversity, both models learn the same shortcuts and the ensemble provides near-zero benefit against adversarial examples targeting dataset artifacts (28% of top features per arxiv 2602.14161).

4. **OR-vote inflates FPR from 3.8% toward 7-9%** — Current FPR is already at operational boundary. Mode-gate OR-vote to STRICT mode (agent instruction files); use confidence threshold p > 0.65 in standard mode; measure ensemble FPR on held-out benign set before finalizing vote policy. Both models will share correlated false positives on the same ambiguous content (CLAUDE.md, .clinerules, system prompts).

5. **False sense of security framing** — Ensemble does not stop adaptive attackers with both public ONNX models. The correct framing throughout: "raises attacker cost." NIST AI 100-2e2025 requires adaptive attack evaluation as mandatory in any adversarial robustness claim. Report adaptive ensemble attack results (Stage 2) alongside non-adaptive results. Never use "secure" or "protected" in benchmark writeup.

---

## Implications for Roadmap

Based on combined research, the natural phase structure follows the hard dependency chain: transferability gate → model training/export → integration/voting → benchmark/publication.

### Phase 1: Transferability Gate and Architecture Validation

**Rationale:** Everything else in v0.3.0 is blocked by this. Fine-tuning DeBERTa on 6,340 samples takes compute time; if the gate fails, that investment is wasted. Use ProtectAI's existing `deberta-v3-small-prompt-injection-v2` as a proxy before committing to custom training — evaluate it against CloneGuard's adversarial benchmark to measure transfer rate at zero training cost. Only if the proxy passes the 40% gate does custom fine-tuning proceed.

**Delivers:** Go/no-go decision on ensemble approach; if go, validated architecture choice with empirical transfer rate baseline.

**Addresses:** Transferability experiment (P1 feature); architecture selection validation.

**Avoids:** Pitfall 1 (constant predictions — export validated during proxy eval), Pitfall 2 (misleading experiment — adaptive attack stage designed upfront), Pitfall 7 (false security framing — gate threshold defined before results).

**Research flag:** Standard patterns — TextAttack methodology is well-documented; ProtectAI ONNX loading is documented. No deep research needed.

### Phase 2: DeBERTa-v3-small Fine-Tune and ONNX Export

**Rationale:** Only begins after Phase 1 gate passes. Training the model correctly requires differential augmentation for DeBERTa vs. MiniLM before the training run, not after. ONNX export must include automated sanity check as part of the export script.

**Delivers:** `deberta-v3-small-prompt-injection-classifier` ONNX model ready for integration; `scripts/train_ensemble_model.py`; `scripts/training_utils.py`; `scripts/fetch_ensemble_model.py`.

**Uses:** `microsoft/deberta-v3-small`, `optimum[onnxruntime]>=1.24.0`, `torch>=2.2.0`, differential augmentation pipeline (back-translation or character perturbations different from v3 augmentation used for MiniLM).

**Avoids:** Pitfall 1 (ONNX export breakage — automated sanity check), Pitfall 3 (correlated boundaries — differential augmentation), Pitfall 6 (latency budget — INT8 quantization post-export, CPUExecutionProvider latency probe before architecture commitment).

**Research flag:** Needs research. Differential augmentation pipeline specifics for DeBERTa need a focused sub-task. Also: INT8 quantization validation procedure for DeBERTa ONNX needs verification on Apple M-series hardware.

### Phase 3: Ensemble Integration and Voting Policy

**Rationale:** Once ONNX model is ready and validated, wiring the voting logic into the existing pipeline is straightforward. The architecture is fully specified (two new modules + two modified callers). Mode-gated voting must be finalized after measuring ensemble FPR on held-out benign set.

**Delivers:** `ensemble_semantic.py`, `ensemble.py`, modified `hooks.py`, `scanner.py`, `mcp_plugin.py`; disagreement state in JSON hook output; graceful degradation (four availability states); version bump to 0.3.0.

**Implements:** EnsembleClassifier, VoteResult, parallel vote table, lazy-loaded singleton pattern extension, disagreement-as-WARNING conservative policy.

**Avoids:** Pitfall 4 (OR-vote FPR inflation — mode-gated OR-vote, confidence threshold p > 0.65 in standard mode); Anti-patterns 1-5 from ARCHITECTURE.md (voting logic centralized in ensemble.py, one class per model, no threading).

**Research flag:** Standard patterns — architecture is fully specified. No deep research needed.

### Phase 4: Adversarial Benchmark and Publication Prep

**Rationale:** The benchmark is the publishable artifact. It must include both non-adaptive and adaptive (ensemble-targeting) attack results per NIST AI 100-2e2025 requirements. Correlated failure analysis (which samples both models get wrong) is required before reporting ensemble FPR as a single number.

**Delivers:** Extended `scripts/multitier_benchmark.py` with ensemble adversarial benchmark; ASR/FR/robust accuracy table; correlated failure analysis; HuggingFace model card update; results in `docs/results/`; version 0.3.0 tagged.

**Addresses:** Ensemble adversarial benchmark (P1 feature); fooling rate published alongside F1 (differentiator); second model trained on same dataset (differentiator).

**Avoids:** Pitfall 2 (misleading experiment — both attack stages reported), Pitfall 5 (correlated vulnerability documented as known limitation), Pitfall 7 (honest framing — "raises attacker cost" throughout).

**Research flag:** Adaptive ensemble attack (Stage 2) design may need a targeted research sub-task if AdaEA-style multi-gradient optimization is not already in the benchmark plan.

### Phase Ordering Rationale

- Phase 1 gates Phase 2 on empirical evidence, not theory. Proxy model evaluation costs one day; training costs compute and calendar time. The gate prevents sunk cost.
- Differential augmentation must be designed before Phase 2 training, not after. Decision boundary diversity cannot be retrofitted.
- Phase 3 integration is straightforward once the ONNX artifact exists. The architecture is fully specified and the build order is dependency-correct.
- Phase 4 benchmark must be the last phase because it depends on the integrated ensemble being operational. Running the benchmark before voting policy is finalized would require rerunning it.
- Across all phases: maintain the "raises attacker cost" framing. Do not claim the ensemble blocks adaptive attackers.

### Research Flags

Phases needing deeper research during planning:
- **Phase 2:** Differential augmentation pipeline specifics — what augmentation strategy to use for DeBERTa training that is meaningfully different from the back-translation + paraphrase used for v3 MiniLM augmentation. Also: INT8 dynamic quantization verification on Apple M-series CPUExecutionProvider — no authoritative M-series CPU benchmark found for DeBERTa ONNX.
- **Phase 4:** Adaptive ensemble attack implementation — if AdaEA (Chen et al. ICCV 2023) joint gradient optimization is out of scope, define the minimum viable adaptive attack that satisfies NIST AI 100-2e2025 requirements.

Phases with standard patterns (skip deep research):
- **Phase 1:** TextAttack methodology and ProtectAI ONNX loading are fully documented; proxy model evaluation procedure is straightforward.
- **Phase 3:** Architecture fully specified in ARCHITECTURE.md; all integration points, build order, and anti-patterns documented.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | DeBERTa-v3-small: 5 agents converge. ONNX export gotchas verified via primary GitHub issues. TokenBreak paper directly confirms tokenizer rationale. ProtectAI production model validates toolchain. One known gap: M-series CPU latency for DeBERTa INT8 — no authoritative benchmark found. |
| Features | MEDIUM-HIGH | MVP scope well-defined. Voting strategy HIGH (evidence from multiple peer-reviewed sources). Transferability experiment design MEDIUM (no study directly measures MiniLM-to-DeBERTa for prompt injection specifically). |
| Architecture | HIGH | Codebase read directly. All component boundaries, data flows, anti-patterns, and build order specified from source. Two ONNX gotchas verified via primary GitHub issues. |
| Pitfalls | HIGH | All critical pitfalls verified via primary GitHub issues, peer-reviewed papers (NeurIPS 2023, EMNLP 2021, NIST AI 100-2e2025), or direct codebase analysis. Adversarial plan validation adds 5 independent agent confirmations on key risks. |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address

- **Differential augmentation strategy for DeBERTa:** The research confirms this is required but does not specify which augmentation pipeline to use. Need to define concrete augmentation for Phase 2 (back-translation via a specific library, character-level perturbations, paraphrase model) that does not overlap with v3 augmentation rounds 7-8. Address in Phase 2 planning.

- **DeBERTa INT8 ONNX latency on Apple M-series CPUExecutionProvider:** No authoritative benchmark found. The 40-60ms estimate is derived from parameter count scaling from known MiniLM latency. A latency probe must be the first step of Phase 2 before committing to the architecture. If latency exceeds 80ms per 128-token window, DeBERTa-v3-xsmall becomes the fallback.

- **Adaptive ensemble attack implementation scope:** NIST AI 100-2e2025 requires adaptive evaluation. AdaEA (Chen et al. ICCV 2023) joint gradient optimization is the gold standard but may be out of v0.3.0 scope. Define the minimum viable adaptive attack that satisfies the requirement without requiring ICCV-level implementation effort. Address in Phase 4 planning.

- **WARNING rate on benign inputs:** If ensemble disagreement rate on benign inputs exceeds 10%, the WARNING tier becomes operationally noisy. This cannot be measured until Phase 3 integration. Set ceiling threshold in Phase 3 planning and make it a go/no-go criterion for Phase 4.

---

## Sources

### Primary (HIGH confidence)

- arxiv:2506.07948 (TokenBreak) — 55.62% WordPiece vs 0% Unigram adversarial success; directly confirms tokenizer dissimilarity rationale
- arxiv:2504.08716 — ModernBERT vs DeBERTa-v3 controlled study; DeBERTa-v3 superior on classification
- huggingface/optimum issue #2075 — DeBERTa-v3 ONNX CLI export always-same-label bug; confirmed unresolved
- huggingface/optimum issue #968 — `token_type_ids` / `pipeline()` bug; confirmed closed "not planned"
- ProtectAI deberta-v3-small-prompt-injection-v2 (HuggingFace) — production ONNX model for identical task; F1=94.62%; validates toolchain
- NIST AI 100-2e2025 — adversarial ML taxonomy; adaptive attack evaluation as mandatory standard
- arxiv:2111.09543 (DeBERTaV3) — original RTD + GDES architecture paper
- NeurIPS 2023: Deng & Mu, "Understanding and Improving Ensemble Adversarial Defense" — diversity training required for meaningful ensemble robustness
- Pang et al. 2019 (arxiv:1901.09981) — diversity training; correlated decision boundaries as primary ensemble failure mode
- arxiv:2602.14161 — 28% of PI classifier features are dataset shortcuts; confirms correlated vulnerability risk
- Athalye, Carlini, Wagner 2018 — Obfuscated Gradients; ensemble gradient attacks on systems with combined gradients
- Chen et al. ICCV 2023 (AdaEA) — adaptive ensemble attacks; two-model ensembles particularly vulnerable

### Secondary (MEDIUM confidence)

- Yuan et al. EMNLP 2021 (aclanthology.org/2021.emnlp-main.121) — NLP adversarial transfer rates 12-55%; four transfer factors
- Papernot et al. 2016 (arxiv:1605.07277) — foundational transferability theory
- Tramèr et al. ICLR 2018 (arxiv:1705.07204) — ensemble adversarial training; black-box transfer vulnerability
- Morris et al. EMNLP 2020 — TextAttack framework; standard attack library
- Scientific Reports 2025 (PMC12019570) — weighted average 98.78% vs majority 87.34% in intrusion detection ensemble
- Krishnan et al. NAACL 2021 — BERT transferability despite architectural mismatch; model extraction threat
- huggingface/transformers issue #35545 — ModernBERT ONNX export fragility; closed Feb 2026, exact resolution unclear

### Tertiary (LOW confidence)

- ONNX Runtime CPUExecutionProvider latency patterns (inworld.ai blog) — cited for architectural pattern; no authoritative benchmark
- DeBERTa INT8 latency estimates (15-20ms per 128-token sequence) — derived from parameter scaling; unverified on Apple M-series CPUExecutionProvider; must be empirically verified in Phase 2

---

*Research completed: 2026-03-10*
*Ready for roadmap: yes*
