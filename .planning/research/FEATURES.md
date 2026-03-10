# Feature Research

**Domain:** Ensemble adversarial resilience for NLP security detectors
**Researched:** 2026-03-10
**Confidence:** MEDIUM (voting strategies HIGH, transferability experiment design MEDIUM, second model selection MEDIUM, metrics MEDIUM)

---

## Context and Scope

This document covers the feature landscape for adding white-box adversarial resilience to CloneGuard's Tier 1.5 (MiniLM-L6-v2 ONNX). The threat: a skilled adversarial ML practitioner can compute exact gradients against the public model and craft near-perfect evasions. The defense: an architecturally diverse second classifier whose decision surface is sufficiently disjoint that white-box attacks on MiniLM do not transfer.

Existing system (out of scope here): Tier 0 regex (193 patterns), Tier 1.5 MiniLM-L6-v2 ONNX, Tier 2 Ollama, 4-layer hook defense, trust cache, MCP plugin.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features the adversarial ML literature treats as non-negotiable for a credible ensemble defense. Missing these makes the ensemble trivially defeatable or unverifiable.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Parallel vote (both models on every input) | A cascade allows an attacker to target only the first-stage model; parallel voting forces the attacker to simultaneously evade two decision surfaces | MEDIUM | PROJECT.md already chose this over cascade; confirm it holds under latency budget (~120ms) |
| Architecturally diverse second model | Adversarial examples transfer significantly less across models with different tokenization schemes and attention mechanisms (Yuan et al., EMNLP 2021; Papernot et al., 2016) | HIGH | DeBERTa-v3-small uses SentencePiece tokenizer vs MiniLM WordPiece — this difference is a primary transferability barrier |
| ONNX-only inference for second model | Runtime constraint: no PyTorch at inference. Both classifiers must run under onnxruntime CPUExecutionProvider | HIGH | DeBERTa-v3 ONNX export via Optimum is confirmed working (ProtectAI maintains `deberta-v3-base-injection-onnx`); the ModernBERT ONNX path has open issues (Flash Attention dtype conflicts, closed Feb 2026 but resolution unclear — LOW confidence on ModernBERT) |
| Transferability validation experiment | Trust no theory — validate empirically that white-box attacks against MiniLM fail to transfer meaningfully to the second model | HIGH | Standard methodology: craft adversarial examples against source model using TextFooler/PWWS/GA on held-out set, measure fooling rate on target model. This is the go/no-go gate for the entire milestone |
| Ensemble adversarial benchmark with published results | Users and reviewers need reproducible, published evidence of resilience improvement | MEDIUM | Extend existing `scripts/multitier_benchmark.py`; report pre- and post-ensemble adversarial recall and FPR |
| Voting strategy with documented tradeoff rationale | The specific voting rule materially affects FPR and recall; an undocumented choice is a liability | LOW | See "Voting Strategy Comparison" section below |

### Differentiators (Competitive Advantage)

Features that go beyond standard ensemble practice and reflect the domain-specific context.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Disagrement-flagged output (ensemble split verdict) | When Tier 1.5 and Tier 1.6 disagree, surface this as a distinct output state ("inconclusive") rather than forcing a binary result — preserves information that an attacker is testing the boundary | MEDIUM | Distinct from abstention; the disagreement signal is itself a security indicator. Requires hook output format change to expose three states: clean, flagged, inconclusive |
| Confidence-weighted soft voting with documented threshold | Allows tuning the FPR/recall tradeoff post-deployment without retraining; particularly valuable as CloneGuard's production FPR baseline (3.8%) is already visible | MEDIUM | Weight = model's softmax probability for the malicious class; threshold tuned on held-out benign set. Requires exposing calibrated probabilities from both ONNX models |
| Transferability fooling rate published alongside F1 | The adversarial ML community evaluates defenses on fooling rate reduction, not just clean-set F1. Publishing this makes the security claim falsifiable | LOW | Define: FR(src→tgt) = fraction of adversarial examples that fool source and also fool target. Target: FR(MiniLM→Tier1.6) < 30% for white-box attacks |
| Second model trained on same 6,340-sample dataset | Training on identical data isolates the architectural diversity variable — any robustness gain is attributable to architecture, not data advantage | HIGH | Required by PROJECT.md constraint. Means Tier 1.6 trains on `prodnull/prompt-injection-repo-dataset` v3 |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Cascade ensemble (sequential: run Tier 1.6 only if Tier 1.5 flags) | Appears to save latency — Tier 1.6 only fires on suspicious inputs | Exposes Tier 1.6 architecture to an attacker who observes which inputs reach it; also means a white-box evasion of Tier 1.5 never reaches Tier 1.6 — the model most resistant to that attack class | Parallel vote: both models run on every input; latency budget allows this (~16ms Tier 1.5 + ~50-80ms Tier 1.6 small = ~120ms total) |
| Unanimous voting (both must flag to block) | Lowers FPR — only flags content both models agree on | Recall drops sharply; an attacker needs only to evade one model; unanimous voting degrades to single-model resilience against targeted attacks | Majority voting (either flags = block) for security contexts where FPR is recoverable but missed attacks are not |
| Averaging raw logits across models | Simple to implement; appears mathematically principled | Models have different output scales and calibrations; MiniLM and DeBERTa logit magnitudes are not comparable without calibration | Soft vote on normalized softmax probabilities; or hard vote with tie-breaking rule |
| Adversarial training of Tier 1.5 as defense | Straightforward literature recommendation | Adversarial training on a public model with a published architecture remains vulnerable to adaptive attacks that specifically target the defended model; requires ongoing adversarial example generation to stay current; adds training complexity | Architectural diversity via ensemble is more maintainable and creates a moving target harder to adapt against |
| Certified robustness / randomized smoothing | Provides provable guarantees against l-norm bounded perturbations | Text is discrete — standard randomized smoothing does not apply directly. Text-specific certified robustness (IBP, interval bound propagation) is experimental and requires architecture changes. Deferred per PROJECT.md | Empirical adversarial benchmarking with published fooling rates — honest about what the defense does and does not guarantee |
| Adding multilingual adversarial test cases | Seems like coverage expansion | Out of scope per PROJECT.md (deferred to GitHub issue #5); multilingual adversarial examples require separate dataset curation and would dilute v0.3.0 scope | Document the limitation in PITFALLS.md; add a smoke test referencing issue #5 |
| ModernBERT as second architecture | Newest encoder, strong benchmark numbers | ONNX export has documented incompatibilities with Flash Attention 2.0 (GitHub issue #35545, closed Feb 2026 with unclear resolution); unvalidated for CPUExecutionProvider without Optimum at runtime; adds risk without validated ONNX path | DeBERTa-v3-small: confirmed ONNX export, ProtectAI maintains a production ONNX variant, 44M params, SentencePiece tokenizer maximizes architecture distance from MiniLM |

---

## Voting Strategy Comparison

This is the central design decision for this milestone. Evidence from the literature and domain context drives the recommendation.

### Strategy 1: Hard Majority Vote (Either-Flags-Blocks)

**Rule:** Block if Tier 1.5 OR Tier 1.6 classifies as malicious.

**Recall:** Maximum — attacker must simultaneously evade both models.
**FPR:** Additive — combined FPR ≈ 1 - (1 - FPR_1) * (1 - FPR_2) assuming independence. At current FPR_1=3.8%, if FPR_2=5%, combined ≈ 8.6%.
**Attack resistance:** Highest — requires white-box access to both models simultaneously.
**Tuning surface:** Binary; no post-deployment tuning.

**When to use:** When the cost of a missed injection is higher than the cost of a false block (agentic contexts, automated pipelines).

### Strategy 2: Unanimous Vote (Both-Must-Flag)

**Rule:** Block only if both Tier 1.5 AND Tier 1.6 classify as malicious.

**Recall:** Minimum — attacker needs to evade only one model; recall degrades toward the weaker model's recall.
**FPR:** Multiplicative — combined FPR ≈ FPR_1 * FPR_2. At FPR_1=3.8% and FPR_2=5%, combined ≈ 0.19%.
**Attack resistance:** Weakest against targeted attacks — defeats only untargeted, broad attacks.
**When to use:** When FPR tolerance is extremely low and missed injections are recoverable by other defense layers.

**Verdict: Not recommended for CloneGuard.** Tier 0 and Tier 2 provide FPR mitigation; recall must remain primary objective.

### Strategy 3: Soft Confidence Vote (Weighted Average Softmax)

**Rule:** Block if weighted_avg(P_mal_1, P_mal_2) >= threshold θ. Weights can reflect model calibration quality.

**Recall and FPR:** Continuously tunable via θ. At θ=0.5 with equal weights, similar to hard majority vote in expectation.
**Benefit:** Preserves calibration signal; allows post-deployment tuning without retraining.
**Cost:** Requires calibrated probabilities. Both models must be temperature-scaled or Platt-calibrated against held-out set. Adds one calibration experiment to the training pipeline.
**Evidence:** An ensemble defense framework for intrusion detection reported 98.78% accuracy under weighted average vs 87.34% under majority voting on the same data (Scientific Reports, PMC12019570) — the gap reflects that weighted averaging exploits confidence information unavailable in hard voting.

**When to use:** When post-deployment tuning is expected; when the operator wants a dial between FPR and recall.

### Strategy 4: Disagreement State (Three-Way Output)

**Rule:** If Tier 1.5 and Tier 1.6 disagree, emit "inconclusive" rather than defaulting to either vote.

**Security value:** The disagreement signal is itself an adversarial indicator — a well-crafted adversarial example will often fool one model but not both, creating a disagreement state that does not appear on clean inputs. Surfacing this state allows the hook layer to apply escalating scrutiny (e.g., trigger Tier 2 Ollama review only on inconclusive cases).
**Cost:** Requires hook output format extension; adds a third state that callers must handle.
**FPR behavior:** Depends on how callers handle "inconclusive." If treated as "warn but allow," FPR stays low. If treated as "block," FPR increases to majority-vote level.

### Recommendation

**Implement hard majority vote as default (Strategy 1) with disagreement state exposed as metadata (Strategy 4), and add confidence scores to hook output to enable post-deployment soft threshold tuning (Strategy 3).**

Rationale:
- Hard majority vote maximizes recall, which is the primary security objective.
- Disagreement state adds a zero-cost adversarial signal on top of hard vote.
- Exposing confidence scores costs nothing at inference time (softmax output is already computed) and enables future tuning without code changes.
- FPR increase from ~3.8% to ~8% (estimated) is acceptable given existing Tier 0 and Tier 2 complement.

---

## Transferability Experiment Design

The transferability experiment is the empirical gate: before committing to the second architecture, validate that white-box attacks against MiniLM transfer at a meaningfully lower rate to DeBERTa-v3-small.

### Standard Methodology (after Yuan et al., EMNLP 2021; Papernot et al., 2016)

**Step 1: Source model white-box attack generation**

Generate adversarial examples against Tier 1.5 (MiniLM) using at minimum two attack algorithms:
- PWWS (Probability Weighted Word Saliency) — gradient-informed word substitution
- TextFooler (Jin et al., AAAI 2020) — synonym-based greedy substitution
- GA (Genetic Algorithm, Jia et al.) — population-based search, less gradient-dependent

Use TextAttack library (Morris et al., EMNLP 2020 Demo) for standardized implementation. Apply attacks to the held-out adversarial benchmark (185 malicious samples).

**Step 2: Define metrics**

Primary: **Fooling Rate (FR)** — standard in the transferability literature:
```
FR(source → target) = |examples that fool both source AND target| / |examples that fool source|
```

Secondary metrics to report:
- **Attack Success Rate (ASR)** on source model = baseline attack effectiveness
- **Robust Accuracy** on target model under transferred examples = what actually matters
- **Robustness Degradation Ratio (RDR)** = (clean_accuracy - adversarial_accuracy) / clean_accuracy — smaller is better
- **Confidence distribution shift** — does the target model's confidence drop on transferred adversarial examples even when it classifies correctly? A large drop suggests the attack is finding a shared vulnerability even without fooling the model

**Step 3: Establish baseline transfer rate**

Run attacks against MiniLM (white-box), then evaluate transferred examples against a same-architecture second MiniLM instance (control condition). This establishes the ceiling: FR(MiniLM→MiniLM) = upper bound, expected near 100% since same architecture.

**Step 4: Measure cross-architecture transfer**

Evaluate same adversarial examples against DeBERTa-v3-small. Report FR(MiniLM→DeBERTa).

**Threshold for proceeding:** If FR(MiniLM→DeBERTa) < 40%, architectural diversity is providing meaningful defense. If FR > 60%, reconsider architecture choice. Target from project memory: < 30%.

The literature (Yuan et al. 2021, studying 63 models) found that: (a) different tokenization schemes are the single largest barrier to transfer; (b) different architecture families (LSTM vs Transformer vs CNN) have lower transfer than same-family variants; (c) different embedding types reduce transfer. MiniLM (WordPiece, 384-dim sentence embedding) vs DeBERTa-v3 (SentencePiece, disentangled attention) spans multiple of these barriers simultaneously — MEDIUM confidence that FR will be below 40%.

**Step 5: Report**

Produce a table structured as:
```
| Attack | ASR on MiniLM | FR → DeBERTa | FR → MiniLM-same-arch |
|--------|---------------|--------------|------------------------|
| PWWS   | X%            | Y%           | Z% (control)           |
| TextFooler | X%        | Y%           | Z%                     |
| GA     | X%            | Y%           | Z%                     |
```

This table is the publishable artifact. Include it in the HuggingFace model card update.

---

## Metrics That Matter for Ensemble Adversarial Robustness

Beyond standard F1 and accuracy, these metrics have validated status in the adversarial ML literature:

| Metric | Definition | Why It Matters Here |
|--------|------------|---------------------|
| Attack Success Rate (ASR) | Fraction of adversarial examples that fool the target | Baseline for attack strength; must be measured on MiniLM alone before ensemble |
| Fooling Rate (FR) | FR(src→tgt) = adversarial examples that fool source AND target / adversarial examples that fool source | Directly measures what the ensemble buys; primary transferability metric |
| Robust Accuracy | Accuracy on adversarial examples (lower = more vulnerable) | Ensemble must maintain recall on adversarial examples, not just clean inputs |
| Robustness Degradation Ratio (RDR) | (clean_acc - adv_acc) / clean_acc | Scale-normalized measure; useful for comparing across models with different baseline accuracies |
| False Block Rate under adversarial distribution | FPR measured on adversarial inputs that the models classify as benign (false negatives) plus benign inputs classified as malicious (false positives) | Reveals whether the ensemble's FPR increase is driven by adversarial examples or by clean text degradation |
| Confidence distribution on transferred examples | Mean and spread of softmax P(malicious) on adversarial examples evaluated against each model | Even if the model doesn't get fooled, a confidence shift toward 0.5 signals the attack is finding shared weak spots |
| Ensemble agreement rate on adversarial examples | Fraction of adversarial examples where both models agree on label | Low agreement = disagreement signal fires; useful for calibrating the "inconclusive" state |

**Do not report:** Certified robustness bounds (text discrete space makes l-norm certificates inapplicable). Semantic similarity scores (standard adversarial evaluation metric for NLP, but less relevant here since CloneGuard operates on repository content, not natural language test sets).

---

## Feature Dependencies

```
[Transferability Experiment]
    └──gates──> [Second ONNX Classifier (Tier 1.6)]
                    └──requires──> [ONNX export of DeBERTa-v3-small fine-tuned on v3 dataset]
                                       └──requires──> [Fine-tuning run on 6,340-sample dataset]

[Parallel Vote Logic]
    └──requires──> [Tier 1.6 ONNX model in place]
    └──requires──> [Confidence score output from both models]

[Disagreement State in Hook Output]
    └──requires──> [Parallel Vote Logic]
    └──enhances──> [Tier 2 Ollama escalation (optional — use inconclusive as Tier 2 trigger)]

[Ensemble Adversarial Benchmark]
    └──requires──> [Parallel Vote Logic]
    └──requires──> [Transferability Experiment results]
    └──enhances──> [HuggingFace model card update]
```

### Dependency Notes

- **Transferability experiment gates second model commitment:** If FR(MiniLM→DeBERTa) > 60%, the architecture choice needs revision before training. Run the experiment on ProtectAI's existing `deberta-v3-base-injection-onnx` as a proxy before full fine-tuning.
- **Confidence scores required for soft voting and disagreement:** This means ONNX models must return softmax probabilities, not just argmax labels. Both models already do this; confirm in integration.
- **Disagreement state conflicts with binary hook exit code:** Hook exit codes are 0 (allow) or 2 (block). Disagreement state must be communicated via JSON stdout, not exit code. No conflict with existing format.

---

## MVP Definition

### Launch With (v0.3.0)

Minimum needed to validate adversarial resilience claim and publish results.

- [ ] Transferability experiment: FR(MiniLM→DeBERTa) measured with PWWS and TextFooler, results tabulated — **required to make any claim about white-box resilience**
- [ ] DeBERTa-v3-small fine-tuned on v3 dataset (6,340 samples), exported to ONNX CPUExecutionProvider — **the second classifier**
- [ ] Hard majority vote integration in `scan` and hook pipeline — **the actual defense**
- [ ] Disagreement state in JSON hook output — **zero marginal cost; high security signal value**
- [ ] Ensemble adversarial benchmark: ASR/FR/robust accuracy table, pre- and post-ensemble recall and FPR — **the publishable evidence**

### Add After Validation (v0.3.x)

- [ ] Soft confidence vote with tunable threshold θ — trigger: operators requesting FPR tuning without retraining
- [ ] Temperature calibration of both models against held-out benign set — required before soft vote is meaningful
- [ ] Tier 2 (Ollama) auto-escalation on inconclusive state — trigger: validation that inconclusive correlates with adversarial inputs in production

### Future Consideration (v0.4+)

- [ ] Adversarial fine-tuning of Tier 1.6 with transferred examples from Tier 1.5 — deferred until transfer rate data is in hand
- [ ] ModernBERT as third ensemble member — deferred until ONNX export issues are confirmed resolved and latency budget allows
- [ ] Automated adversarial example generation in CI — trigger: production white-box attack attempt observed

---

## Feature Prioritization Matrix

| Feature | Security Value | Implementation Cost | Priority |
|---------|----------------|---------------------|----------|
| Transferability experiment | HIGH (empirical gate) | MEDIUM | P1 |
| DeBERTa-v3-small fine-tune + ONNX export | HIGH | HIGH | P1 |
| Hard majority vote integration | HIGH | LOW | P1 |
| Ensemble adversarial benchmark | HIGH (publishable) | MEDIUM | P1 |
| Disagreement state in JSON output | MEDIUM | LOW | P1 |
| Soft confidence vote with threshold | MEDIUM | MEDIUM | P2 |
| Temperature calibration | MEDIUM | LOW | P2 |
| Tier 2 escalation on inconclusive | LOW | MEDIUM | P3 |
| ModernBERT as third member | LOW (ONNX risk) | HIGH | P3 |

---

## Existing Ensemble Prompt Injection Detectors

The closest prior art, relevant for learning and for framing CloneGuard's contribution:

| System | Architecture | Ensemble Approach | Notes |
|--------|-------------|-------------------|-------|
| ProtectAI deberta-v3-base-injection-onnx | DeBERTa-v3-base fine-tuned | Single model, ONNX export via Optimum | Production ONNX path confirmed; 99.93% accuracy on eval set. Source for second model architecture choice. |
| deepset/deberta-v3-base-injection | DeBERTa-v3-base | Single model | Trained on deepset/prompt-injections dataset |
| Sentinel (DMPI-PMHFE, SpringerLink 2025) | DeBERTa + heuristic feature engineering | Dual-channel fusion (semantic + structural) | Average F1=0.938 vs baseline 0.709; not ONNX; not open source |
| Embedding + tree classifier (MDPI 2025) | GTE-large / MiniLM / OpenAI embeddings + XGBoost/Random Forest | Embedding model swap comparison, not true ensemble | Different from architectural ensemble; listed for contrast |

**Gap CloneGuard fills:** No open-source system currently combines an ONNX sentence-embedding model (MiniLM) with an ONNX disentangled-attention encoder (DeBERTa) in a parallel vote architecture specifically targeting white-box adversarial resilience for AI coding agent contexts. The dual-channel fusion approach (Sentinel) is closest in spirit but not open or ONNX-deployable.

---

## Sources

- Yuan et al. (EMNLP 2021): "On the Transferability of Adversarial Attacks against Neural Text Classifier" — https://aclanthology.org/2021.emnlp-main.121/ — 63 models, four transferability factors (architecture, tokenization, embedding, capacity)
- Papernot et al. (2016): "Transferability in Machine Learning: from Phenomena to Black-Box Attacks using Adversarial Samples" — https://arxiv.org/abs/1605.07277 — foundational transferability theory
- Tramèr et al. (ICLR 2018): "Ensemble Adversarial Training: Attacks and Defenses" — https://arxiv.org/abs/1705.07204 — ensemble defense + black-box transfer vulnerability
- Morris et al. (EMNLP 2020): "TextAttack: A Framework for Adversarial Attacks" — https://aclanthology.org/2020.emnlp-demos.16/ — standard attack library
- MDPI Computers 2025: "Lexicon-Based Random Substitute and Word-Variant Voting Models" — https://www.mdpi.com/2073-431X/14/8/315 — voting strategy ensemble for adversarial text defense
- Scientific Reports 2025 (PMC12019570): "Enhanced ensemble defense framework for boosting adversarial robustness of intrusion detection systems" — https://pmc.ncbi.nlm.nih.gov/articles/PMC12019570/ — voting strategy comparison (majority 87.34% vs weighted 98.78%)
- MDPI Mathematics 2024: "Improving Adversarial Robustness of Ensemble Classifiers by Diversified Feature Selection and Stochastic Aggregation" — https://www.mdpi.com/2227-7390/12/6/834
- ProtectAI deberta-v3-base-injection-onnx: https://huggingface.co/protectai/deberta-v3-base-injection-onnx — production DeBERTa ONNX deployment reference
- ProtectAI deberta-v3-small-prompt-injection-v2: https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2 — small variant, faster inference
- SpringerLink DMPI-PMHFE (2025): "Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering" — https://link.springer.com/chapter/10.1007/978-981-95-3072-4_6 — dual-channel ensemble for prompt injection
- Survey on Transferability (arXiv 2310.17626): https://arxiv.org/html/2310.17626 — fooling rate definition and experimental methodology
- NIST AI 100-2e (2025): "Adversarial Machine Learning" — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf — attack taxonomy and robustness definitions
- GitHub transformers issue 35545: ModernBERT ONNX export failures — https://github.com/huggingface/transformers/issues/35545

---

*Feature research for: ensemble adversarial resilience — CloneGuard v0.3.0*
*Researched: 2026-03-10*
