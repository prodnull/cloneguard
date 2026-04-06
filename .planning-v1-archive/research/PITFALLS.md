# Pitfalls Research

**Domain:** Ensemble adversarial classifier — adding a second ONNX classifier to an existing single-model prompt injection detection system
**Researched:** 2026-03-10
**Confidence:** HIGH (ONNX issues, correlated errors, voting tradeoffs verified via primary GitHub issues + peer-reviewed literature). MEDIUM on specific latency numbers (no authoritative M-series CPU benchmark found for DeBERTa ONNX).

---

## Critical Pitfalls

### Pitfall 1: Transferability Experiment Gives a Misleadingly Optimistic Verdict

**What goes wrong:**

You generate adversarial examples against MiniLM-L6-v2 using a standard gradient-based attack (e.g., FGSM, PGD, TextFooler), measure how many transfer to the second architecture, observe a low transfer rate (~20-40% is common cross-architecture), and conclude the ensemble is robust. The conclusion is wrong in two distinct ways:

1. **The attack was not adaptive.** The experiment tests non-adaptive (static) black-box transfer. A real white-box attacker — who knows the ensemble exists and has access to both model weights — can craft examples targeting the union of both models' decision boundaries simultaneously. Meta research showed static attacks achieved 0-28% success while adaptive attacks achieved 90-100% against all 12 published PI defenses (Willison 2025 summary of Meta SHADE-Arena results).

2. **Transfer experiments use the same attack vocabulary.** TextFooler, BERT-Attack, and similar word-substitution attacks were optimized against BERT-family models. DeBERTa and MiniLM share WordPiece/SentencePiece subword tokenization roots. An attack that exploits shared tokenization artifacts (e.g., OOV handling, subword boundary tokens) transfers more readily than the raw architecture difference suggests. Cross-architecture transfer is higher when tokenizers overlap.

**Why it happens:**

Transfer experiments are cheap to run and generate a number that looks like validation. Teams treat a 25% transfer rate as proof of ensemble benefit without stress-testing whether an adaptive attacker achieves the same rate. The ACL EMNLP 2021 systematic study (Yuan et al., "On the Transferability of Adversarial Attacks Against Neural Text Classifiers") confirmed that architectural similarity, shared tokenization, and embedding similarity are the dominant factors — not model family alone.

**How to avoid:**

Run a two-stage experiment:
- Stage 1 (non-adaptive): transfer rate from standard attacks. Expect 15-45% cross-architecture.
- Stage 2 (adaptive): craft adversarial examples against both models simultaneously (ensemble attack). Use the combined logit or loss as the optimization target. If Stage 2 achieves >60% success, the ensemble provides substantially less protection than Stage 1 suggested.

Report both numbers in the benchmark. Treat Stage 1 as a lower bound on attacker capability, not a ceiling.

**Warning signs:**
- Transfer experiment is only run in one direction (MiniLM → DeBERTa, not DeBERTa → MiniLM)
- No adaptive ensemble attack is designed or attempted
- Transfer rate is used as the primary evidence of robustness without human expert review of attack methodology
- The attack alphabet and the classifier's training vocabulary overlap heavily (same injection phrase templates)

**Phase to address:** Transferability experiment phase (Phase 1). Define adaptive attack baseline before declaring the experiment conclusive.

---

### Pitfall 2: DeBERTa-v3 ONNX Export Produces a Broken Model That Always Predicts One Class

**What goes wrong:**

The optimum-cli export of DeBERTa-v3-base completes without error but generates an ONNX model that always predicts the same label (always BENIGN or always MALICIOUS), regardless of input. This is not caught until the model is evaluated on a validation set, potentially after considerable compute time fine-tuning it.

**Why it happens:**

DeBERTa-v3's disentangled attention mechanism uses `torch.tensor()` to construct position-dependent tensors at runtime. During ONNX tracing, these are registered as constants rather than dynamic operations, producing a graph that ignores the actual input. Seven separate `TracerWarning` instances are generated in the DeBERTa V2/V3 modeling code (verified: GitHub huggingface/optimum issue #2075, huggingface/transformers issue #18237). The resulting ONNX graph appears structurally valid — it will accept inputs and return outputs — but the predictions are degenerate.

Secondary issue: DeBERTa-v3 ONNX files are often double the expected size due to duplicated weight tensors in the export. A DeBERTa-v3-base PyTorch checkpoint (~375 MB) can inflate to ~750 MB in ONNX FP32, and INT8 dynamic quantization is required to reach a deployable size.

**How to avoid:**

1. Use `optimum` `ORTModelForSequenceClassification.from_pretrained(model_id, export=True)` rather than `optimum-cli` for the initial export. This path has better handling of DeBERTa's dynamic tensor issues.
2. Immediately after export, run a sanity check: feed 50 samples with known labels (25 malicious, 25 benign) and verify predictions are not constant. This must be part of the export script, not a manual check.
3. Validate the ONNX model's output distribution against the PyTorch model on the same batch before any downstream evaluation. The maximum acceptable difference per logit should be atol ≤ 0.001 (tighter than optimum's default of 0.0001 for absolute differences in probabilities, but the direction of prediction should never flip).
4. After validating correctness, apply INT8 dynamic quantization (`onnxruntime.quantization.quantize_dynamic`) to reduce model size by ~50-60% with negligible recall impact for encoder-only classifiers.

**Warning signs:**
- Multiple `TracerWarning: torch.tensor results are registered as constants` messages during export
- Exported model achieves 100% precision and 0% recall, or vice versa on any balanced split
- ONNX file size is approximately double the expected PyTorch checkpoint size
- ONNX and PyTorch logits disagree on more than 1-2% of validation examples

**Phase to address:** ONNX export phase (Phase 2). Export sanity check must be an automated test, not a manual step.

---

### Pitfall 3: ModernBERT Cannot Be Exported to ONNX With Standard Tooling

**What goes wrong:**

ModernBERT (answerdotai/ModernBERT-base, 149M params) fails ONNX export entirely under the standard `transformers` + `optimum` stack due to three layered incompatibilities: (1) `torch.compile` is enabled by default and conflicts with `torch.jit.trace`; (2) Flash Attention 2.0 requires float16/bfloat16 but tracing starts in float32; (3) Rotary embeddings use Triton kernels that produce type mismatches (`pointer<int64>` vs `triton.language.int32`) during tracing. As of January 2025, this was unresolved (GitHub huggingface/transformers issue #35545).

**Why it happens:**

ModernBERT was designed for GPU training speed. Its default configuration assumes CUDA availability and uses kernels that are incompatible with CPU-targeted ONNX tracing. The `--optimize` flag in optimum-cli also does not support ModernBERT (huggingface/optimum issue #2177). Export of the base model without fine-tuning may work with specific workarounds (`reference_compile=False`, disabling Flash Attention before export), but a fine-tuned classification head reintroduces the same issues.

**How to avoid:**

Before committing to ModernBERT as the second architecture:
1. Run a feasibility export test on the base model with `reference_compile=False` and `attn_implementation="eager"` (disables Flash Attention).
2. Verify the fine-tuned classifier head can also be exported with those same flags.
3. Accept that ModernBERT ONNX export requires non-default workarounds and may require pinning specific `optimum` and `transformers` versions.

If ModernBERT export remains unstable, DeBERTa-v3-base is the safer choice: it has a known export path via optimum and an existing PI classifier (protectai/deberta-v3-base-prompt-injection-v2) that demonstrates the export is achievable.

**Warning signs:**
- Any mention of `torch.compile` or Flash Attention in error traces during export
- Export succeeds for the base model but fails after adding a classification head
- Export path requires CUDA to run the tracing step

**Phase to address:** Architecture selection phase (Phase 1, before training). Validate ONNX exportability before fine-tuning.

---

### Pitfall 4: Parallel OR-Vote Inflates False Positive Rate to an Operationally Unacceptable Level

**What goes wrong:**

With parallel voting (flag if either model flags), the false positive rate of the ensemble is approximately `1 - (1 - FPR_1) * (1 - FPR_2)`. If MiniLM achieves a false block rate of 3.8% and DeBERTa achieves 5% on the same content distribution, the combined OR-vote false block rate is approximately 8.6% — more than double either individual model. At 3.8% false block rate per hook invocation, the pipeline is already at the operational boundary. An 8.6% rate would cause the tool to block legitimate repository files more than once per typical project scan.

**Why it happens:**

OR-voting is chosen because it maximizes recall (exactly the adversarial resilience goal). The error is forgetting that the two models' false positives are not independent — they share training data and will make correlated false positive errors on the same ambiguous content (legitimate system prompts, CLAUDE.md files, .clinerules, agent configuration). The independence assumption that makes the combined FPR calculation optimistic is violated when both models see the same distribution of benign content that superficially resembles malicious content.

**How to avoid:**

1. Measure per-model FPR on the held-out benign set independently, then measure ensemble FPR on the same set. If ensemble FPR is close to the sum of individual FPRs, errors are independent. If it is close to the maximum of the two, errors are correlated (same benign samples confuse both models).
2. Use confidence-weighted OR: only flag if at least one model exceeds a higher per-model threshold (e.g., p > 0.7 rather than p > 0.5). This shifts the operating point.
3. Reserve pure OR-vote for STRICT mode (agent instruction files) where the false positive cost is lower. Use majority/AND for STANDARD and LENIENT modes.
4. Report ensemble FPR as a first-class metric in the adversarial benchmark alongside recall.

**Warning signs:**
- Ensemble FPR on held-out benign is greater than `max(FPR_1, FPR_2) * 1.5`
- The same legitimate file repeatedly triggers false positives from both models
- CLAUDE.md, `.clinerules`, or agent instruction files trigger warnings at high rate

**Phase to address:** Voting strategy phase (Phase 3). Do not finalize the vote rule until per-model and ensemble FPR are measured together on matched benign samples.

---

### Pitfall 5: Shared Training Data Creates Correlated Vulnerabilities That Negate Ensemble Benefit

**What goes wrong:**

Both models are trained on the same 6,340-sample dataset. They learn to classify the same feature distributions as malicious or benign. Adversarial examples that exploit dataset-level spurious correlations (the 28% shortcut features identified in arxiv 2602.14161) fool both models, because both learned the same shortcuts. The ensemble does not increase adversarial robustness against any attack that targets dataset artifacts rather than architecture-specific features.

**Why it happens:**

Architecture diversity (MiniLM vs. DeBERTa) reduces gradient-space correlation, which helps against white-box gradient attacks. But it does not reduce semantic-space correlation — if both models learned that the phrase "ignore previous instructions" is the canonical malicious signal, both fail on paraphrased variants. The adversarial benchmark (arxiv 2602.14161) found that 28% of top predictive features in prompt injection classifiers are dataset shortcuts, not semantic features. Both models trained on the same dataset inherit the same shortcuts.

**Mitigation** (this cannot be fully avoided with one dataset, but it can be bounded):
1. Evaluate both models individually on the OOD benign eval sets (the 234 held-out benign samples plus the 144 MCP samples from ferentin-net/mcp-guard). If both models fail on the same OOD samples, they share a correlated vulnerability.
2. Use the adversarial benchmark to measure which attack categories fool both models simultaneously. Fragmentation and synonym substitution are the highest-risk categories for correlated failure, given the existing v3 results.
3. Document the correlated vulnerability as a known limitation in the benchmark output, with the honest framing: ensemble improves robustness against architecture-specific white-box attacks but does not improve robustness against dataset artifact attacks.

**Warning signs:**
- Both models have identical recall by attack category (e.g., both fail on fragmentation at exactly the same rate)
- Adversarial examples that fool MiniLM are found to fool DeBERTa at > 65% rate
- OOD evaluation shows both models fail on the same specific samples

**Phase to address:** Dataset planning phase (Phase 1) and benchmark phase (Phase 4). Flag correlated failures in the final benchmark rather than suppress them.

---

### Pitfall 6: Model Size and Latency Budget Blowout From DeBERTa-v3-base

**What goes wrong:**

DeBERTa-v3-base has 184M parameters (compared to MiniLM-L6-v2's 22.7M — an 8x difference). ONNX FP32 export inflates the file size further due to duplicated embeddings. The resulting model is ~700-800 MB on disk before quantization. INT8 dynamic quantization reduces this to ~200-250 MB, but the latency penalty remains significant. At 120ms total budget and ~16ms for MiniLM, DeBERTa-v3-base must complete inference in ≤ 104ms on Apple M-series CPU. For long inputs requiring sliding window (e.g., 512-token chunks), this budget is tight.

INT8 dynamic quantization on DeBERTa-v3 on CPU provides roughly 3x speedup over FP32, with reported latency of 15-20ms per 128-token sequence for similar models. However, latency scales nonlinearly with sequence length for transformer models due to attention complexity. A 512-token sequence is not 4x slower than 128 tokens — it is closer to 8-16x slower due to quadratic attention cost (DeBERTa uses disentangled attention with two sets of attention matrices).

CloneGuard's sliding window approach (currently ~16ms/window for MiniLM at 128 tokens) will need the same treatment for DeBERTa. At 512 tokens, DeBERTa FP32 ONNX on CPU may reach 200-400ms per window, blowing the latency budget entirely.

**How to avoid:**

1. Before committing to DeBERTa-v3-base, run a latency probe: time DeBERTa-v3-base (FP32 ONNX) on 128-token inputs on the target hardware (Apple M-series CPU via CPUExecutionProvider). If > 50ms, apply INT8 quantization and re-measure. If still > 80ms, DeBERTa-v3-base is not viable at the current latency budget.
2. Consider DeBERTa-v3-small (5 layers, ~44M params) as an alternative. It is architecturally distinct from MiniLM (disentangled attention vs. symmetric attention) while being 4x smaller than DeBERTa-v3-base.
3. Use the same sliding window strategy as MiniLM (128-token windows with overlap) rather than attempting to process the full sequence length. Do not use DeBERTa's 512-token context window as an argument for batching large inputs.
4. Measure latency with CPUExecutionProvider explicitly, not with MPS or CUDA, since CloneGuard requires CPUExecutionProvider for ONNX-only inference.

**Warning signs:**
- INT8 quantization is skipped to avoid an extra build step
- Latency is measured on GPU and assumed equivalent for CPU
- Single-window latency exceeds 60ms before the sliding window loop overhead is added
- DeBERTa-v3-large is chosen over DeBERTa-v3-base for accuracy reasons without a latency validation gate

**Phase to address:** Architecture selection (Phase 1) and ONNX export (Phase 2). Latency probe must precede any fine-tuning investment.

---

### Pitfall 7: Ensemble Provides False Sense of Security Against a Skilled Adaptive Attacker

**What goes wrong:**

The ensemble benchmark shows improved recall over MiniLM alone. The team concludes the system is now resilient to white-box attacks. This is overstated. A skilled attacker with access to both exported ONNX models (which will be published on HuggingFace) can:
- Run exact white-box gradient computation against the ensemble (both models' exact weights are public)
- Craft adversarial examples that minimize both models' malicious-class probabilities simultaneously
- Use "Obfuscated Gradients" techniques (Athalye, Carlini, Wagner 2018 — the framework showed that gradient obfuscation gives a false sense of security and applies to defensive ensembles with public weights)

The ensemble raises the cost of white-box attacks but does not eliminate them. With two public models, the attacker has more targets, not fewer. The correct framing is: "ensemble increases attacker cost from X to Y hours of compute" not "ensemble defeats white-box attacks."

**Why it happens:**

Ensemble methods were shown to be highly effective against black-box transfer attacks in the image domain. This finding is frequently overgeneralized to white-box settings, especially when both models are public.

**How to avoid:**

1. Maintain the existing project framing throughout: "raises attacker cost, does not block." Apply this explicitly to the ensemble benchmark writeup.
2. State the white-box threat model explicitly in the benchmark: attacker has both ONNX models, can compute exact gradients, and can run iterative optimization.
3. Report ensemble performance separately for black-box (transfer) attacks and adaptive (ensemble-targeting) attacks if the latter can be implemented.
4. NIST AI 100-2e2025 on adversarial ML recommends adaptive attack evaluation as a mandatory step in any adversarial robustness claim — treat this as a requirement, not an optional validation.

**Warning signs:**
- Benchmark reports only non-adaptive transfer results and calls them "adversarial robustness"
- The word "secure" or "protected" appears in the benchmark writeup
- The adaptive attacker scenario is deferred to future work without an explicit caveat in the current results

**Phase to address:** Benchmark design (Phase 1) and results writeup (Phase 4). Frame the security claim correctly before running experiments.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Skip INT8 quantization | Simpler export pipeline | DeBERTa ONNX model is 700-800 MB, breaking install size targets | Never — always quantize after validating correctness |
| Use FP32 ONNX for latency testing | Avoids quantization complexity | INT8 has different latency profile; FP32 measurements are not representative | Never for latency gating |
| Train second model without held-out OOD eval | Faster iteration | Cannot measure correlated failures between models | Never for adversarial benchmark milestone |
| Use ModernBERT without ONNX export validation | ModernBERT is faster and newer | Export may be broken; discover this after weeks of fine-tuning | Never — validate export before training |
| Soft-vote with raw logits (no calibration) | Simple implementation | Logit scales differ between MiniLM and DeBERTa; soft vote is dominated by the better-calibrated model | Use temperature scaling or normalize to [0,1] probabilities |
| Hard OR-vote without threshold tuning | Maximum recall | False positive rate is sum of both FPRs, not max | Only acceptable in STRICT mode with awareness of FPR impact |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| ONNX export of DeBERTa-v3 | Use `optimum-cli` and trust the output without validation | Use `ORTModelForSequenceClassification.from_pretrained(..., export=True)` and immediately run a 50-sample sanity check for non-constant predictions |
| ModernBERT ONNX export | Export with default model config | Set `reference_compile=False` and `attn_implementation="eager"` before tracing; validate FP32 first, then quantize |
| Sliding window over DeBERTa | Extend window to 512 tokens to use DeBERTa's longer context | Keep 128-token windows matching MiniLM; DeBERTa's quadratic attention makes 512-token windows 4-16x slower |
| Soft-vote probability averaging | Average raw sigmoid outputs without calibration | Calibrate each model independently (temperature scaling), then average calibrated probabilities |
| ONNX CPUExecutionProvider | Benchmark on Mac with Metal or Torch MPS | Set `providers=["CPUExecutionProvider"]` explicitly in benchmarks — M-series accelerators change the profile significantly |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| DeBERTa FP32 ONNX on 512-token sequences | Hook invocation exceeds 300ms | INT8 quantize + 128-token sliding window | First real-world file scan with long READMEs |
| Uncached ONNX session creation per invocation | 2-5 second startup per hook call | Create InferenceSession at module import time, not per-call | Every hook invocation if session is not cached |
| Double-inference on every hook event | Latency doubles relative to single-model | Load both models at startup; for low-signal content, skip second model using Tier 0 pre-filter | Large repositories with many hook events |
| Soft-vote with unnormalized logits | Larger model dominates vote regardless of confidence | Normalize to probabilities via softmax before averaging | Always if models have different logit scales |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Publishing both ONNX models on HuggingFace simultaneously | White-box attacker has exact weights of both models; ensemble gradient attack is trivially constructable | This is unavoidable given the open-source mandate; compensate by framing security as cost-raising, not attack-blocking |
| Treating ensemble recall as security guarantee | Users assume 90%+ recall means 90%+ of attacks are blocked | State that adaptive attackers who know the ensemble exist can target both models; recall numbers apply to the current adversarial benchmark, not future adaptive attacks |
| No per-model confidence threshold in OR-vote | Weak signal from either model triggers a block | Require p > configurable threshold (default 0.65) per model before the OR-vote fires |

---

## "Looks Done But Isn't" Checklist

- [ ] **ONNX export:** Verify that exported DeBERTa model produces non-constant predictions on a 50-sample balanced test set immediately after export — not just that the export command completed without error
- [ ] **Latency gate:** Measure DeBERTa INT8 ONNX inference time on CPUExecutionProvider on the target hardware (Apple M) before committing to the architecture — not on GPU or with default providers
- [ ] **Correlated failure analysis:** Run both models on the same held-out benign samples and identify which samples both models get wrong — do this before reporting ensemble FPR as a single number
- [ ] **Adaptive attack experiment:** Design and run at least one ensemble-targeting attack (minimizing both models' malicious-class probabilities simultaneously) before publishing the adversarial benchmark
- [ ] **Calibration check:** Verify that probability outputs of both models are calibrated (ECE < 0.05) before using soft-vote; if not, apply temperature scaling
- [ ] **Mode restriction propagation:** Confirm that the ensemble's OR-vote respects existing mode-restricted patterns — DeBERTa must not OR-vote in standard mode on content that MiniLM correctly handles alone

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| DeBERTa ONNX export is broken (constant predictions) | LOW | Re-export using `ORTModelForSequenceClassification` path with explicit export=True; re-run sanity check |
| ModernBERT export fails entirely | MEDIUM | Switch to DeBERTa-v3-small or DeBERTa-v3-base; DeBERTa has a known export path and existing PI classifiers to validate against |
| Ensemble FPR is unacceptable in production | MEDIUM | Raise per-model confidence threshold; restrict OR-vote to STRICT mode only; add a third-stage confidence filter |
| DeBERTa latency exceeds budget | MEDIUM | Downsize to DeBERTa-v3-small (5 layers); or apply additional ONNX graph optimization via ORT transformer optimizer |
| Adversarial benchmark overstates robustness | HIGH | Rerun benchmark with adaptive ensemble attack included; revise claims in writeup and HF model card; publish correction |
| Both models share correlated dataset failures | HIGH | Cannot be fixed without a second, independently sourced dataset; document as known limitation with specific attack categories affected |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Misleading transferability experiment | Phase 1: Transferability experiment design | Benchmark includes both non-adaptive and adaptive (ensemble-targeting) attack results |
| DeBERTa ONNX export broken | Phase 2: ONNX export and validation | Automated sanity test (50 balanced samples, non-constant predictions) is part of the export CI step |
| ModernBERT ONNX export incompatible | Phase 1: Architecture selection | Export feasibility test runs before any fine-tuning begins |
| OR-vote inflates false positive rate | Phase 3: Voting integration and threshold tuning | Ensemble FPR measured on held-out benign and reported alongside ensemble recall |
| Shared dataset correlated vulnerabilities | Phase 4: Adversarial benchmark | Correlated failure analysis (which samples both models get wrong) is a required benchmark section |
| Latency budget blowout | Phase 2: Architecture validation | CPUExecutionProvider latency probe (128-token single window) < 80ms gate before proceeding to training |
| False sense of security | Phase 4: Benchmark and writeup | All claims use "raises attacker cost" framing; adaptive attack experiment is required, not optional |

---

## Sources

- Willison, S. (2025-11). "The Attacker Moves Second" — Meta SHADE-Arena summary. Static attacks 0-28%, adaptive 90-100%. https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/
- Yuan et al. (2021, EMNLP). "On the Transferability of Adversarial Attacks Against Neural Text Classifiers." Systematic study of architecture, tokenization, and embedding similarity as transfer factors. https://arxiv.org/abs/2011.08558
- Carlini et al. (2019). "On Evaluating Adversarial Robustness." Adaptive attack evaluation as required standard.
- Athalye, Carlini, Wagner (2018). "Obfuscated Gradients Give a False Sense of Security." Ensemble gradient attacks on systems with obfuscated/combined gradients.
- NIST AI 100-2e2025. Adversarial Machine Learning — taxonomy and evaluation requirements. https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf
- huggingface/optimum GitHub issue #2075: DeBERTaV3 TracerWarning → constant predictions. https://github.com/huggingface/optimum/issues/2075
- huggingface/transformers GitHub issue #18237: DeBERTa v3 ONNX runtime expand shape error. https://github.com/huggingface/transformers/issues/18237
- huggingface/transformers GitHub issue #35545: ModernBERT ONNX export — torch.compile + Flash Attention incompatibility. https://github.com/huggingface/transformers/issues/35545
- huggingface/optimum GitHub issue #2177: ModernBERT missing ONNX optimization support. https://github.com/huggingface/optimum/issues/2177
- Sanh et al. / Answer.AI (2024-12). ModernBERT introduction — 149M params, 2-4x faster than DeBERTa on CPU. https://www.answer.ai/posts/2024-12-19-modernbert.html
- arxiv 2504.08716 (2025). "ModernBERT or DeBERTaV3? Examining Architecture and Data Influence." DeBERTaV3 marginally outperforms ModernBERT on classification (95.63% vs 95.18%); ModernBERT sensitive to hyperparameters. https://arxiv.org/html/2504.08716v1
- arxiv 2602.14161 (2026-02). "When Benchmarks Lie: Evaluating Malicious Prompt Classifiers Under True Distribution Shift." 28% of top features are dataset shortcuts; standard eval inflates AUC by 8.4 points vs OOD. https://arxiv.org/abs/2602.14161
- Protect AI (2024). deberta-v3-base-prompt-injection-v2: 200M params, F1=95.49%. https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
- Gal & Ghahramani (2016) / Lakshminarayanan et al. (2017). Deep ensemble calibration — averaging uncalibrated probabilities degrades ensemble reliability.
- scikit-learn docs. VotingClassifier — OR-vote (veto) increases FPR while improving recall. https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.VotingClassifier.html
- MDPI Mathematics 2024. "Improving Adversarial Robustness of Ensemble Classifiers by Diversified Feature Selection and Stochastic Aggregation." Diversity diminishes as perturbation magnitude increases. https://www.mdpi.com/2227-7390/12/6/834
- arxiv 1901.09981 (2019). "Improving Adversarial Robustness of Ensembles with Diversity Training." Correlated loss functions defeat ensemble benefit against adversarial attacks. https://arxiv.org/abs/1901.09981

---
*Pitfalls research for: CloneGuard v0.3.0 — ensemble adversarial classifier addition*
*Researched: 2026-03-10*
