# Stack Research

**Domain:** Adversarial-resilient ONNX ensemble text classifier (prompt injection detection)
**Researched:** 2026-03-10
**Confidence:** MEDIUM-HIGH (ONNX export path has one known gotcha requiring verification; all other claims verified)

---

## Context: What Already Exists (Do Not Re-add)

| Component | Version | Status |
|-----------|---------|--------|
| `onnxruntime` | latest | Inference runtime — keep as-is |
| `transformers` | latest | Tokenizer pipeline — keep as-is |
| MiniLM-L6-v2 ONNX | v3 | 87MB, WordPiece, ~16ms/sample — primary classifier |
| Python | 3.11+ | Fixed |
| `uv` | latest | Packaging — fixed |

---

## New Stack Components for v0.3.0

### 1. Second Classifier Architecture: DeBERTa-v3-small

**Recommendation:** `microsoft/deberta-v3-small`

**Why DeBERTa-v3-small over all alternatives:**

DeBERTa-v3-small is the correct choice and the recommendation is not close. The rationale operates on three independent axes:

**Axis 1 — Architectural dissimilarity from MiniLM-L6-v2**

MiniLM-L6-v2 is a BERT-family distillation using WordPiece tokenization and standard bidirectional attention. DeBERTa-v3-small differs on every architectural dimension that matters for adversarial transfer:

| Dimension | MiniLM-L6-v2 | DeBERTa-v3-small |
|-----------|-------------|------------------|
| Tokenizer | WordPiece (BERT-style) | SentencePiece Unigram |
| Attention | Standard self-attention (absolute position) | Disentangled attention (content + position separate) |
| Pre-training objective | MLM distillation | ELECTRA-style Replaced Token Detection (RTD) |
| Position encoding | Absolute positional embeddings | Relative positional encodings |
| Embedding sharing | N/A | Gradient-Disentangled Embedding Sharing (GDES) |
| Parameters | ~22M | ~44M |

The tokenizer difference alone is decisive for adversarial robustness. The TokenBreak paper (arxiv:2506.07948) measures WordPiece models at 55.62% mean adversarial success rate against token-prepend attacks, while SentencePiece/Unigram models (DeBERTa-v2 family) show 0% success rate on the same attack. Mixing tokenizer families is the most concrete cross-architecture protection available in the text classification domain.

**Axis 2 — Demonstrated fitness for the exact task**

ProtectAI ships `protectai/deberta-v3-small-prompt-injection-v2` as a production ONNX model for prompt injection detection. It achieves 94.28% accuracy, 99.71% recall, and 90% precision on 20,000 held-out samples from 22 training datasets. The ONNX subfolder ships with the model checkpoint and loads via `ORTModelForSequenceClassification`. This is proof-of-viability, not theory.

**Axis 3 — Accuracy/size tradeoff for the latency budget**

DeBERTa-v3-small (~44M params, ~176MB FP32 ONNX) fits the ~70-120ms ensemble latency budget. The full DeBERTa-v3-base (~86M params) would double latency unnecessarily. DeBERTa-v3-xsmall (~22M params) exists but has less published fine-tuning precedent for classification. The -small tier is the sweet spot.

**Architectural dissimilarity justification (Papernot/Tramer transferability theory):**
White-box adversarial examples exploit model-specific gradients. Cross-architecture transfer rate is inversely correlated with:
1. Embedding space difference (WordPiece vs SentencePiece Unigram = different vocabulary, different tokenization, different input representation)
2. Attention mechanism difference (absolute vs disentangled relative attention)
3. Training objective difference (MLM distillation vs RTD)

All three factors maximize transfer penalty when using DeBERTa-v3-small as the ensemble partner.

---

### 2. What NOT to Use as Second Architecture

| Architecture | Why Not |
|--------------|---------|
| **DistilBERT** | WordPiece tokenizer (same as MiniLM). BERT-family distillation. Minimal architectural dissimilarity. Adversarial examples transfer at high rate. Provides near-zero ensemble benefit against white-box attacks targeting MiniLM. |
| **ModernBERT-base** | ONNX export was broken (transformers issue #35545, closed Feb 2026). Export requires `reference_compile=False` workaround and remains fragile. Additionally: uses BPE tokenization (not SentencePiece Unigram), and a Jan 2026 controlled study (arxiv:2504.08716) found ModernBERT fails to surpass older encoder baselines on classification — DeBERTa-v3 wins on accuracy and sample efficiency. More risk, less payoff than DeBERTa-v3-small. |
| **BERT-base-uncased** | WordPiece. Same family as MiniLM. No disentangled attention. Architecturally too similar. |
| **RoBERTa-base** | BPE tokenizer (different from WordPiece, but still left-to-right subword; TokenBreak shows moderate vulnerability unlike Unigram's 0%). No disentangled attention. Less dissimilar from MiniLM than DeBERTa-v3. |

---

### 3. Adversarial Example Generation: TextAttack

**Recommendation:** `textattack==0.3.10`

**Why TextAttack:**
- Single framework covering all needed attack recipes (TextFooler, BERTAttack, PWWS, A2T)
- Built-in CSV logging of adversarial examples — output format is directly importable as dataset augmentation
- Black-box mode: attacks work by querying the model's output probabilities, no gradient access required
- Supports custom dataset loading from CSV with `(text, label)` columns — matches our 6,340-sample format
- TextFooler and BERTAttack are the two most commonly used word-substitution attacks in NLP robustness evaluation literature

**Attack recipes to use for the transferability experiment:**

| Recipe | Class | Attack Type | Use For |
|--------|-------|-------------|---------|
| `BERTAttackLi2020` | Word substitution via masked LM | Black-box | Primary: generates semantically coherent adversarial examples. Highest semantic quality. |
| `TextFoolerJin2019` | Word substitution via embedding similarity | Black-box | Secondary: simpler perturbation model, widely cited baseline |
| `PWWSRen2019` | Weighted word substitution | Black-box | Tertiary: saliency-weighted variant |

**Transferability experiment protocol:**

1. Generate adversarial examples against MiniLM classifier using BERTAttack + TextFooler
2. Run generated examples through DeBERTa-v3-small (without retraining)
3. Measure recall drop on MiniLM-targeted examples
4. If DeBERTa-v3-small maintains recall >= 70% on MiniLM-targeted examples, the ensemble hypothesis is confirmed

**TextAttack version status:** Current version is 0.3.10 (PyPI). Maintenance status is low but stable — no breaking changes in recent history. The framework is research tooling for training/evaluation, not a runtime dependency. Install in dev/train environment only.

**Custom model integration:**

TextAttack requires a `ModelWrapper` that exposes `__call__(text_list) -> probabilities`. For the transferability experiment, wrap the ONNX inference pipeline:

```python
import textattack
import numpy as np

class ONNXModelWrapper(textattack.models.wrappers.ModelWrapper):
    def __init__(self, ort_session, tokenizer):
        self.session = ort_session
        self.tokenizer = tokenizer

    def __call__(self, text_list):
        results = []
        for text in text_list:
            inputs = self.tokenizer(text, return_tensors="np", max_length=512, truncation=True, padding="max_length")
            logits = self.session.run(None, dict(inputs))[0]
            probs = softmax(logits, axis=-1)
            results.append(probs[0])
        return np.array(results)
```

---

### 4. ONNX Export for DeBERTa-v3-small

**Method:** `optimum` via `ORTModelForSequenceClassification` with `export=True` — NOT `optimum-cli`.

**Why not `optimum-cli`:** Issue #2075 (huggingface/optimum, Oct 2024, unresolved) documents that `optimum-cli export onnx` for DeBERTa-v3 produces TracerWarnings and exports a model that "always predicts the same label." The issue was reported with zero comments and no fix as of the research date.

**Working path (used by ProtectAI's production ONNX model):**

```python
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer

# Fine-tune DeBERTa-v3-small first (PyTorch)
# Then export via export=True at load time, OR use the subfolder pattern:

# Export during conversion:
model = ORTModelForSequenceClassification.from_pretrained(
    "path/to/finetuned-deberta-v3-small",
    export=True,
    provider="CPUExecutionProvider"
)
model.save_pretrained("path/to/deberta-v3-small-onnx")

# Load for inference (no PyTorch dependency):
tokenizer = AutoTokenizer.from_pretrained(
    "path/to/deberta-v3-small-onnx",
    use_fast=False  # REQUIRED: DeBERTa-v3 tokenizer requires use_fast=False
)
model = ORTModelForSequenceClassification.from_pretrained(
    "path/to/deberta-v3-small-onnx",
    export=False
)
```

**Critical gotcha — `token_type_ids` in pipeline mode:**

If using HuggingFace `pipeline()` with the exported model, the pipeline preprocessor sends `token_type_ids` which DeBERTa-v3 ONNX does not accept as a named input. Error: `Invalid Feed Input Name: token_type_ids`. Issue #968 (huggingface/optimum) was closed as "not planned" June 2025 — no fix in the library.

**Fix:** Do NOT use `pipeline()`. Call the tokenizer and model directly, passing only `input_ids` and `attention_mask`:

```python
inputs = tokenizer(text, return_tensors="np", max_length=512, truncation=True,
                   padding="max_length", return_token_type_ids=False)
logits = model(**inputs).logits
```

**Critical gotcha — `use_fast=False` on tokenizer:**

DeBERTa-v3's SentencePiece tokenizer requires `use_fast=False` at load time. The fast Rust tokenizer implementation does not reliably handle the SentencePiece vocabulary for this model family. ProtectAI's production model card explicitly requires this. Failure mode: tokenizer loads but produces incorrect token IDs silently.

**Critical gotcha — file size:**

DeBERTa-v3-small ONNX in FP32 is approximately 176MB. The mixed-precision training means `from_pretrained` loads as FP32 by default, which can cause the ONNX export to reach 350MB+ if loading incorrectly. To prevent size bloat, load the PyTorch base in FP16 before export: `from_pretrained(..., torch_dtype=torch.float16)` then export. The ORTModel export path handles this correctly when using Optimum's `export=True` flag.

**Quantization path (recommended for latency):**

Apply INT8 dynamic quantization post-export to reduce inference latency. The ProtectAI base-variant ONNX model (without quantization) is operational but larger. Dynamic INT8 quantization via `onnxruntime.quantization.quantize_dynamic` is the standard approach and has no accuracy impact for classification at this scale.

---

### 5. Training Tooling (Train Environment Only)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `torch` | >=2.2.0 | Fine-tune DeBERTa-v3-small | CPU sufficient for 6,340 samples. NOT a runtime dep. |
| `transformers` | >=4.48.0 | DeBERTa model + trainer | Already present. Minimum version for ModernBERT ONNX if needed later. |
| `optimum[onnxruntime]` | >=1.24.0 | ONNX export via ORTModel | v1.24.0 added ModernBERT support; contains DeBERTa ONNX export path. |
| `datasets` | >=2.0.0 | Load/split 6,340-sample CSV | Standard HF datasets. |
| `textattack` | 0.3.10 | Transferability experiment | Dev/research use only. Not a runtime dep. |
| `scikit-learn` | >=1.3.0 | Evaluation metrics, CV | Already likely present. |

**Installation (train/eval environment):**

```bash
uv pip install "optimum[onnxruntime]>=1.24.0" textattack==0.3.10 datasets torch
```

**Runtime-only additions (no new deps):**

The ensemble adds zero new runtime dependencies. Inference for both classifiers runs through the existing `onnxruntime` + `transformers` tokenizer pipeline.

---

## Ensemble Architecture Integration

The second classifier integrates with the existing pipeline as a parallel vote — both run on every input:

```
Input text
    │
    ├─► Tier 1.5a: MiniLM-L6-v2 ONNX (WordPiece, ~16ms)
    │       └─► score_a
    │
    └─► Tier 1.5b: DeBERTa-v3-small ONNX (SentencePiece, ~25-40ms INT8)
            └─► score_b
                        │
                        ▼
              Union vote: BLOCK if either score > threshold
              (Configurable to AND for lower FPR, OR for higher recall)
```

Total estimated latency: ~40-60ms INT8, ~50-80ms FP32, both within the 120ms budget.

---

## Alternatives Considered

| Recommended | Alternative | Why Not |
|-------------|-------------|---------|
| DeBERTa-v3-small | ModernBERT-base | ONNX export fragile (issue #35545 closed Feb 2026). BPE not Unigram. Lower accuracy on classification tasks (arxiv:2504.08716). Higher risk, less payoff. |
| DeBERTa-v3-small | RoBERTa-base | BPE tokenizer — TokenBreak shows moderate vulnerability vs Unigram's 0%. Less architecturally different from MiniLM family. No disentangled attention. |
| DeBERTa-v3-small | DistilBERT | WordPiece = same as MiniLM. Maximum architectural similarity = minimum ensemble benefit. |
| DeBERTa-v3-small | DeBERTa-v3-base | 2x parameters, 2x latency. Marginal accuracy gain for a 6,340-sample dataset unlikely to justify it. |
| TextAttack 0.3.10 | OpenAttack 2.1.1 | Less community adoption, less maintained. Older BERT-Attack integration. TextAttack has better HuggingFace ecosystem integration and CSV output handling. |
| optimum ORTModel export=True | optimum-cli export | CLI path has confirmed "always same label" bug for DeBERTa-v3 (issue #2075, unresolved Oct 2024). ORTModel programmatic path is what ProtectAI uses in production. |

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `optimum>=1.24.0` | `transformers>=4.48.0`, `onnxruntime>=1.16.0` | v1.24.0 = ModernBERT ONNX support added; v2.0+ moved ONNX to `optimum-onnx` sub-package |
| `textattack==0.3.10` | `transformers>=4.0.0`, `torch>=1.8.0` | Requires torch in train env; not runtime |
| DeBERTa-v3-small tokenizer | `use_fast=False` only | Fast tokenizer fails silently on SentencePiece vocab |
| ONNX export | `export=True` flag in ORTModel | NOT `optimum-cli` — see gotcha above |

---

## Sources

- [arxiv:2506.07948 — TokenBreak: Bypassing Text Classification Models Through Token Manipulation](https://arxiv.org/html/2506.07948v1) — HIGH confidence: peer-reviewed, 0% Unigram vs 55.62% WordPiece attack success. Directly confirms tokenizer dissimilarity rationale.
- [arxiv:2504.08716 — ModernBERT or DeBERTaV3? Examining Architecture and Data Influence](https://arxiv.org/html/2504.08716v1) — HIGH confidence: controlled study Jan 2026. DeBERTa-v3 superior on classification tasks.
- [ProtectAI deberta-v3-small-prompt-injection-v2 HuggingFace](https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2) — HIGH confidence: production ONNX model for identical task. F1=94.62%, ONNX subfolder confirmed.
- [huggingface/optimum issue #2075 — Problem converting DeBERTaV3 to ONNX using optimum-cli](https://github.com/huggingface/optimum/issues/2075) — HIGH confidence: confirms CLI export bug for DeBERTa-v3.
- [huggingface/optimum issue #968 — Deberta ONNX pipeline issue](https://github.com/huggingface/optimum/issues/968) — HIGH confidence: `token_type_ids` bug confirmed, closed "not planned" June 2025.
- [huggingface/optimum issue #2177 — Add ONNX export optimization support for ModernBERT](https://github.com/huggingface/optimum/issues/2177) — HIGH confidence: closed March 2025, ModernBERT support merged in optimum v1.24.0.
- [huggingface/transformers issue #35545 — ModernBERT ONNX export error](https://github.com/huggingface/transformers/issues/35545) — MEDIUM confidence: issue closed Feb 2026 as resolved, but exact version not stated. Export fragility documented.
- [TextAttack GitHub — QData/TextAttack](https://github.com/QData/TextAttack) — MEDIUM confidence: v0.3.10 current on PyPI, maintenance low but stable.
- [ProtectAI deberta-v3-base-injection-onnx HuggingFace](https://huggingface.co/protectai/deberta-v3-base-injection-onnx) — MEDIUM confidence: base variant ONNX pattern, validates ORTModel export path.
- [DeBERTaV3 paper — arxiv:2111.09543](https://ar5iv.labs.arxiv.org/html/2111.09543) — HIGH confidence: original RTD + GDES architecture paper.

---

*Stack research for: CloneGuard v0.3.0 white-box adversarial resilience ensemble*
*Researched: 2026-03-10*
