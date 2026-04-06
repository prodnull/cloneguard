# Phase 1: Transferability Gate - Research

**Researched:** 2026-03-10
**Domain:** Adversarial NLP attacks (TextAttack), transfer experiments, ProtectAI DeBERTa proxy model
**Confidence:** HIGH (core stack) / MEDIUM (TextAttack-transformers 5.x compatibility, expected transfer rates)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Attack target: MiniLM-L6-v2 ONNX classifier (white-box)
- Attack recipes: TextAttack PWWS + TextFooler
- Transfer target: ProtectAI DeBERTa proxy model (pre-fine-tuning signal only)
- Corpus: 185-sample held-out adversarial benchmark (`data/benchmark/malicious_corpus.json`)
- Gate threshold: 40% is a hard binary cutoff — 40.1% = pivot, 39.9% = proceed
- Results output: `docs/results/` as JSON with date-stamped filename
- Script location: `scripts/` with `sys.path.insert(0, "src")` pattern
- Publication: results document only in Phase 1 — blog/HF/LinkedIn are deferred follow-ups
- Pivot path: alternatives survey with pros/cons/effort estimates evaluated against CloneGuard's constraints (20ms latency, ONNX-only, no external services, hook architecture compatibility)

### Claude's Discretion
- Attack methodology details (TextAttack recipe parameters, perturbation budgets, success criteria per sample)
- Proxy model loading and inference wrapper implementation
- Results document structure and specific metrics reported
- Statistical methods for confidence intervals

### Deferred Ideas (OUT OF SCOPE)
- Blog/Medium article drafting
- HuggingFace model card update
- LinkedIn post
- Alternative milestone planning (v0.3.0-alt) — only if pivot triggered, and only after user reviews survey
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| XFER-01 | Generate adversarial examples against MiniLM using TextAttack (PWWS + TextFooler) on held-out adversarial benchmark (185 samples) | TextAttack 0.3.10 PWWS + TextFooler recipes, custom ONNX ModelWrapper pattern documented |
| XFER-02 | Measure transfer rate to ProtectAI DeBERTa proxy model as early signal before fine-tuning investment | ProtectAI DeBERTa-v3-base-prompt-injection-v2 pipeline loading documented, transfer rate calculation methodology documented |
| XFER-03 | Hard gate: transfer rate >40% = pivot to alternative defense; document and publish results regardless of outcome | Gate logic, confidence interval calculation, and result document schema documented |
</phase_requirements>

---

## Summary

Phase 1 is a standalone experiment script: generate adversarial text examples against the MiniLM ONNX classifier using TextAttack, score those adversarial examples against the ProtectAI DeBERTa proxy model, and report the transfer rate as a percentage with confidence interval. The experiment produces a date-stamped JSON results file in `docs/results/` and makes the binary gate decision documented therein.

The key implementation challenge is wrapping the MiniLM ONNX classifier in a TextAttack-compatible `ModelWrapper`. PWWS requires only WordNet (NLTK); TextFooler additionally requires Universal Sentence Encoder (USE) via TensorFlow, which is a significant dependency. The recommended approach for TextFooler is to use a BERT-based sentence encoder constraint rather than the USE default, avoiding the TensorFlow requirement entirely. Alternatively, PWWS alone may suffice if TextFooler's USE dependency proves unacceptable.

The ProtectAI proxy model (`protectai/deberta-v3-base-prompt-injection-v2`) is publicly available on HuggingFace in both full PyTorch (.safetensors, 738 MB) and ONNX formats. For the proxy experiment, loading via the HuggingFace `pipeline` API is appropriate — this is an experimental script, not production code, so the 60ms production latency constraint does not apply here.

**Primary recommendation:** Implement a custom `TextAttackMiniLMWrapper` that wraps the ONNX ONNX session directly. Use PWWS unconditionally. Use TextFooler with the BERT sentence encoder constraint (not USE) to avoid TensorFlow. Score each successful adversarial example against the DeBERTa proxy. Report transfer rate with a Wilson 95% CI.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| textattack | 0.3.10 (latest) | PWWS + TextFooler adversarial attack recipes | Required by XFER-01; only maintained Python framework for both recipes |
| transformers | 5.3.0 (already installed) | DeBERTa proxy model tokenizer and model loading | Already in environment; confirmed compatible with DeBERTa-v3-base |
| torch | 2.10.0 (already installed) | Required by TextAttack and DeBERTa pipeline | Already in environment |
| onnxruntime | 1.24.3 (already installed) | MiniLM ONNX inference (attack target) | Already in environment |
| scipy | 1.17.1 (already installed) | Wilson CI for transfer rate confidence interval | Already in environment, `scipy.stats.binom_test` or `proportion_confint` |
| nltk | (installed via textattack) | WordNet synonym lookup for PWWS | Required by PWWS recipe |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| bert-score | latest | BERT-based semantic constraint for TextFooler (replaces USE) | When running TextFooler without TensorFlow |
| huggingface-hub | 1.6.0 (already installed) | Download ProtectAI DeBERTa proxy model | Model is not gated — public |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| TextFooler (USE/TensorFlow) | TextFooler with BERT-Score semantic constraint | Avoids ~500 MB TF install; BERT-Score is torch-native; slight semantic constraint difference |
| TextFooler (USE/TensorFlow) | PWWS only | PWWS is sufficient standalone; reduces dependencies; loses diversity of attack method |
| ProtectAI DeBERTa-v3-base-v2 | ProtectAI DeBERTa-v3-small-v2 | Small is faster but less capable; base is the canonical proxy |
| HF pipeline (DeBERTa) | ONNX via ORTModelForSequenceClassification | Pipeline is fine for experiment; ONNX export only needed if this becomes production classifier |

**Installation (in isolated environment to avoid transformers version conflict):**

```bash
# Create isolated venv for the transfer experiment
uv venv .venv-transfer --python 3.11
source .venv-transfer/bin/activate
uv pip install textattack==0.3.10 torch transformers>=4.30.0,<5.0.0 bert-score
# Post-install: TextAttack downloads NLTK data automatically
python -c "import textattack"
```

**Important:** TextAttack 0.3.10 specifies `transformers>=4.30.0` but the main project environment has `transformers==5.3.0`. Running TextAttack in the main env risks API breakage (HuggingFace changed internal APIs between 4.x and 5.x). Use an isolated venv for the transfer experiment script only.

---

## Architecture Patterns

### Recommended Project Structure

```
scripts/
└── transfer_experiment.py    # new: standalone experiment script
docs/results/
└── transfer-experiment-YYYY-MM-DD.json    # output (existing pattern)
```

The experiment is a standalone script with no integration with production code. It does not import from `cloneguard.*` except `mini_semantic.MiniSemanticClassifier` for the ONNX model.

### Pattern 1: Custom TextAttack ModelWrapper for ONNX Classifier

**What:** TextAttack requires any model to be wrapped in a `ModelWrapper` subclass that accepts `List[str]` and returns a list/array of per-class scores. The ONNX-based `MiniSemanticClassifier` is not a PyTorch model, so it cannot use `HuggingFaceModelWrapper`. A custom wrapper is required.

**When to use:** Whenever the attack target is not a native HuggingFace `transformers` model.

```python
# Source: TextAttack docs - textattack.readthedocs.io/en/latest/apidoc/textattack.models.wrappers.html
import numpy as np
from textattack.models.wrappers import ModelWrapper

class MiniLMOnnxWrapper(ModelWrapper):
    """Wrap MiniLM ONNX classifier as a TextAttack ModelWrapper.

    TextAttack expects __call__ to return shape [batch, num_classes]
    where [:, 0] = P(benign) and [:, 1] = P(malicious).
    """

    def __init__(self, classifier):
        self.model = classifier  # MiniSemanticClassifier instance
        self.tokenizer = classifier._tokenizer

    def __call__(self, text_inputs: list[str]) -> np.ndarray:
        results = []
        for text in text_inputs:
            inputs = self.tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=256,
                padding="max_length",
            )
            logits = self.model._session.run(
                None,
                {
                    "input_ids": inputs["input_ids"],
                    "attention_mask": inputs["attention_mask"],
                },
            )[0][0]
            probs = np.exp(logits) / np.exp(logits).sum()
            # [P(benign), P(malicious)]
            results.append(probs)
        return np.array(results)
```

**Note on `get_grad`:** PWWS and TextFooler use greedy/word-importance search methods, not gradient-based search. `get_grad` does NOT need to be implemented for these recipes. The `ModelWrapper` base class provides a default that raises `NotImplementedError`, which will only be hit if a gradient-based attack recipe is used.

### Pattern 2: Build TextAttack Attacks Programmatically

```python
# Source: textattack.readthedocs.io/en/latest/3recipes/attack_recipes.html
from textattack.attack_recipes import PWWSRen2019, TextFoolerJin2019

model_wrapper = MiniLMOnnxWrapper(classifier)
pwws_attack = PWWSRen2019.build(model_wrapper)
# TextFooler with BERT-Score semantic constraint (avoids TF/USE dependency):
# Build manually by inspecting textfooler_jin_2019.py and substituting
# UniversalSentenceEncoder with BERTScore constraint
```

### Pattern 3: Dataset Construction for TextAttack

TextAttack expects a dataset of `(text, label)` tuples where label is an integer class index. The malicious corpus uses label `1` (malicious). Only samples that MiniLM currently classifies as malicious are meaningful attack targets — samples already misclassified by MiniLM should be skipped.

```python
# Source: textattack.readthedocs.io/en/latest/api/datasets.html
from textattack.datasets import Dataset

# Only include samples MiniLM already detects (successful detections = meaningful attack targets)
examples = [
    (sample["payload"], 1)  # (text, true_label=malicious)
    for sample in malicious_corpus
    if minilm_scores[sample["id"]] > 0.5  # MiniLM detects it
]
dataset = Dataset(examples)
```

### Pattern 4: Iterating Attack Results for Transfer Rate

```python
# Source: textattack.readthedocs.io/en/latest/api/attacker.html + attack_results.html
import textattack
from textattack.attack_results import SuccessfulAttackResult, FailedAttackResult, SkippedAttackResult

attacker = textattack.Attacker(attack, dataset, attack_args)
results = attacker.attack_dataset()

adversarial_examples = []
for result in results:
    if isinstance(result, SuccessfulAttackResult):
        original = result.original_text()
        adversarial = result.perturbed_text()
        adversarial_examples.append({
            "original": original,
            "adversarial": adversarial,
            "attack": "PWWS",
        })
    # FailedAttackResult: attack could not fool MiniLM — skip
    # SkippedAttackResult: sample was pre-misclassified — skip
```

### Pattern 5: Transfer Rate Measurement

After generating adversarial examples, score each against the ProtectAI DeBERTa proxy:

```python
# Source: huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch

tokenizer = AutoTokenizer.from_pretrained("ProtectAI/deberta-v3-base-prompt-injection-v2")
model = AutoModelForSequenceClassification.from_pretrained("ProtectAI/deberta-v3-base-prompt-injection-v2")
deberta_clf = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    truncation=True,
    max_length=512,
    device=torch.device("cpu"),
)

transferred = 0
total_adversarial = len(adversarial_examples)
for ex in adversarial_examples:
    result = deberta_clf(ex["adversarial"])[0]
    # label 0 = benign, label 1 = injection detected
    # "transferred" = adversarial example also evades DeBERTa (DeBERTa outputs label 0)
    if result["label"] == "LABEL_0":
        transferred += 1

transfer_rate = transferred / total_adversarial if total_adversarial > 0 else 0.0
```

**Important:** "Transfer rate" in this context means the fraction of adversarial examples (that successfully fool MiniLM) which also fool DeBERTa. High transfer = ensemble approach is risky. Low transfer = models are diverse enough to resist shared adversarial examples.

### Pattern 6: Wilson Confidence Interval

```python
# Source: scipy docs - scipy.stats — already in environment (1.17.1)
from scipy.stats import binom_test
# Prefer statsmodels proportion_confint for direct CI (no extra install needed if scipy available)
# OR manual Wilson formula using scipy.stats.norm

def wilson_ci(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Wilson score interval for binomial proportion."""
    from scipy.stats import norm
    z = norm.ppf(1 - alpha / 2)
    p_hat = k / n
    center = (p_hat + z**2 / (2 * n)) / (1 + z**2 / n)
    margin = (z / (1 + z**2 / n)) * (p_hat * (1 - p_hat) / n + z**2 / (4 * n**2)) ** 0.5
    return max(0.0, center - margin), min(1.0, center + margin)

low, high = wilson_ci(transferred, total_adversarial)
```

### Anti-Patterns to Avoid

- **Attacking pre-misclassified samples:** Samples MiniLM already classifies as benign cannot be "fooled further." Only attack samples MiniLM currently detects. TextAttack will produce `SkippedAttackResult` for these automatically.
- **Scoring original payloads against DeBERTa instead of adversarial:** Transfer rate must be measured on the *perturbed* adversarial text, not the original. The question is whether the adversarial perturbation that evades MiniLM also evades DeBERTa.
- **Using sliding window for scoring:** Use single-window raw scoring (mirroring `_score_raw` in the existing benchmark) to match the TextAttack attack surface. The sliding window is a production defense, not the model's raw discriminative ability.
- **Conflating proxy quality with fine-tuned quality:** The ProtectAI DeBERTa is not trained on CloneGuard's dataset. A low transfer rate here is evidence for architectural diversity; it is not proof the fine-tuned DeBERTa ensemble would work. Document this limitation explicitly.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Word substitution attacks | Custom synonym replacement + saliency scoring | TextAttack PWWS | Saliency scoring requires model query access; PWWS handles all edge cases (stopwords, POS, WIR) |
| Semantic similarity constraint | Custom cosine similarity | TextAttack BERTScore constraint | Handles tokenization edge cases, threshold tuning already done in literature |
| Confidence interval for proportion | Custom formula | `scipy.stats.norm.ppf` (Wilson formula) | Already installed, numerically correct |
| WordNet synonym lookups | Direct NLTK calls | TextAttack WordSwapWordNet | TextAttack handles NLTK download, POS filtering, edge cases |

**Key insight:** TextAttack has solved the hard parts of NLP adversarial attacks (word importance ranking, semantic constraints, search methods). The only custom code needed is the ModelWrapper and the transfer scoring loop.

---

## Common Pitfalls

### Pitfall 1: TextAttack + transformers 5.x API conflicts

**What goes wrong:** TextAttack 0.3.10 was developed against transformers 4.x. The `tokenizer(text, return_tensors="pt")` and certain internal HuggingFace pipeline APIs changed in transformers 5.x. Running TextAttack in the main project venv (which has transformers 5.3.0) may produce `AttributeError` or `TypeError` on model loading.

**Why it happens:** TextAttack pins `transformers>=4.30.0` with no upper bound. It assumes 4.x behavior.

**How to avoid:** Run the transfer experiment in an isolated venv with `transformers>=4.30,<5.0`. The main project venv is untouched. The script itself needs this separate venv only for TextAttack; the ProtectAI DeBERTa model can be loaded with transformers 4.x just as well.

**Warning signs:** `TypeError: pipeline() got an unexpected keyword argument` or `ModuleNotFoundError: No module named 'transformers.modeling_outputs'`.

### Pitfall 2: TextFooler requires TensorFlow + Universal Sentence Encoder

**What goes wrong:** The default `TextFoolerJin2019.build()` instantiates `UniversalSentenceEncoder`, which requires `tensorflow` and `tensorflow_hub`. These are not installed and would add ~500 MB.

**Why it happens:** TextFooler's original paper used USE for semantic similarity constraints.

**How to avoid:** Two options:
1. **Preferred:** Build TextFooler manually, substituting `UniversalSentenceEncoder` with `BERTScore` constraint (`pip install bert-score`). BERTScore uses PyTorch.
2. **Fallback:** Use PWWS only, and document that only one attack recipe was run with explanation.

**Warning signs:** `ImportError: No module named 'tensorflow_hub'` when calling `TextFoolerJin2019.build()`.

### Pitfall 3: Adversarial success rate ≠ transfer rate

**What goes wrong:** Reporting TextAttack's "attack success rate" (fraction of MiniLM-detected samples that were successfully fooled) as the transfer rate.

**Why it happens:** These are different quantities. Attack success rate measures how well TextAttack fooled MiniLM. Transfer rate measures what fraction of those successful adversarial examples *also* evade DeBERTa.

**How to avoid:** Transfer rate formula: `# adversarial examples that evade DeBERTa / # adversarial examples generated`. Document both numbers in the results file.

**Warning signs:** A result where "transfer rate" equals TextAttack's reported success rate exactly.

### Pitfall 4: Short payloads get SkippedAttackResult

**What goes wrong:** TextAttack skips samples where the original text is too short for meaningful word substitution. Many of the 185-sample corpus entries may be terse (e.g., fragmentation category items are ≤30 chars). This reduces the effective denominator.

**Why it happens:** TextAttack's search method cannot substitute words if there are no substitutable words.

**How to avoid:** Report skipped count alongside attacked count. Use `len(adversarial_examples)` (successful attacks) as the denominator for transfer rate, not 185. Document the skip count and which categories produced most skips.

### Pitfall 5: ProtectAI DeBERTa label mapping

**What goes wrong:** Assuming the pipeline output `"LABEL_0"` and `"LABEL_1"` map to benign/malicious in a known order without verifying.

**Why it happens:** HuggingFace `pipeline` with `AutoModelForSequenceClassification` uses the model's `config.json` `id2label` mapping. ProtectAI's model uses `0 = INJECTION, 1 = SAFE` in some versions, or the reverse.

**How to avoid:** Check `model.config.id2label` at script start and log it in the results file. Never hard-code label strings; use the config mapping.

**Warning signs:** Transfer rate of 0% or 100% on first pass — likely a label inversion.

### Pitfall 6: Proxy result misinterpreted near the gate

**What goes wrong:** A result of, e.g., 37% transfer with CI [28%, 47%] crosses the 40% gate threshold in the upper bound. Reporting the point estimate as the gate decision while ignoring the CI.

**Why it happens:** Gate is defined on the point estimate, but statistical uncertainty should be surfaced.

**How to avoid:** Apply the gate on the point estimate exactly (per the locked decision). Report the CI alongside. If the point estimate is within ±5% of 40%, flag this explicitly in the results document as "borderline result — CI includes both outcomes."

---

## Code Examples

Verified patterns from official sources:

### DeBERTa Proxy Loading (official HuggingFace README)

```python
# Source: huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch

tokenizer = AutoTokenizer.from_pretrained("ProtectAI/deberta-v3-base-prompt-injection-v2")
model = AutoModelForSequenceClassification.from_pretrained(
    "ProtectAI/deberta-v3-base-prompt-injection-v2"
)
classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    truncation=True,
    max_length=512,
    device=torch.device("cpu"),
)
# Verify label mapping before use
print(model.config.id2label)  # {0: 'INJECTION', 1: 'SAFE'} or similar — verify
```

### TextAttack Attacker API

```python
# Source: textattack.readthedocs.io/en/latest/api/attacker.html
import textattack
from textattack.attack_recipes import PWWSRen2019
from textattack.datasets import Dataset

attack = PWWSRen2019.build(model_wrapper)
dataset = Dataset(examples)  # list of (text, label) tuples
attack_args = textattack.AttackArgs(
    num_examples=len(examples),
    disable_stdout=True,
    silent=True,
)
attacker = textattack.Attacker(attack, dataset, attack_args)
results = attacker.attack_dataset()
```

### NLTK WordNet download (required by PWWS)

```python
# TextAttack auto-downloads on first run, but can be forced:
import nltk
nltk.download("wordnet")
nltk.download("averaged_perceptron_tagger")
nltk.download("omw-1.4")
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| TextFooler with USE (TF) constraint | TextFooler with BERT-Score or BERT sentence encoder (torch-native) | TextAttack 0.3.x | Eliminates TF dependency while maintaining semantic constraint quality |
| Manual attack loops | TextAttack 0.3.10 attack recipes | 2020 onwards | Standardized reproducible adversarial NLP evaluation |
| Report point estimate only | Report point estimate + Wilson 95% CI | Standard since ~2019 | Required for honest reporting; NIST AI 100-2e2025 cites adaptive evaluation standards |

**Deprecated/outdated:**
- `textattack-cli` command-line usage: still works but programmatic API (`Attacker`) is more appropriate for reproducible experiment scripts.
- TensorFlow-based USE for TextFooler: unnecessary in torch-native environments; BERT-based alternatives exist.

---

## Open Questions

1. **TextAttack 0.3.10 + transformers 5.x compatibility in isolated venv**
   - What we know: TextAttack pins `transformers>=4.30.0`; the main env has 5.3.0; the isolated venv approach sidesteps this.
   - What's unclear: Whether installing `transformers<5.0` in the isolated venv causes any secondary dependency conflicts (tokenizers, huggingface-hub version).
   - Recommendation: Plan Wave 0 task to install textattack in isolated venv and run a smoke test (`python -c "from textattack.attack_recipes import PWWSRen2019"`) before the main experiment task.

2. **Expected transfer rate baseline**
   - What we know: MiniLM (small distilled) and DeBERTa-v3-base are architecturally distinct. Literature suggests cross-architecture transfer in NLP is lower than within-architecture. No exact numbers for this specific model pair.
   - What's unclear: Whether synonym-swapping attacks (PWWS) transfer more or less than embedding-based attacks. Some literature suggests PWWS-generated adversarials are relatively human-readable and may transfer better than gradient-based examples.
   - Recommendation: Do not predict the outcome; the experiment exists precisely because this is unknown.

3. **ProtectAI DeBERTa model size and download time**
   - What we know: `model.safetensors` is 738 MB; total repo ~1.5 GB including ONNX.
   - What's unclear: Whether the HuggingFace cache already has this model on the dev machine.
   - Recommendation: Plan a model prefetch step (HuggingFace Hub `snapshot_download`) early in Wave 0.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 9.0.2 |
| Config file | pyproject.toml (`[tool.pytest.ini_options]` if present, else default) |
| Quick run command | `pytest tests/test_mini_semantic.py -x -q` |
| Full suite command | `pytest tests/ -x -q` |

### Phase Requirements → Test Map

Phase 1 is an experiment script, not production code. The experiment script itself has no unit test suite — its "correctness" is validated by running it and inspecting the results document. However, the following smoke tests are appropriate:

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| XFER-01 | TextAttack PWWS generates ≥1 adversarial example from corpus | smoke | `python scripts/transfer_experiment.py --dry-run --limit 5` | ❌ Wave 0 |
| XFER-02 | DeBERTa proxy scores each adversarial example and returns label | smoke | (same dry-run output includes DeBERTa labels) | ❌ Wave 0 |
| XFER-03 | Results JSON is written to `docs/results/` with required fields | smoke | check file exists + `jq .gate_decision` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** N/A (experiment script; run full script when complete)
- **Per wave merge:** Run `python scripts/transfer_experiment.py` (full experiment)
- **Phase gate:** Results file exists and contains `gate_decision` field before phase is marked complete

### Wave 0 Gaps
- [ ] `scripts/transfer_experiment.py` — does not yet exist; created in Phase 1 Wave 1
- [ ] Isolated venv `.venv-transfer/` with TextAttack 0.3.10 — created in Wave 0 setup task
- [ ] NLTK data (`wordnet`, `averaged_perceptron_tagger`, `omw-1.4`) downloaded
- [ ] ProtectAI DeBERTa model prefetched to HuggingFace cache

---

## Sources

### Primary (HIGH confidence)
- `huggingface.co/protectai/deberta-v3-base-prompt-injection-v2` — model card, inference code, label schema, performance metrics, ONNX subfolder confirmation
- `textattack.readthedocs.io/en/latest/api/attacker.html` — Attacker API, result types, programmatic usage
- `textattack.readthedocs.io/en/latest/api/attack_results.html` — SuccessfulAttackResult, FailedAttackResult, SkippedAttackResult APIs
- `textattack.readthedocs.io/en/master/_modules/textattack/attack_recipes/pwws_ren_2019.html` — PWWS source code, constraints, dependencies
- `textattack.readthedocs.io/en/master/_modules/textattack/attack_recipes/textfooler_jin_2019.html` — TextFooler source code, USE dependency confirmed
- `raw.githubusercontent.com/QData/TextAttack/master/requirements.txt` — dependency pins: `transformers>=4.30.0`, `torch>=1.7.0`
- `scripts/adversarial_benchmark.py` (project) — `_score_raw` pattern for ONNX inference without production path
- `src/cloneguard/mini_semantic.py` (project) — MiniLM ONNX internals: `_session`, `_tokenizer`, logit computation

### Secondary (MEDIUM confidence)
- TextAttack 0.3.10 + transformers 5.x compatibility: no direct evidence of breakage found; isolated venv approach is precautionary and standard practice — multiple community sources recommend venv isolation for TextAttack
- ProtectAI `id2label` mapping: inferred from HuggingFace standard binary classification convention; must be verified at runtime

### Tertiary (LOW confidence)
- Expected transfer rate range: literature suggests cross-architecture NLP transfer is typically lower than within-architecture (He et al., 2021 NAACL — "Model Extraction and Adversarial Transferability"), but no specific numbers for this model pair exist; the experiment is the authoritative source

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries verified via official docs; versions confirmed against installed environment
- Architecture: HIGH — ONNX wrapper pattern derived from project's own `_score_raw`; TextAttack API verified via official docs
- Pitfalls: HIGH (USE dependency, label mapping, proxy vs. fine-tuned distinction) / MEDIUM (transformers 5.x conflict — precautionary, not confirmed broken)
- Transfer rate expectations: LOW — no literature numbers for this exact model pair

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (TextAttack and ProtectAI models are stable; transformers compatibility may shift faster)
