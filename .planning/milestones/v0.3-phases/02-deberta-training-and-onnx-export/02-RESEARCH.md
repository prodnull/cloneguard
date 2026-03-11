# Phase 2: Adversarial Hardening — Research

**Researched:** 2026-03-10
**Domain:** Adversarial NLP training (FreeLB), PWWS augmentation (TextAttack), Mahalanobis anomaly detection, ONNX dual-output export
**Confidence:** HIGH (core methods), MEDIUM (projected ASR targets), LOW (Mahalanobis single-layer AUC on this dataset)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- Export CLS embeddings (384-dim) alongside logits in the ONNX model — dual output heads
- Mahalanobis distance computed at inference as a separate signal, not merged into classifier probability
- Anomaly score surfaces as `anomaly_score` field in scan results — additive, does not replace existing verdict
- SAFE + Mahalanobis flags anomalous → escalate to SUSPICIOUS (defense-in-depth)
- MALICIOUS + Mahalanobis agrees → higher confidence, no behavior change
- Threshold: fit at ≤5% FPR on the 234-sample benign eval set (per HARD-03)
- Per-class Gaussian fit (separate means/covariances for SAFE vs MALICIOUS training embeddings)
- Fixed 2-round minimum, up to 3 rounds maximum augmentation
- Each round: generate PWWS adversarial examples against current model, add successful attacks (ASR > 0) to training set with correct malicious labels
- Stop early if ASR drops below ≤35% after round 2
- If 3 rounds still miss ≤35% ASR: accept actual numbers, proceed to Phase 3 honestly — do NOT invoke TF-IDF contingency
- Augmented samples labeled as malicious; track provenance metadata (round + attack method)
- New `anomaly_score` field (float, 0.0 = normal, higher = more anomalous) in Tier 1.5 scan results
- New `anomaly_flagged` boolean field (true when score exceeds threshold)
- Hook exit codes unchanged: 0=allow, 2=block. Mahalanobis escalation to SUSPICIOUS exits 0
- Hardened model becomes v4; ONNX opset version stays at 18
- Trust cache automatically invalidates on model hash change (H2 fix already handles this)
- `fetch_model.py` pulls latest version, cache invalidates, no user action needed

### Claude's Discretion

- FreeLB hyperparameters: ε magnitude, K steps, step size (start with literature defaults: ε=0.01, K=3)
- PWWS TextAttack recipe parameters and perturbation budgets
- Mahalanobis covariance regularization (shrinkage parameter)
- Exact augmentation sample counts per round
- Training hyperparameter adjustments for augmented dataset (learning rate warmup, epoch count)
- Compression/optimization of dual-output ONNX graph
- Benchmark script structure and metrics formatting

### Deferred Ideas (OUT OF SCOPE)

- TF-IDF + XGBoost contingency (TFIDF-01)
- Adaptive attacks against hardened model — Phase 3 (BENCH-02)
- Correlated failure analysis — Phase 3 (BENCH-03)
- HuggingFace model card update with v4 methodology — Phase 3 publication scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| HARD-01 | Generate PWWS adversarial examples against MiniLM v3 using TextAttack, add to training set with correct labels, retrain (2-3 augmentation rounds) | TextAttack PWWS recipe confirmed working in `.venv-transfer`; `MiniLMOnnxWrapper` already validated in `transfer_experiment.py`; augmentation JSONL format confirmed from `augmentation_round2.jsonl` |
| HARD-02 | Implement FreeLB embedding perturbation AT in `scripts/train_mini_model.py` training loop (configurable ε, K=3 PGD steps) | FreeLB algorithm verified from Zhu et al. 2020 (arxiv:1909.11764); insertion point is lines 290-326 of `train_mini_model.py`; no new dependencies needed |
| HARD-03 | Fit per-class Mahalanobis detector on MiniLM CLS embeddings from training data, integrate into scan pipeline with configurable threshold | Lee et al. 2018 + Yoo et al. 2022 confirm method; CLS = mean_pooling output (384-dim); `scipy.linalg.pinv` for covariance inversion; scipy 1.17.1 already installed in `.venv` |
| HARD-04 | Re-run adversarial benchmark (185 malicious + 234 benign) with hardened pipeline, publish before/after comparison to `docs/results/` | `adversarial_benchmark.py` + `multitier_benchmark.py` are extension points; delta comparison already implemented in `compute_delta()` |
| HARD-05 | Verify combined pipeline latency (Tier 0 + hardened Tier 1.5 + Mahalanobis) under 25ms per sample on Apple M-series CPU | Mahalanobis is a single 384×384 matrix multiply (<1ms); ONNX inference already ~2-5ms; benchmark script must time end-to-end |
</phase_requirements>

---

## Summary

Phase 2 hardens CloneGuard's Tier 1.5 ONNX classifier (MiniLM-L6-v2, currently v3) through three complementary mechanisms: (1) PWWS adversarial data augmentation over 2-3 rounds, (2) FreeLB embedding perturbation adversarial training added to the existing training loop, and (3) a per-class Mahalanobis anomaly detector fitted on CLS embeddings from the training corpus. The phase also extends the ONNX export to a dual-output graph (logits + CLS embedding) and wires the Mahalanobis score through the scan pipeline as an additive field.

The implementation environment is well-prepared. TextAttack with PWWS is already validated and running in `.venv-transfer` (PyTorch 2.10.0, scipy 1.17.1). The main `.venv` has all training dependencies (onnx 1.20.1, onnxruntime 1.24.1, transformers 5.3.0, scikit-learn 1.8.0, scipy 1.17.1). The `MiniLMOnnxWrapper` (TextAttack ModelWrapper protocol) is production-ready in `transfer_experiment.py` and can be reused verbatim for PWWS augmentation generation. FreeLB requires approximately 50-80 additional lines in the existing training loop — no new dependencies. Mahalanobis fitting requires only numpy/scipy, which are already installed.

The critical risk: all ASR improvement targets are projections from A2T (Yoo & Qi, EMNLP 2021) on IMDB/Yelp — different task, different dataset size. The ≤35% target must be treated as a goal, not a guarantee. The planner must structure the phase to produce honest empirical results regardless of whether the projection holds.

**Primary recommendation:** Implement in three sequential wave groups — (Wave 1) data augmentation pipeline + round 1 training, (Wave 2) FreeLB integration + rounds 2-3 with ASR gate, (Wave 3) Mahalanobis module + ONNX dual-output + pipeline integration + benchmark. Each wave produces a measurable artifact before the next begins.

---

## Standard Stack

### Core (all already installed in `.venv` and/or `.venv-transfer`)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| textattack | latest in .venv-transfer | PWWS attack generation, TextAttack ModelWrapper protocol | Only mature NLP adversarial attack library with PWWS; already validated in Phase 1 |
| torch | 2.10.0 | FreeLB gradient computation, embedding perturbation | MPS acceleration confirmed working on M-series |
| transformers | 5.3.0 | AutoModel, AutoTokenizer for MiniLM | Already used by training script |
| onnxruntime | 1.24.3 | ONNX inference for Mahalanobis embedding extraction | Already used by Tier 1.5 |
| onnx | 1.20.1 | Dual-output graph export and validation | Already used by export pipeline |
| scipy | 1.17.1 | `scipy.linalg.pinv` for Mahalanobis covariance inversion | More numerically stable than numpy.linalg.inv for near-singular covariances |
| scikit-learn | 1.8.0 | `StratifiedKFold` for 5-fold CV validation post-training | Already used by kfold_eval.py |
| numpy | 2.4.3 | Matrix multiply for Mahalanobis distance at inference | Already available in .venv |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest | >=8.0 | Unit tests for Mahalanobis module, ONNX dual-output verification | Already in dev dependencies |
| time.perf_counter | stdlib | Latency measurement for HARD-05 | Use this, not time.time(), for sub-millisecond precision |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| scipy.linalg.pinv | numpy.linalg.inv | scipy pinv handles near-singular covariance (small class) without raising; safer |
| PWWS (TextAttack recipe) | TextFooler-BERTScore | PWWS succeeded in Phase 1; TextFooler had silent failure on sample 0. Stick with PWWS. |
| LedoitWolf shrinkage | Manual alpha tuning | scikit-learn LedoitWolf is a principled shrinkage estimator — good for small n (malicious class) |

**Installation note:** TextAttack is in `.venv-transfer`, not the main `.venv`. The PWWS augmentation generation script runs under `.venv-transfer`. Training and Mahalanobis fitting run under `.venv`. Two environments, two scripts.

---

## Architecture Patterns

### Recommended Script/Module Structure

```
scripts/
├── generate_pwws_augmentation.py    # Wave 1: runs under .venv-transfer
├── train_mini_model.py              # Wave 2: add --freelb flag, --dataset arg already exists
├── fit_mahalanobis.py               # Wave 3: runs under .venv, outputs mahalanobis_params.npz
└── hardened_benchmark.py            # Wave 3: extends multitier_benchmark.py

src/cloneguard/
├── mini_semantic.py                 # Wave 3: add CLS extraction + Mahalanobis scoring
├── mahalanobis.py                   # Wave 3: new module — Mahalanobis detector class
├── scanner.py                       # Wave 3: ScanReport gains anomaly_score, anomaly_flagged
└── model/
    ├── mini_semantic.onnx           # v4 dual-output (logits + cls_embedding)
    └── mahalanobis_params.npz       # class_means, class_inv_covs, threshold, class_labels

data/training/
├── dataset_augmented_r2.jsonl       # EXISTING: 6,340 samples (current training base)
├── pwws_adversarial_r1.jsonl        # NEW: round 1 PWWS adversarial examples
├── pwws_adversarial_r2.jsonl        # NEW: round 2 PWWS adversarial examples
├── pwws_adversarial_r3.jsonl        # NEW: round 3 (if needed)
└── dataset_v4_rN.jsonl              # NEW: merged training dataset for round N retrain
```

### Pattern 1: FreeLB Training Loop Integration

**What:** Inner-loop PGD perturbation on input embeddings, averaged gradient update. Replaces the simple `loss.backward()` in the existing training loop.

**When to use:** Applied in place of standard backward pass when `--freelb` flag is set (so baseline training remains available without the flag).

**Implementation — insertion after `optimizer.zero_grad()` at line 303 of `train_mini_model.py`:**

```python
# Source: Zhu et al. 2020, FreeLB (arxiv:1909.11764), Algorithm 1
# ε=0.01, K=3, step_size = ε/K * 2 (common heuristic from Li & Qiu 2021)
FREELB_EPSILON = 0.01
FREELB_K = 3
FREELB_STEP_SIZE = FREELB_EPSILON * 2 / FREELB_K

def freelb_step(model, ids, mask, labels_b, criterion, optimizer, epsilon, K, step_size):
    """FreeLB: K PGD ascent steps on input embeddings, then gradient descent."""
    # Get input embeddings (bypass embedding lookup for perturbation)
    embeds_init = model.encoder.embeddings.word_embeddings(ids)
    delta = torch.zeros_like(embeds_init).uniform_(-epsilon, epsilon)
    delta.requires_grad_(True)

    total_loss = torch.tensor(0.0, device=ids.device)

    for _ in range(K):
        # Forward through encoder with perturbed embeddings
        outputs = model.encoder(
            inputs_embeds=embeds_init + delta,
            attention_mask=mask,
        )
        pooled = model.mean_pooling(outputs, mask)
        logits = model.classifier(pooled)
        loss = criterion(logits, labels_b) / K
        total_loss += loss.detach()
        loss.backward(retain_graph=(True))

        # PGD ascent: move delta in direction of gradient (maximize loss)
        delta_grad = delta.grad.detach()
        delta = delta + step_size * delta_grad.sign()
        delta = torch.clamp(delta, -epsilon, epsilon).detach()
        delta.requires_grad_(True)

    optimizer.step()
    return total_loss.item()
```

**Critical detail:** `model.encoder.embeddings.word_embeddings` is the correct entry point for `sentence-transformers/all-MiniLM-L6-v2` (HuggingFace BertModel backbone). The mean_pooling in `PromptInjectionClassifier` takes `model_output` not `outputs` — pass `outputs` directly.

**Warning:** FreeLB does NOT call `optimizer.zero_grad()` inside the K-step loop. Zero grad happens once before, step happens once after. This is correct per Algorithm 1 in the paper.

### Pattern 2: ONNX Dual-Output Export

**What:** Export both `logits` (shape `[batch, 2]`) and `cls_embedding` (shape `[batch, 384]`) as named outputs.

**When to use:** Required for Mahalanobis inference without PyTorch at runtime.

**Key change to `forward()` and `export_onnx()`:**

```python
# Modified forward() — returns tuple
def forward(self, input_ids, attention_mask):
    outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
    pooled = self.mean_pooling(outputs, attention_mask)   # (batch, 384)
    logits = self.classifier(pooled)                       # (batch, 2)
    return logits, pooled  # dual output

# Modified export_onnx() — two output names
torch.onnx.export(
    model_cpu,
    (dummy_ids, dummy_mask),
    str(ONNX_PATH),
    input_names=["input_ids", "attention_mask"],
    output_names=["logits", "cls_embedding"],   # NEW: second output
    dynamic_axes={
        "input_ids":       {0: "batch_size", 1: "sequence"},
        "attention_mask":  {0: "batch_size", 1: "sequence"},
        "logits":          {0: "batch_size"},
        "cls_embedding":   {0: "batch_size"},   # NEW
    },
    opset_version=18,
)
```

**Backward compatibility:** Existing `mini_semantic.py` calls `session.run(None, ...)[0]` — index 0 is still `logits`. The new `cls_embedding` is at index 1. No existing inference code breaks.

### Pattern 3: Mahalanobis Detector (Fit + Inference)

**What:** Per-class Gaussian fit on CLS embeddings. At inference: compute Mahalanobis distance from each class mean, return minimum distance as anomaly score (low = typical, high = anomalous).

**Theory:** Lee et al. 2018 (arxiv:1807.03888) — fit class-conditional Gaussians on penultimate layer features, use minimum Mahalanobis distance as confidence score. Yoo et al. 2022 (arxiv:2203.01677) validated this for adversarial NLP detection, AUC 85-98% for multi-layer RDE.

```python
# Source: Lee et al. 2018, Algorithm; scipy for numerical stability
import numpy as np
from scipy.linalg import pinv

class MahalanobisDetector:
    """Per-class Gaussian anomaly detector on CLS embeddings.

    Fit: extract CLS embeddings from training data, compute per-class mean
         and inverse covariance with Ledoit-Wolf shrinkage.
    Infer: compute Mahalanobis distance from each class center, return minimum.
    """

    def __init__(self, shrinkage: float = 1e-4):
        self.shrinkage = shrinkage  # Ridge regularization on covariance diagonal
        self.class_means: dict[int, np.ndarray] = {}
        self.class_inv_covs: dict[int, np.ndarray] = {}
        self.threshold: float = float("inf")

    def fit(self, embeddings: np.ndarray, labels: np.ndarray) -> None:
        """Fit per-class Gaussians. labels: 0=benign, 1=malicious."""
        for c in np.unique(labels):
            class_embeddings = embeddings[labels == c]
            mean = class_embeddings.mean(axis=0)
            cov = np.cov(class_embeddings.T)
            # Shrinkage: add alpha*I for numerical stability (small classes)
            cov += self.shrinkage * np.eye(cov.shape[0])
            self.class_means[int(c)] = mean
            self.class_inv_covs[int(c)] = pinv(cov)

    def mahalanobis_distance(self, embedding: np.ndarray, class_id: int) -> float:
        mean = self.class_means[class_id]
        inv_cov = self.class_inv_covs[class_id]
        delta = embedding - mean
        return float(np.sqrt(delta @ inv_cov @ delta))

    def score(self, embedding: np.ndarray) -> float:
        """Return minimum Mahalanobis distance across all class centers.
        Lower = more typical of training distribution. Higher = more anomalous.
        """
        return min(
            self.mahalanobis_distance(embedding, c) for c in self.class_means
        )

    def fit_threshold(self, benign_embeddings: np.ndarray, target_fpr: float = 0.05) -> float:
        """Fit threshold at target FPR on benign eval set."""
        scores = np.array([self.score(e) for e in benign_embeddings])
        # Threshold = (1-FPR) quantile of benign scores
        self.threshold = float(np.quantile(scores, 1.0 - target_fpr))
        return self.threshold

    def save(self, path) -> None:
        """Save params to .npz for ONNX-only inference."""
        np.savez(path,
            class_means=np.stack(list(self.class_means.values())),
            class_inv_covs=np.stack(list(self.class_inv_covs.values())),
            class_labels=np.array(list(self.class_means.keys())),
            threshold=np.array([self.threshold]),
        )
```

**Shrinkage recommendation:** Start with `shrinkage=1e-4` (mild regularization). If malicious class covariance is near-singular (small augmented dataset), increase to `1e-3`. The malicious training set has ~3,033 samples — sufficient for 384-dim Gaussian, but the effective effective rank may be lower due to embedding clustering.

**Alternative — LedoitWolf from scikit-learn:**

```python
from sklearn.covariance import LedoitWolf
lw = LedoitWolf().fit(class_embeddings)
inv_cov = pinv(lw.covariance_)  # More principled shrinkage for small n
```

Use LedoitWolf when the class has <1000 samples per dimension (here: 3033 samples / 384 dims ≈ 8:1 ratio — borderline). LedoitWolf is more principled; manual shrinkage is simpler to tune.

### Pattern 4: CLS Embedding Extraction from Dual-Output ONNX

```python
# In mini_semantic.py classify() and classify_files()
# session.run(None, inputs) returns [logits, cls_embedding]
outputs = self._session.run(None, {
    "input_ids": inputs["input_ids"],
    "attention_mask": inputs["attention_mask"],
})
logits = outputs[0][0]          # shape (2,)
cls_embedding = outputs[1][0]   # shape (384,) — NEW

# Apply Mahalanobis scoring
anomaly_score = self._mahalanobis.score(cls_embedding)
anomaly_flagged = anomaly_score > self._mahalanobis.threshold
```

### Anti-Patterns to Avoid

- **Calling `optimizer.zero_grad()` inside the FreeLB inner loop:** Destroys the accumulated gradient. Zero grad happens ONCE before the K-step loop, step happens ONCE after.
- **Using `logits` (not pooled embedding) for Mahalanobis:** Logits are 2-dim — too low-dimensional for useful geometry. Use the 384-dim CLS embedding (mean pooling output).
- **Fitting Mahalanobis on val/test embeddings:** Fit on training embeddings only. Threshold is fitted on the held-out benign eval set (234 samples at `data/benchmark/benign_eval_751.json` or `benign_corpus_eval.json`).
- **Inlining numpy.linalg.inv without regularization:** Will raise `LinAlgError: Singular matrix` when augmented malicious class is small. Always add shrinkage to diagonal.
- **Running PWWS augmentation in main `.venv`:** TextAttack is NOT in main `.venv`. Augmentation generation must run under `.venv-transfer`. Training and Mahalanobis fitting run under `.venv`.
- **Exporting dual-output ONNX from MPS device:** torch.onnx.export must move model to CPU first (already done in `export_onnx()`). Do not skip this step.
- **Augmenting with samples the model already correctly classifies (score > 0.5):** These are not attacks in the transfer sense. The PWWS augmentation corpus should start from malicious samples where `raw_score > 0.5` (as done in Phase 1 pre-filtering) to ensure we're generating adversarial examples that actually fool the current model.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PWWS word substitution attack | Custom synonym search + saliency scoring | `textattack.attack_recipes.PWWSRen2019` | PWWS uses WordNet + probability-weighted word saliency — correct implementation is complex; TextAttack is validated |
| Covariance inversion for Mahalanobis | `numpy.linalg.inv` directly | `scipy.linalg.pinv` + diagonal regularization | pinv handles rank deficiency without raising; important for small or clustered embedding classes |
| Per-class Gaussian fitting | Manual mean/cov computation | `sklearn.covariance.LedoitWolf` (optional) | Principled shrinkage for n/p ratios below ~10 |
| 5-fold CV for accuracy validation | Custom cross-validation | `sklearn.model_selection.StratifiedKFold` | Already used in `kfold_eval.py` — reuse the existing script |
| Latency measurement | `time.time()` | `time.perf_counter()` | perf_counter has nanosecond resolution; time.time() resolution varies by OS |
| TextAttack ModelWrapper | New wrapper class | `MiniLMOnnxWrapper` from `transfer_experiment.py` | Already validated, handles softmax normalization correctly |

**Key insight:** The Mahalanobis detector is mathematically straightforward but numerically fragile (matrix inversion of large covariance). Use scipy's pseudoinverse + diagonal regularization — do not implement raw inversion.

---

## Common Pitfalls

### Pitfall 1: FreeLB Gradient Accumulation Scope

**What goes wrong:** FreeLB K-step loop accumulates gradients across steps. Calling `loss.backward()` K times without clearing intermediate buffers causes an `out of memory` error on MPS, or the `retain_graph` flag causes exponential memory growth.

**Why it happens:** FreeLB's algorithm requires the same computational graph to be retained across all K backward passes. The `retain_graph=True` flag keeps the graph alive, but each backward() accumulates gradients on the leaf tensors (delta). On MPS this can OOM on long sequences.

**How to avoid:** Detach delta between steps (`delta = delta.detach()` + re-enable `requires_grad`) — which we do explicitly in the pattern above. Also: divide loss by K before backward (`loss = criterion(...) / K`) so the gradient scale stays comparable to standard training.

**Warning signs:** Training loss significantly lower than expected after epoch 1 (gradient blow-up), or MPS memory errors.

### Pitfall 2: PWWS Augmentation Corpus Contamination

**What goes wrong:** Adding samples to the training set that were generated from the training set itself (not held-out adversarial examples) inflates ASR measurement in subsequent rounds.

**Why it happens:** The 185-sample adversarial benchmark is held-out. The PWWS augmentation should generate attacks against the benchmark corpus OR against held-out training samples, but ASR must always be measured on the same 185-sample benchmark, not on augmented samples.

**How to avoid:** Measure ASR on `data/benchmark/malicious_corpus.json` (185 samples) exclusively. Generate augmentation examples from the same corpus but do NOT include them in the ASR measurement. Keep benchmark corpus immutable.

### Pitfall 3: Mahalanobis Threshold Overfitting to Small Benign Eval Set

**What goes wrong:** Fitting threshold at exactly 5% FPR on 234 benign samples produces a threshold that doesn't generalize. On a different benign distribution it may have 8-15% FPR.

**Why it happens:** 234 samples is small. At 5% FPR, only ~12 samples define the threshold quantile. Small sample variance is high.

**How to avoid:** Report the actual FPR observed on the eval set. Note the 95% Wilson CI for FPR (same formula from `transfer_experiment.py`). Document that the threshold is calibrated on a specific distribution and may shift on OOD content.

**Warning signs:** Threshold changes by >2x between round 1 and round 2 Gaussian fits (indicates embedding space is shifting significantly during retraining).

### Pitfall 4: Dual-Output ONNX Breaking Existing Inference

**What goes wrong:** `mini_semantic.py:classify()` calls `session.run(None, ...)[0]` — index 0. If the output order in the ONNX export changes between v3 and v4, existing code silently returns the wrong output.

**Why it happens:** torch.onnx.export respects the order of `output_names`. If `cls_embedding` is listed first, index 0 would return the embedding, not logits.

**How to avoid:** In `export_onnx()`, always list `output_names=["logits", "cls_embedding"]` with logits first. Verify after export: `session.get_outputs()[0].name == "logits"`. Add an assertion in `verify_onnx()`.

### Pitfall 5: FreeLB with MPS — `inputs_embeds` Availability

**What goes wrong:** Some versions of HuggingFace `transformers` AutoModel do not expose `inputs_embeds` directly on `model.encoder` — they may require `model.encoder.embeddings(inputs_embeds=...)` instead.

**Why it happens:** The embedding layer call pattern differs slightly between BertModel versions.

**How to avoid:** Test `model.encoder(inputs_embeds=delta + embeds_init, attention_mask=mask)` in isolation before integrating FreeLB. transformers 5.3.0 (installed in `.venv`) uses `BertModel.forward(inputs_embeds=...)` which is supported. Verify once with a single batch before committing to the full training loop change.

### Pitfall 6: Two-Environment Workflow

**What goes wrong:** Confusing which script runs in which virtualenv. TextAttack lives in `.venv-transfer`; training, Mahalanobis fitting, and ONNX export live in `.venv`. Mixing them causes `ModuleNotFoundError`.

**How to avoid:** Document the shebang or explicit interpreter path in each script. `generate_pwws_augmentation.py` → `.venv-transfer/bin/python`. All other Phase 2 scripts → `.venv/bin/python`.

---

## Code Examples

Verified patterns from existing codebase and referenced papers:

### Extracting CLS Embeddings from Current v3 ONNX (Diagnostic — before v4 export)

```python
# Existing session returns [logits] only. To get CLS pre-export:
# Use PyTorch model directly (training script has the model in memory)
with torch.no_grad():
    outputs = model.encoder(input_ids=ids, attention_mask=mask)
    cls = model.mean_pooling(outputs, mask)  # (batch, 384)
```

### Wilson CI for Mahalanobis FPR Report

```python
# Reuse wilson_ci_95() from transfer_experiment.py verbatim
def wilson_ci_95(successes: int, total: int) -> tuple[float, float]:
    ...  # copy from transfer_experiment.py
```

### Saving Augmentation with Provenance Metadata

```python
# data/training/pwws_adversarial_r1.jsonl format
{"text": "...", "label": 1, "provenance": {"round": 1, "method": "pwws", "original_id": "mal-0023"}}
```

### PWWS Augmentation Generation Script Skeleton

```python
# runs under .venv-transfer/bin/python
# Reuse MiniLMOnnxWrapper from transfer_experiment.py — copy or import
from textattack.attack_recipes import PWWSRen2019
from textattack import AttackArgs, Attacker
from textattack.datasets import Dataset as TADataset

model_wrapper = MiniLMOnnxWrapper(classifier)
attack = PWWSRen2019.build(model_wrapper)
dataset = TADataset([(sample["payload"], 1) for sample in corpus])
attack_args = AttackArgs(num_examples=len(corpus), disable_stdout=True, silent=True)
attacker = Attacker(attack, dataset, attack_args)

# Collect successes, write with provenance metadata to JSONL
```

### Latency Measurement Pattern for HARD-05

```python
import time

N_WARMUP = 5
N_MEASURE = 50

# Warmup
for _ in range(N_WARMUP):
    _ = classifier.classify(test_text)

# Measure
times = []
for _ in range(N_MEASURE):
    t0 = time.perf_counter()
    result = classifier.classify(test_text)  # includes Mahalanobis scoring
    times.append((time.perf_counter() - t0) * 1000)

p50 = sorted(times)[N_MEASURE // 2]
p95 = sorted(times)[int(N_MEASURE * 0.95)]
print(f"Tier 1.5 + Mahalanobis: p50={p50:.1f}ms, p95={p95:.1f}ms")
# Gate: p95 < 25ms (per HARD-05 requirement)
```

---

## State of the Art

| Old Approach | Current Approach | Notes |
|--------------|------------------|-------|
| Standard training (baseline) | FreeLB + PWWS augmentation | Adversarial training is now standard for production NLP classifiers |
| Single output ONNX (logits only) | Dual output ONNX (logits + CLS) | Enables runtime anomaly detection without PyTorch dependency |
| Binary classifier only | Classifier + anomaly detector | Lee et al. 2018 + Yoo et al. 2022 established Mahalanobis as complementary signal |
| A2T (Yoo & Qi 2021) best approach | FreeLB (Zhu et al. 2020) preferred | FreeLB outperforms A2T on GLUE while being simpler (no token-level inner loop) |

**Deprecated/outdated for this context:**
- Defensive distillation: Carlini & Wagner 2016 proved broken
- Gradient masking: irrelevant against PWWS (gradient-free)
- IBP certified robustness: 3-8% accuracy cost, incompatible with 94.5% floor requirement

---

## Open Questions

1. **FreeLB epsilon sensitivity on MPS**
   - What we know: Literature default ε=0.01 works on CPU/CUDA for BERT-class models
   - What's unclear: MPS numerical precision for embedding-space PGD may differ. Gradient sign methods can be unstable on MPS for float16 operations.
   - Recommendation: Force float32 in the FreeLB training loop (`model.float()` + `delta.float()`). Test with `--limit 100` sanity run before full training.

2. **PWWS generation speed on the 185-sample benchmark**
   - What we know: Phase 1 PWWS on ~120 pre-filtered samples took approximately 30-60 minutes
   - What's unclear: Round 2+ runs against a hardened model — PWWS may take longer (fewer successful substitutions)
   - Recommendation: Add `--time-limit N` to PWWS generation script. Budget 90 min per round.

3. **Mahalanobis performance on our specific dataset**
   - What we know: AUC 75-85% projected from Lee et al. + Yoo et al. for single-layer CLS on word-substitution attacks
   - What's unclear: Our malicious class spans very diverse attack categories (9 categories). A single Gaussian per class may be bimodal. Per-category Gaussians would help but cost more.
   - Recommendation: Start with two-class Gaussian (SAFE/MALICIOUS). If flagging rate is below 40% on adversarial examples, try per-category Gaussians as a discretionary enhancement.

4. **Augmented dataset size and class balance**
   - What we know: Dataset v3 has 3,033 mal / 3,307 benign (6,340 total). PWWS on 185-sample benchmark yields at most 185 new adversarial samples per round.
   - What's unclear: Should we augment the full training malicious set or just the benchmark corpus?
   - Recommendation: Generate PWWS examples from `malicious_corpus.json` (185 samples), add all successful attacks. The augmented malicious class remains balanced at ~3,033+185 per round — acceptable.

---

## Validation Architecture

`nyquist_validation` key is absent from `.planning/config.json` — validation architecture applies.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 8.x |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` — `testpaths = ["tests"]` |
| Quick run command | `uv run pytest tests/test_mini_semantic.py tests/test_mahalanobis.py -x -q` |
| Full suite command | `uv run pytest tests/ -x -q` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HARD-01 | PWWS augmentation produces valid JSONL with provenance fields | unit | `pytest tests/test_augmentation.py -x` | Wave 0 |
| HARD-01 | Augmented JSONL has `label=1`, `provenance.round`, `provenance.method` | unit | `pytest tests/test_augmentation.py::test_augmentation_schema -x` | Wave 0 |
| HARD-02 | FreeLB training loop completes without error (2-epoch smoke) | integration | `pytest tests/test_train_freelb.py::test_freelb_smoke -x` | Wave 0 |
| HARD-02 | FreeLB gradient accumulated correctly (delta detached between steps) | unit | `pytest tests/test_train_freelb.py::test_freelb_gradient_accumulation -x` | Wave 0 |
| HARD-03 | MahalanobisDetector fits without error on synthetic embeddings | unit | `pytest tests/test_mahalanobis.py::test_fit_smoke -x` | Wave 0 |
| HARD-03 | Threshold at 5% FPR on benign eval set within expected range | integration | `pytest tests/test_mahalanobis.py::test_threshold_fpr -x` | Wave 0 |
| HARD-03 | `anomaly_score` and `anomaly_flagged` fields present in MiniClassification | unit | `pytest tests/test_mini_semantic.py::test_anomaly_fields -x` | Wave 0 |
| HARD-04 | Benchmark script produces JSON with before/after delta section | integration | `pytest tests/test_hardened_benchmark.py::test_benchmark_output_schema -x` | Wave 0 |
| HARD-05 | p95 latency < 25ms for Tier 1.5 + Mahalanobis on test text | integration | `pytest tests/test_latency.py::test_tier15_mahalanobis_latency -x` | Wave 0 |
| HARD-05 | Dual-output ONNX has logits at index 0, cls_embedding at index 1 | unit | `pytest tests/test_mini_semantic.py::test_onnx_output_order -x` | Wave 0 |

### Sampling Rate

- **Per task commit:** `uv run pytest tests/test_mini_semantic.py tests/test_mahalanobis.py -x -q`
- **Per wave merge:** `uv run pytest tests/ -x -q`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_augmentation.py` — covers HARD-01 augmentation schema and provenance tracking
- [ ] `tests/test_train_freelb.py` — covers HARD-02 FreeLB integration (smoke + gradient test)
- [ ] `tests/test_mahalanobis.py` — covers HARD-03 Mahalanobis module (fit, threshold, score)
- [ ] `tests/test_hardened_benchmark.py` — covers HARD-04 benchmark output schema
- [ ] `tests/test_latency.py` — covers HARD-05 latency gate

All five test files are new (no existing Phase 2 test infrastructure). Existing `tests/test_mini_semantic.py` must be extended with `test_anomaly_fields` and `test_onnx_output_order` tests when v4 ONNX is available.

---

## Sources

### Primary (HIGH confidence)

- Zhu et al. 2020, "FreeLB: Enhanced Adversarial Training for Natural Language Understanding," ICLR 2020 (arxiv:1909.11764) — FreeLB algorithm, epsilon defaults, K=3 PGD steps, gradient accumulation pattern
- Lee et al. 2018, "A Simple Unified Framework for Detecting Out-of-Distribution Samples and Adversarial Attacks," NeurIPS 2018 (arxiv:1807.03888) — Mahalanobis distance detection, per-class Gaussian fitting
- Yoo & Qi 2021, "Towards Improving Adversarial Training of NLP Classifiers," EMNLP Findings 2021 (arxiv:2109.00544) — A2T results, 30-50% ASR reduction on IMDB/Yelp with PWWS augmentation
- Yoo et al. 2022, "Adversarial Example Detection for NLP with Robust Density Estimation," ACL Findings 2022 (arxiv:2203.01677) — AUC 85-98% for RDE/Mahalanobis on NLP adversarial detection benchmark
- TextAttack documentation (Morris et al. 2020, arxiv:2005.05909) — PWWS recipe, ModelWrapper protocol, AttackArgs
- Phase 1 transfer experiment results: `docs/results/transfer-experiment-2026-03-10.json` — confirmed PWWS attack success rate (58.0%), `MiniLMOnnxWrapper` validated
- Pivot alternatives survey: `docs/results/pivot-alternatives-survey-2026-03-10.md` — citation audit for all projected claims
- Existing codebase: `scripts/train_mini_model.py` (lines 290-326 training loop, lines 82-103 model), `scripts/transfer_experiment.py` (MiniLMOnnxWrapper, PWWSRen2019 usage), `scripts/adversarial_benchmark.py` (`_score_raw`, delta comparison)
- torch.onnx documentation — dynamic axes, opset 18, multiple output names

### Secondary (MEDIUM confidence)

- Li & Qiu 2021, "Token-Aware Virtual Adversarial Training in Medical NLP," AAAI 2021 (doi:10.1609/aaai.v35i13.17022) — step_size = 2ε/K heuristic
- ACL Findings 2023, "Investigating Adversarial Training Robustness and Generalization" (aclanthology.org/2023.findings-acl.496) — <5% improvement on unseen attack types (generalization ceiling)
- scikit-learn LedoitWolf documentation — optimal covariance shrinkage for small-n Gaussians

### Tertiary (LOW confidence — marked as PROJECTED in citation audit)

- ASR reduction "58% → 35-42%": projected from A2T IMDB/Yelp extrapolation to our 6,340-sample dataset — must validate experimentally
- Mahalanobis single-layer CLS AUC "75-85%": degraded estimate from multi-layer RDE (85-98%); no paper benchmarks single-layer on PI detection — must validate experimentally
- FreeLB "+0.1-0.5% clean F1": extrapolated from GLUE multi-task to binary classification — treat as "neutral to slightly positive"

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already installed and validated in Phase 1 or existing training pipeline
- FreeLB algorithm: HIGH — primary paper cited, algorithm is well-specified
- ONNX dual-output: HIGH — pattern is standard torch.onnx.export usage, backward compatibility is certain
- Mahalanobis implementation: HIGH — primary papers cited, numpy/scipy implementation is straightforward
- ASR improvement targets: LOW — all projections from different task/dataset; must validate experimentally
- Mahalanobis detection rate: LOW — projected from multi-layer results to single-layer; must validate experimentally

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (30 days — stack is stable; textattack and transformers version pinned in venvs)
