# Phase 2: Adversarial Hardening - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Harden MiniLM v3 against white-box vocabulary attacks (PWWS) through adversarial data augmentation and FreeLB embedding perturbation training. Add Mahalanobis anomaly detector on CLS embeddings as an orthogonal defense signal. Re-benchmark the hardened pipeline. Does NOT include publication, adaptive attacks, or correlated failure analysis (those are Phase 3).

</domain>

<decisions>
## Implementation Decisions

### Mahalanobis signal integration
- Export CLS embeddings (384-dim) alongside logits in the ONNX model — dual output heads
- Mahalanobis distance computed at inference as a separate signal, not merged into the classifier probability
- Anomaly score surfaces as a new `anomaly_score` field in scan results — additive, does not replace existing verdict
- When classifier says SAFE but Mahalanobis flags anomalous: escalate to SUSPICIOUS (defense-in-depth — false negative is worse than false positive)
- When classifier says MALICIOUS and Mahalanobis agrees: higher confidence, no behavior change
- Threshold: fit at ≤5% FPR on the 234-sample benign eval set (per HARD-03 requirement)
- Per-class Gaussian fit (separate means/covariances for SAFE vs MALICIOUS training embeddings)

### Augmentation rounds and stopping criteria
- Fixed 2-round minimum, up to 3 rounds maximum
- Each round: generate PWWS adversarial examples against the current model, add successful attacks (ASR > 0) to training set with correct malicious labels
- Stop early if ASR drops below target (≤35%) after round 2
- If 3 rounds still miss ≤35% ASR: accept and publish actual numbers, proceed to Phase 3 honestly — do NOT invoke TF-IDF contingency within this phase (TFIDF-01 remains deferred)
- Augmented samples labeled as malicious (they ARE injection attempts, just paraphrased)
- Track augmentation provenance: metadata field noting which round and attack method generated each sample

### Scan output and hook behavior
- New `anomaly_score` field added to Tier 1.5 scan results (float, 0.0 = normal, higher = more anomalous)
- New `anomaly_flagged` boolean field (true when score exceeds threshold)
- Existing MALICIOUS/SUSPICIOUS/SAFE verdict taxonomy unchanged — Mahalanobis escalates SAFE→SUSPICIOUS only, never overrides MALICIOUS
- Hook exit codes unchanged: 0=allow, 2=block. Mahalanobis escalation to SUSPICIOUS still exits 0 (warning, not block) unless Tier 0 also flagged it
- Backward-compatible: consumers that don't read `anomaly_score` see no behavior change except the SAFE→SUSPICIOUS escalation

### Model versioning and rollout
- Hardened model becomes v4 (v3 = current, v4 = adversarially hardened)
- Trust cache automatically invalidates on model hash change (H2 fix from v0.2.3 already handles this)
- Silent upgrade path: `fetch_model.py` pulls latest version, cache invalidates, no user action needed
- Model card on HuggingFace updated with v4 training methodology (adversarial augmentation + FreeLB)
- ONNX opset version stays at 18 — adding CLS output head is backward-compatible with existing onnxruntime versions

### Claude's Discretion
- FreeLB hyperparameters: ε magnitude, K steps, step size (start with literature defaults: ε=0.01, K=3)
- PWWS TextAttack recipe parameters and perturbation budgets
- Mahalanobis covariance regularization (shrinkage parameter)
- Exact augmentation sample counts per round
- Training hyperparameter adjustments for augmented dataset (learning rate warmup, epoch count)
- Compression/optimization of dual-output ONNX graph
- Benchmark script structure and metrics formatting

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/train_mini_model.py`: Training loop at lines 290-326 — FreeLB inserts gradient accumulation here. Mean pooling at lines 93-98 gives CLS-equivalent embedding (384-dim).
- `scripts/transfer_experiment.py`: `MiniLMOnnxWrapper` (TextAttack-compatible) — reuse for PWWS augmentation generation.
- `scripts/adversarial_benchmark.py`: `_score_raw()` bypasses thresholds for raw probabilities — use for ASR measurement between rounds.
- `src/cloneguard/mini_semantic.py`: ONNX inference. Currently exports logits only — needs dual-output (logits + CLS embedding) for Mahalanobis.
- `scripts/multitier_benchmark.py`: Combined Tier 0 + Tier 1.5 evaluation — extend for Mahalanobis signal.
- `scripts/fetch_model.py`: Model fetching infrastructure — update for v4 model artifact.

### Established Patterns
- ONNX export with dynamic axes (opset 18) in `train_mini_model.py`
- Benchmark results to `docs/results/` as JSON with date-stamped filenames
- Scripts use `sys.path.insert(0, "src")` for imports
- Training data as JSONL: `{"text": str, "label": 0|1}`
- Augmented data in `data/training/` with round metadata

### Integration Points
- `mini_semantic.py` classify methods: add CLS embedding extraction + Mahalanobis scoring
- `scanner.py:396-398`: where Tier 1.5 is called — Mahalanobis result flows through existing scan report
- `ScanReport` dataclass: add `anomaly_score` and `anomaly_flagged` fields
- Training data: extend `data/training/dataset_augmented_r2.jsonl` → new file with PWWS augmentation
- Model artifact: new v4 ONNX file replaces v3 in model directory

</code_context>

<specifics>
## Specific Ideas

- User directive: "Choose according to best practice and security" — all gray areas resolved toward defense-in-depth, false-negative-is-worse-than-false-positive stance
- Mahalanobis as escalation-only (SAFE→SUSPICIOUS), never suppression — consistent with project's "raise attacker cost" philosophy
- Augmentation provenance tracking enables audit of what the model learned from adversarial examples

</specifics>

<deferred>
## Deferred Ideas

- TF-IDF + XGBoost contingency (TFIDF-01) — only if Phase 2 results are unsatisfactory AND user decides to pursue after Phase 3 publication
- Adaptive attacks against hardened model — Phase 3 (BENCH-02)
- Correlated failure analysis — Phase 3 (BENCH-03)
- HuggingFace model card update with v4 methodology — Phase 3 publication scope

</deferred>

---

*Phase: 02-deberta-training-and-onnx-export*
*Context gathered: 2026-03-10*
