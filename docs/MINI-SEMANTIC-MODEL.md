# Mini Semantic Model (Tier 1.5)

Bundled ONNX classifier for prompt injection detection. Runs entirely offline with no external service dependencies.

## Summary

| Property | Value |
|----------|-------|
| Base model | sentence-transformers/all-MiniLM-L6-v2 (22M params) |
| Architecture | Mean-pooled embeddings → Linear(384,128) → ReLU → Dropout(0.1) → Linear(128,2) |
| Export format | ONNX (opset 18) |
| Model size | 87 MB |
| Runtime | onnxruntime CPUExecutionProvider |
| Tokenizer | WordPiece, max 256 tokens |
| Cross-validated F1 (v2) | 95.80% ± 0.65% (5-fold CV, original 5,671 samples) |
| Cross-validated F1 (v3) | 95.51% ± 0.53% (5-fold CV, augmented 6,340 samples) |
| Cross-validated accuracy (v4) | 94.51% ± 0.67% (5-fold CV, adversarially hardened 6,472 samples) |
| Cross-validated F1 (v4) | 94.34% ± 0.77% (5-fold CV, adversarially hardened 6,472 samples) |
| Validation accuracy (v3) | 96.21% (augmented dataset, 80/20 split) |
| Inference speed | ~16 ms/sample (Apple M-series CPU); p95 16.61 ms |
| ONNX outputs | logits (classification) + cls_embedding (Mahalanobis anomaly detection) |
| Dependencies | `onnxruntime>=1.17`, `transformers>=4.36`, `numpy>=1.26` |

## Role in Detection Architecture

```
Tier 0 (regex)  →  Tier 1.5 (this model)  →  Tier 2 (Ollama, fallback)
  <1 ms/file          ~16 ms/file               ~680 ms/file
  193 patterns         semantic classifier        qwen2.5:7b LLM
  23% recall           95.4% recall (CV)          42% recall
  91% precision        96.2% precision (CV)       93% precision
```

### Multi-Tier Pipeline Performance

When Tier 0 and Tier 1.5 run together (production mode), they compensate for each other's weaknesses. Evaluated on 185 adversarial payloads + 234 held-out benign samples:

| Metric | Tier 0 alone | Tier 1.5 alone | Combined Pipeline |
|--------|:------:|:--------:|:------:|
| Recall | 31.9% | 78.4% | **80.5%** |
| FPR | 9.8% | 15.4% | 22.2% |
| False block rate | — | — | **3.8%** |
| False warning rate | — | — | 18.4% |
| Clean pass rate | — | — | 77.8% |

Tier 0 catches truncation (80%) and fragmentation (20%) attacks that the semantic classifier misses due to token-window limits. Tier 1.5 catches synonym substitution (100%) and encoding evasion (100%) that regex cannot touch. Script: `scripts/multitier_benchmark.py`.

Tier 1.5 is the primary semantic defense. It runs when `--tier2` is enabled (or automatically in the Layer 0 wrapper). If onnxruntime is not installed, the system falls back to Tier 2 (Ollama). If neither is available, only Tier 0 regex runs.

Install from [GitHub Releases](https://github.com/prodnull/cloneguard/releases) (`.whl` includes the ONNX model).

## Adversarial Training (v4)

### Method: PWWS Augmentation + FreeLB

v4 applies two rounds of adversarial hardening to raise the cost of vocabulary-based
evasion attacks (PWWS, TextFooler-style synonym substitution):

**PWWS (Probability Weighted Word Saliency) augmentation:** For each sample the model
currently classifies correctly, PWWS identifies the most influential tokens and substitutes
them with semantically similar alternatives to flip the model's prediction. Successful
adversarial examples are added to the training set.

**FreeLB (Free Large-Batch) adversarial training:** During each training step, small
l-infinity-norm perturbations are applied to the input embeddings (epsilon=0.1, K=3 PGD
gradient accumulation steps). The model is trained to be consistent across perturbations
near each sample, tightening the decision boundary.

### Hardening Rounds

| Round | PWWS gen ASR | Samples added | Benchmark ASR | Benchmark recall |
|-------|:------------:|:-------------:|:-------------:|:----------------:|
| Baseline (v3) | 65.7%\* | — | 20.0%† | 80.0% |
| Round 1 | 65.7% | 88 | 24.9% | 75.1% |
| Round 2 | 31.7% | 44 | **20.0%** | **80.0%** |
| Final (v4) | — | — | **9.7%**‡ | **90.3%**‡ |

\*v3 generation ASR estimated from round 1 starting conditions.
†v3 benchmark ASR measured at round 2 start.
‡v4 numbers from Phase 3 hardened benchmark (757-sample benign eval, full pipeline).

Round 3 was skipped: ASR gate (≤35%) passed after round 2 (20.0%).

PWWS generation ASR progression (65.7% → 31.7%) confirms hardening: the model learned
to resist PWWS-style synonym substitution across two iterations.

### Adversarial Robustness (v4)

From the hardened benchmark (185 adversarial payloads, v4 model):

| Metric | Value |
|--------|:-----:|
| Overall recall | 90.3% |
| ASR (all categories) | 9.7% |
| ASR (vocabulary attacks: encoding + synonym + homoglyph) | 0.0% |
| Adaptive PWWS ASR (test-time, fresh adversary) | 20.3% (CI: 14.6%–27.5%) |
| Latency p95 | 16.61 ms |

The adaptive ASR (20.3%) is higher than the benchmark ASR (9.7%) because it measures a
fresh PWWS adversary against the fully-trained v4 model, rather than the training-time
measurement. See `docs/SECURITY.md` for full discussion.

### Mahalanobis Anomaly Detection

v4 exports cls_embedding as a second ONNX output, enabling Mahalanobis distance anomaly
detection. The detector is calibrated on the training set (threshold 20.78, 99th percentile).

Results on the adversarial corpus:
- Detection rate: **2.7%** (5/185 samples)
- FPR: **1.2%** (9/757 benign samples)
- Distribution overlap: benign mean 17.59, malicious mean 17.21

The detection rate did not meet the target (60%). PWWS adversarial examples preserve
semantic similarity by construction — the CLS distributions do not separate sufficiently
for Mahalanobis scoring to be effective. Applied only in single-chunk classify() path;
calibration domain (single-chunk training samples) must match inference domain.

## Benchmark Results

### Cross-Validated Metrics (Primary)

5-fold stratified cross-validation on v3 augmented dataset (6,340 samples) — the honest generalization estimate:

| Metric | Tier 0 (Regex) | Tier 1.5 (ONNX, 5-fold CV) | Tier 2 (Ollama) |
|--------|:-:|:-:|:-:|
| **Accuracy** | 54.91% | **95.71% ± 0.53%** | 69.50% |
| **Precision** | 91.33% | **95.79% ± 1.55%** | 93.33% |
| **Recall** | 23.26% | **95.25% ± 1.21%** | 42.00% |
| **F1 Score** | 37.08% | **95.51% ± 0.53%** | 57.93% |
| **Speed** | 0.1 ms | 16 ms | 682 ms |

Hyperparameters were selected via comprehensive grid search (192 configurations, 2-phase screening + validation). See `bench/comprehensive_sweep.json`.

### Out-of-Distribution Evaluation (MCP Tool Results)

144 hand-written samples from [ferentin-net/mcp-guard](https://github.com/ferentin-net/mcp-guard) (Apache 2.0) — an independent project focused on MCP tool result scanning. These samples represent a completely different domain (JSON APIs, Slack messages, Kubernetes output, web pages) that the model was never trained on.

| Metric | Value |
|--------|:-----:|
| **Recall** | 100% (68/68 malicious detected) |
| **FPR** | 43.4% (33/76 benign flagged) |
| **Accuracy** | 77.1% |
| **F1** | 80.5% |

All 10 attack categories (instruction override, authority impersonation, reasoning hijack, behavioral manipulation, data exfiltration, tool poisoning, encoding obfuscation, mixed context, benchmark challenges) were detected at 100%. False positives concentrated on content formats absent from training data (JSON API responses, chat messages, infrastructure output).

**Interpretation:** Attack detection generalizes across domains — the semantic patterns the model learned from repository files transfer to MCP tool results. The benign class is domain-specific: the model is specialized for repository file scanning, not general-purpose tool output classification.

### Independent Validation (Hand-Crafted)

Fresh test cases crafted independently — NOT from the training data:

| Test | Samples | Detection Rate | Notes |
|------|---------|:-:|---|
| Obvious injection | 10 | 100% | All >99% confidence |
| Subtle/evasive injection | 10 | 90% | 1 tokenization edge case |
| Benign samples | 11 | 90.9% TNR | 1 SQL INSERT FP at borderline |
| Gemini adversarial evasions | 49 | 100% | 10 strategies, single-query |
| Mean-pooling dilution | 1 | 0% (whole-text) / 100% (line scanner) | Architectural limitation |

**Known limitations found during validation:**
- SQL `INSERT INTO` can trigger borderline false positive (~90.7% confidence)
- Mean-pooling dilution: 1 malicious line in 8+ benign lines evades whole-text classification (mitigated by `_scan_code_block_lines()`)
- The 100% Gemini adversarial rate reflects single-query attempts. An attacker with iterative black-box access to the model would likely achieve evasion.

### Full-Dataset Evaluation (Reference Only)

These numbers include training samples and overstate generalization:

| Metric | Value |
|--------|:-----:|
| Accuracy | ~99% |
| Note | In-distribution; see cross-validated and OOD metrics above for honest performance |

Tier 2 (Ollama qwen2.5:7b) was evaluated on a balanced random sample of 200 items (seed=42). Its poor recall (42%) is due to the general-purpose LLM frequently classifying attack payloads as safe — it was not fine-tuned for this task.

## Training Dataset

### Composition

**v4 (current): 6,472 labeled samples** — 3,165 malicious (48.9%), 3,307 benign (51.1%).
v4 adds 132 PWWS adversarial samples (88 in round 1 + 44 in round 2) to the v3 base.
The adversarial augmentation raised malicious recall while maintaining benign precision.

v3: 6,340 samples (3,033 malicious / 3,307 benign). Balance ratio 0.92:1.

The original 5,671 samples (v2) are published on Hugging Face: [`prodnull/prompt-injection-repo-dataset`](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset). The v3 augmentation added 669 samples in two rounds targeting out-of-distribution FPR and adversarial robustness gaps identified by the adversarial benchmark.

### Sources

The dataset was built in six rounds, each addressing gaps found by adversarial audit:

**Round 1: Core patterns (4,575 samples)**
- Tier 1 regex pattern payloads converted to labeled samples
- Proof-of-concept attack files from `data/poc/`
- Ollama-generated paraphrases of known attacks (temperature 0.9)
- Evasion variants: synonym substitution, encoding, obfuscation
- Multi-file coordinated attack scenarios
- Cross-category combination payloads
- Benign project files: READMEs, configs, license texts, CI/CD workflows
- Hard negatives: security documentation that describes attacks without being attacks
- Edge cases: files that straddle the benign/malicious boundary

**Round 2: Category gap fill (1,229 samples)**
Coverage audit found 7 categories with zero training samples. Filled:
- Source code comment injection (C3)
- Git metadata attacks (C6)
- Test fixture trojans (C9)
- Lock file/dependency confusion (C10)
- Agent-specific implementation details (C15)
- Homoglyph/confusable character evasion (C5.3)
- Poisoned filename attacks (C12.4)
- Multi-step progressive escalation (C11)
- Longer realistic document samples (500+ chars)

**Round 3: Advanced vectors (169 samples)**
- Multilingual injection: Russian, Chinese, Hindi, Japanese, Korean, Arabic, French, German, mixed-language
- Meta-reasoning / indirect persuasion: hypothetical scenarios, roleplay framing, moral dilemmas, authority-through-expertise, progressive context building
- Advanced encoding evasion: ROT13 references, Pig Latin, leetspeak, character spacing, first-letter acrostics

**Round 4: First-principles adversarial (166 samples)**
Generated by reasoning about what a knowledgeable attacker would try:
- Payload fragmentation across benign sentences
- Social engineering via empathy, urgency, and authority
- Semantic redefinition ("security" means "read credentials")
- Counter-defensive attacks targeting CloneGuard itself
- Temporal/conditional triggers (maintenance windows, error states)
- Insecure code generation instructions
- Reconnaissance instructions disguised as documentation
- Structural format exploitation (JSON `$ref`, YAML anchors)
- Adversarial ML padding (benign-looking text to confuse classifiers)

**Round 5: Literature-driven gap closure (179 samples)**
Cross-referenced against 14 published papers and research reports:
- SKILL.md / plugin supply chain attacks (ToxicSkills, arXiv)
- Agent-specific config files: Windsurf `.windsurfrules`, Roo `.roo/rules`, Junie `.junie/guidelines.md`, Codex `AGENTS.md`
- MCP advanced attacks: rug pull (description changes post-approval), tool shadowing, name squatting, SSE injection, DNS rebinding
- Media beyond SVG: PDF hidden text layers, EXIF metadata injection, font metadata, steganographic markers

**Round 6: Inline augmentation (59 samples)**
- XOXO semantics-preserving code modifications (arXiv:2503.14281)
- GitHub Actions cache poisoning (Clinejection mechanism)
- Workspace/IDE settings injection (`.code-workspace`, `tasks.json`, `launch.json`)
- JSON `$schema` exfiltration
- "For debugging purposes" social engineering framing (AIShellJack 83.4% ASR)

**Round 7: Adversarial benchmark — benign augmentation (523 samples)**
Driven by adversarial benchmark results showing 40-87% FPR on real-world content. The model had never seen realistic repository files during training:
- 352 real samples from 59 GitHub repos (CLAUDE.md, .cursorrules, READMEs, workflows, test files, configs) selected for AI-native activity (agent instruction files present, 30+ stars, active 6 months)
- 149 synthetic gap-fill across 8 content types where real samples were sparse
- 42 malicious samples from encoding evasion, homoglyph, and structural dilution categories
- 70/30 train/eval split to prevent data leakage in benchmark

**Round 8: Targeted adversarial augmentation (104 samples)**
Driven by round 7 benchmark showing truncation_padding regression (100% → 0% raw) and counter-defensive regression (85% → 65%):
- 50 truncation padding attack cores — isolated payload chunks that the sliding window would extract, training the model to flag them independently
- 25 counter-defensive malicious samples — attempts to disable/bypass CloneGuard, distinguishable from legitimate configuration
- 15 counter-defensive benign samples — legitimate CloneGuard documentation and configuration
- 14 real long-form benign samples from major OSS repos (React, Next.js, Django, Flask, Ruff, uv) for sliding window FPR reduction

### Quality Controls

- **Deduplication:** Exact-match dedup after each round
- **Label audit:** Automated regex-based scan fixed 68 mislabeled samples (benign README headers like `## Roadmap` incorrectly labeled malicious)
- **Shuffle:** Final dataset shuffled with seed=42 for reproducible splits
- **Hard negatives:** Deliberate inclusion of security documentation, CVE descriptions, and pentesting guides labeled as benign — these are the primary source of false positives

### Source Literature

The attack catalog draws from peer-reviewed research and vendor disclosures:

| Source | Contribution |
|--------|-------------|
| arXiv:2509.22040 (AIShellJack) | 70 MITRE ATT&CK techniques, 84% attack success rate |
| arXiv:2601.17548 | 42-attack taxonomy for coding assistants |
| arXiv:2602.10453 | 30+ prompt injection techniques survey |
| arXiv:2503.14281 (XOXO) | Semantics-preserving code modifications |
| Pillar Security "Rules File Backdoor" | Unicode obfuscation in .cursorrules |
| Snyk "ToxicSkills" | 1,467 malicious skills on ClawHub |
| IDEsaster (30+ CVEs) | Cross-IDE prompt injection to tool abuse |
| Cymulate "InversePrompt" | Claude Code path bypass + command injection |
| Lasso Security "Hidden Backdoor" | PostToolUse defense bypass |
| Greshake et al. (2023) | Foundational indirect prompt injection |
| Microsoft/UVA "Trojan Puzzle" | Poisoned code suggestion triggers |
| OWASP LLM Top 10 2025 | LLM01 Prompt Injection |

## Training Process

### Hyperparameters

| Parameter | Value | Selection |
|-----------|-------|-----------|
| Base model | sentence-transformers/all-MiniLM-L6-v2 | |
| Epochs | 8 | Grid search (3,4,6,8) |
| Learning rate | 3e-5 (AdamW) | Grid search (2e-5, 3e-5, 5e-5) |
| Batch size | 32 | |
| Weight decay | 0.01 | Grid search (0.01, 0.05) |
| Dropout | 0.1 | Grid search (0.1, 0.2, 0.3, 0.4) |
| Hidden dim | 128 | Grid search (64, 128) |
| Max sequence length | 256 tokens | |
| Train/val split | 80/20 stratified | |
| Device | MPS (Apple Metal) | |
| Training time | ~3 minutes | |

A 192-configuration grid search (2-phase: 2-fold screening, 5-fold validation on top 15) confirmed the current config is near-optimal. The top candidate (ep=6, do=0.2, lr=5e-5, wd=0.05, hd=64) achieved CV F1=96.23% (+0.44pp) but introduced false positives on short inputs due to aggressive embedding compression (hd=64). The current config (hd=128) provides more stable classification across input lengths.

### Classification Head

The base MiniLM encoder produces 384-dimensional token embeddings. These are mean-pooled across the sequence, then passed through:

```
MeanPool(token_embeddings) → Linear(384, 128) → ReLU → Dropout(0.1) → Linear(128, 2)
```

Output: 2-class logits (safe, malicious). Softmax applied at inference.

### Decision Thresholds

| Malicious Probability | Verdict |
|:---------------------:|---------|
| > 0.8 | MALICIOUS |
| > 0.5 | SUSPICIOUS |
| ≤ 0.5 | SAFE |

Confidence is reported as the probability of the predicted class (malicious_prob for MALICIOUS/SUSPICIOUS, 1-malicious_prob for SAFE).

### Training Results

**v4 model (current, 6,472 samples — adversarially hardened):**

| Metric | Value |
|--------|:-----:|
| Cross-validated accuracy | 94.51% ± 0.67% |
| Cross-validated F1 | 94.34% ± 0.77% |
| Cross-validated precision | 95.04% ± 1.20% |
| Cross-validated recall | 93.68% ± 1.77% |
| Cross-validated FPR | 4.69% ± 1.55% |
| Validation accuracy (80/20 split) | 95.44% |

**v3 model (6,340 samples):**

| Metric | Value |
|--------|:-----:|
| Validation accuracy | 96.21% |
| Validation precision (benign) | 96.65% |
| Validation recall (benign) | 96.07% |
| Validation precision (malicious) | 95.74% |
| Validation recall (malicious) | 96.38% |

**v2 model (original, 5,671 samples, 5-fold CV):**

| Metric | Value |
|--------|:-----:|
| Cross-validated F1 (v2) | 95.80% ± 0.65% |
| Cross-validated accuracy (v2) | 95.70% ± 0.66% |
| Cross-validated precision (v2) | 96.23% ± 0.79% |
| Cross-validated recall (v2) | 95.37% ± 0.93% |

**v3 model 5-fold cross-validation (6,340 samples):**

| Metric | Value |
|--------|:-----:|
| Cross-validated F1 (v3) | 95.51% ± 0.53% |
| Cross-validated accuracy (v3) | 95.71% ± 0.53% |
| Cross-validated precision (v3) | 95.79% ± 1.55% |
| Cross-validated recall (v3) | 95.25% ± 1.21% |
| Cross-validated FPR (v3) | 3.87% ± 1.55% |

The v3 augmentation (669 samples targeting OOD FPR and adversarial robustness) did not degrade generalization — v3 CV F1 (95.51%) is within the confidence interval of v2 CV F1 (95.80%). The adversarial benchmark provides the honest out-of-distribution evaluation.

## Adversarial Evaluation

### Adversarial Robustness Benchmark (v3 model, 185 malicious + 234 held-out benign)

Systematic benchmark across 9 adversarial categories + multilingual smoke test, evaluated on held-out data (no training overlap). Design: `docs/plans/2026-03-09-adversarial-benchmark-design.md`. Script: `scripts/adversarial_benchmark.py`.

**Per-category recall (production mode, threshold 0.50):**

| Category | Payloads | Recall | Notes |
|----------|:--------:|:------:|-------|
| Encoding evasion (base64, hex, ROT13, Unicode) | 20 | **100%** | Augmented in training |
| Synonym substitution | 20 | **100%** | |
| Homoglyph/Unicode (Cyrillic, ZWJ, RTL) | 20 | **95%** | Augmented in training |
| Structural dilution (payload in long benign text) | 20 | **95%** | Augmented in training |
| Social engineering (authority, urgency, compliance) | 20 | **90%** | |
| Truncation padding (benign preamble + payload) | 20 | **80%** | Sliding window required; 25% raw |
| Counter-defensive (targeting the scanner) | 20 | **80%** | Augmented in round 8 |
| Multilingual smoke test | 5 | **80%** | Full coverage deferred (#5) |
| Implicit instruction (behavioral nudges) | 20 | **45%** | Structural limitation |
| Fragmentation (attack split across short phrases) | 20 | **20%** | Structural limitation; Tier 0 compensates |

**Per-content-type FPR (production mode, threshold 0.50, held-out eval set):**

| Content Type | Samples | FPR | Notes |
|--------------|:-------:|:---:|-------|
| Config (pyproject.toml, tsconfig, etc.) | 23 | **0%** | |
| Env config (.env files) | 17 | **0%** | |
| Security documentation | 15 | **7%** | |
| Build scripts (Makefile, Dockerfile) | 17 | **12%** | |
| README files | 44 | **14%** | |
| Test files | 53 | **19%** | Sliding window effect on long files |
| GitHub Actions workflows | 50 | **24%** | Sliding window effect on long files |
| Agent instructions (CLAUDE.md, .cursorrules) | 15 | **33%** | Sliding window sensitive to instruction-like chunks |

**Improvement from original model (pre-augmentation):**
- FPR: 27-88% → 0-33% (production mode with sliding window)
- Recall: encoding 85%→100%, homoglyph 90%→95%, structural dilution 55%→95%, counter-defensive 85%→80%

**Structural limitations identified:**
- Fragmentation: payloads under ~30 chars / 10 tokens are indistinguishable from benign instructions. Tier 0 regex is the appropriate defense for these.
- Implicit instruction: behavioral nudges without explicit attack keywords. More data unlikely to help — the payloads genuinely resemble legitimate coding guidelines.
- Sliding window FPR: long benign files scanned chunk-by-chunk produce isolated chunks that lack context, raising FPR for workflows and test files.

### Original Adversarial Evaluation (v1/v2 model, 26 payloads)

26 crafted adversarial payloads across 9 attack categories, pre-augmentation:

| Category | Attacks | Caught | Evasion Rate |
|----------|:-------:|:------:|:------------:|
| Truncation (payload past 256 tokens) | 2 | 0 | 100% |
| Benign dilution | 2 | 1 | 50% |
| Encoding evasion (base64, hex, ROT13) | 4 | 3 | 25% |
| Fragmentation | 3 | 2 | 33% |
| Semantic rephrasing | 5 | 5 | 0% |
| Homoglyph/Unicode | 3 | 3 | 0% |
| Implicit (package.json, Makefile, CI) | 3 | 3 | 0% |
| Counter-defensive (target scanner) | 2 | 2 | 0% |
| Temporal/conditional triggers | 2 | 2 | 0% |
| **Total** | **26** | **21** | **19%** |

### Structural Vulnerability: Mean-Pooling Dilution

The model uses mean-pooling over all token embeddings before classification. This creates a fundamental vulnerability:

**Attack:** Embed a short malicious instruction inside a long block of legitimate code or documentation. The malicious tokens' contribution to the mean is overwhelmed by the majority benign tokens.

**Practical impact:** Moderate. Exploiting this requires:
1. The malicious payload must be short (1-2 lines)
2. The surrounding context must be genuinely benign code/config
3. The payload must still accomplish the attacker's goal when the agent processes it
4. Tier 0 regex must also miss the payload (it independently scans each line)

For a watering hole attack, the attacker would need to plant a single exfiltration line in a build script of an otherwise legitimate repository — a scenario that Tier 0 regex pattern matching would likely catch (curl/wget to external URLs are pattern-matched).

**Mitigations (implemented):**
- **Code block line scanning:** When whole-file classification returns SAFE, the classifier extracts lines from fenced code blocks (` ```...``` `) and classifies each individually. If any line triggers MALICIOUS or SUSPICIOUS, the file is escalated. This directly counters the dilution attack — the `curl` exfiltration line classified alone scores 99.0% MALICIOUS.
- **Sliding window classification:** When the initial whole-text classification returns SAFE and input exceeds 256 tokens, the classifier applies a sliding window: 256-token window, 128-token stride (50% overlap), max 16 chunks. This covers ~8K characters of content (~256ms worst case). Content beyond 16 chunks still relies on Tier 0 regex. The 50% overlap prevents boundary-splitting evasion where a payload is deliberately positioned to straddle a chunk boundary.
- **Tier 0 regex:** Scans line-by-line independently, catching most dilution attacks via pattern matching on curl/wget/exfiltration URLs.

**Future improvements:**
- Max-pooling or attention-weighted pooling instead of mean-pooling (requires retraining)

## Known Limitations

1. **Mean-pooling dilution (partially mitigated).** Short malicious payloads embedded in long benign code blocks can evade whole-file classification. Mitigated by line-level scanning of fenced code blocks, but non-fenced prose dilution remains a theoretical risk. See Structural Vulnerability section above.

2. **Multilingual coverage.** The training set contains ~30 multilingual samples. The model detects some non-English attacks but has lower recall for languages underrepresented in training (Russian tested at 86% benign — a false negative). Non-English attacks are better handled by Tier 2 (Ollama) if available.

3. **256-token window (mitigated).** Content beyond the first 256 WordPiece tokens is now scanned via sliding window classification (256-token window, 128-token stride, max 16 chunks covering ~8K chars). Content beyond ~8K chars still relies on Tier 0 regex coverage. The chunk cap prevents DoS from extremely long inputs while covering the vast majority of scanned file types (instruction files, configs, tool arguments).

4. **Training data bias.** The model was trained primarily on English-language attack patterns from published research. Novel attack vectors not represented in the literature may evade detection.

5. **False positives on long content via sliding window.** When the sliding window scans long benign files chunk-by-chunk, individual chunks lacking context can trigger false positives. Production-mode FPR on held-out data: 0-33% depending on content type (worst: agent instructions at 33%, workflows at 24%). Raw single-window FPR is much lower (0-12%).

6. **Binary classification.** The model outputs safe/malicious. The SUSPICIOUS verdict is a confidence-based threshold (0.5-0.8), not a separate trained class. True three-class classification could improve nuance.

## Files

```
src/cloneguard/
├── mini_semantic.py          # Runtime classifier (MiniSemanticClassifier)
└── model/
    ├── mini_semantic.onnx    # 87 MB ONNX model (downloaded via scripts/fetch_model.py)
    ├── tokenizer.json        # 695 KB WordPiece tokenizer
    ├── tokenizer_config.json
    ├── vocab.txt             # 226 KB vocabulary
    └── special_tokens_map.json

scripts/
├── train_mini_model.py       # Fine-tuning + ONNX export
├── fetch_model.py            # Download pre-trained ONNX model
├── benchmark_tiers.py        # Tier 0 vs 1.5 vs 2 comparison
├── adversarial_eval.py       # Informed attacker simulation
├── kfold_eval.py             # K-fold cross-validation evaluation
├── hyperparameter_sweep.py   # Hyperparameter grid search
├── comprehensive_sweep.py    # Extended 192-config sweep
├── ood_eval_mcp_guard.py     # Out-of-distribution MCP evaluation
└── consistency_check.py      # Dataset/model consistency checks

data/training/
├── dataset.jsonl             # 5,671 labeled samples (v2, also on HuggingFace)
└── dataset_augmented_r2.jsonl # 6,340 labeled samples (v3, current training set)
```

## Reproducing

```bash
# Dataset is on HuggingFace: prodnull/prompt-injection-repo-dataset
# Download and convert if needed:
# hf download prodnull/prompt-injection-repo-dataset

# Train and export (requires torch, transformers, onnx)
uv run python scripts/train_mini_model.py

# Download the model (if not training from scratch)
uv run python scripts/fetch_model.py

# Benchmark
uv pip install -e ".[mini]"
uv run python scripts/benchmark_tiers.py
uv run python scripts/adversarial_eval.py
uv run python scripts/kfold_eval.py
```
