---
language: en
license: apache-2.0
tags:
  - prompt-injection
  - security
  - text-classification
  - onnx
datasets:
  - prodnull/prompt-injection-repo-dataset
metrics:
  - accuracy
  - f1
  - precision
  - recall
pipeline_tag: text-classification
model-index:
  - name: cloneguard-mini-semantic-v3
    results:
      - task:
          type: text-classification
          name: Prompt Injection Detection
        metrics:
          - name: F1 (5-fold CV)
            type: f1
            value: 0.9580
          - name: Accuracy (5-fold CV)
            type: accuracy
            value: 0.9570
          - name: Precision (5-fold CV)
            type: precision
            value: 0.9623
          - name: Recall (5-fold CV)
            type: recall
            value: 0.9537
---

# CloneGuard Mini Semantic Classifier v3

Fine-tuned [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) for detecting prompt injection attacks in AI coding agent configuration files. v3 adds 669 augmentation samples targeting out-of-distribution FPR and adversarial robustness.

## Model Description

Binary classifier that detects prompt injection payloads targeting AI coding agents (Claude Code, GitHub Copilot, Cursor, Gemini CLI, Codex CLI). Designed to run as part of [CloneGuard](https://github.com/prodnull/cloneguard), a pre-execution defense layer.

- **Base model:** all-MiniLM-L6-v2 (22M parameters, 384-dim embeddings)
- **Classification head:** MeanPool → Linear(384,128) → ReLU → Dropout(0.1) → Linear(128,2)
- **Export:** ONNX opset 18 (87 MB)
- **Runtime:** onnxruntime CPUExecutionProvider, ~16 ms/sample

## Intended Use

Scanning repository files (CLAUDE.md, README.md, package.json, Makefile, CI configs, etc.) for prompt injection before an AI coding agent processes them. Part of a layered defense:

1. **Tier 0** — Regex pattern matching (191 rules, <1 ms)
2. **Tier 1.5** — This model (semantic classification, ~16 ms)
3. **Tier 2** — Ollama LLM fallback (~680 ms)

## Training Data

6,340 labeled samples (3,033 malicious, 3,307 benign) built in 8 rounds from 14+ published research sources and 59 real GitHub repositories. Rounds 7-8 added 669 samples to fix out-of-distribution FPR (40-87% → 0-33%) identified by the adversarial benchmark. Sources include:

- arXiv:2509.22040 (AIShellJack), arXiv:2601.17548, arXiv:2602.10453, arXiv:2503.14281 (XOXO)
- Pillar Security, Snyk ToxicSkills, IDEsaster (30+ CVEs), Cymulate InversePrompt
- OWASP LLM Top 10 2025

Attack categories: instruction override, credential harvesting, exfiltration, behavioral manipulation, encoding evasion, homoglyphs, social engineering, insecure code generation, MCP tool poisoning, plugin supply chain, counter-defensive attacks, and more.

## Evaluation

### Multi-Tier Pipeline (Primary, v3)

When combined with Tier 0 regex (191 patterns), the tiers compensate for each other. Evaluated on 185 adversarial payloads + 234 held-out benign samples (production mode):

| Metric | Tier 0 alone | Tier 1.5 alone | Combined Pipeline |
|--------|:------:|:--------:|:------:|
| Recall | 31.9% | 78.4% | **80.5%** |
| False block rate | — | — | **3.8%** |
| Clean pass rate | — | — | 77.8% |

### Adversarial Robustness Benchmark (v3)

185 adversarial payloads (9 categories + multilingual smoke) evaluated against 234 held-out benign samples. No training data overlap.

**Recall (production mode, threshold 0.50):**

| Category | Recall |
|----------|:------:|
| Encoding evasion | 100% |
| Synonym substitution | 100% |
| Homoglyph/Unicode | 95% |
| Structural dilution | 95% |
| Social engineering | 90% |
| Truncation padding | 80% (requires sliding window) |
| Counter-defensive | 80% |
| Implicit instruction | 45% (structural limitation) |
| Fragmentation | 20% (structural limitation; Tier 0 compensates) |

**FPR (production mode, held-out eval):** 0-33% depending on content type. Best: config/env (0%), worst: agent instructions (33%), workflows (24%).

### Cross-Validated Metrics (v2 dataset, 5,671 samples)

5-fold stratified cross-validation on the original dataset:

| Metric | Value |
|--------|:-----:|
| F1 | 95.80% ± 0.65% |
| Accuracy | 95.70% ± 0.66% |
| Precision | 96.23% ± 0.79% |
| Recall | 95.37% ± 0.93% |

## Limitations

- **Multilingual:** Limited non-English training data (~30 samples). Lower recall for non-English attacks.
- **256-token window:** Content beyond 256 WordPiece tokens scanned via sliding window (256-token, 128-stride, max 16 chunks). Long benign files may produce false positives from context-free chunks.
- **Mean-pooling dilution:** Mitigated by line-level code block scanning, but non-fenced prose dilution remains theoretical risk.
- **Training bias:** Primarily English-language attacks from published research. Novel vectors may evade.
- **Binary classification:** SUSPICIOUS is threshold-based (0.5-0.8), not a trained class.

## How to Use

```python
from cloneguard.mini_semantic import MiniSemanticClassifier

classifier = MiniSemanticClassifier()
if classifier.available:
    result = classifier.classify("Ignore all previous instructions")
    print(result.verdict, result.confidence)
    # MALICIOUS 0.998
```

## Citation

If you use this model in research, please cite the CloneGuard project and the underlying research papers listed in the training data section.
