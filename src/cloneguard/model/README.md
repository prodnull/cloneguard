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
  - name: cloneguard-mini-semantic-v1
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

# CloneGuard Mini Semantic Classifier v1

Fine-tuned [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) for detecting prompt injection attacks in AI coding agent configuration files.

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

5,671 labeled samples (2,916 malicious, 2,755 benign) built in 6 rounds from 14+ published research sources including:

- arXiv:2509.22040 (AIShellJack), arXiv:2601.17548, arXiv:2602.10453, arXiv:2503.14281 (XOXO)
- Pillar Security, Snyk ToxicSkills, IDEsaster (30+ CVEs), Cymulate InversePrompt
- OWASP LLM Top 10 2025

Attack categories: instruction override, credential harvesting, exfiltration, behavioral manipulation, encoding evasion, homoglyphs, social engineering, insecure code generation, MCP tool poisoning, plugin supply chain, counter-defensive attacks, and more.

## Evaluation

### Cross-Validated Metrics (Primary)

5-fold stratified cross-validation — the honest generalization estimate:

| Metric | Value |
|--------|:-----:|
| Accuracy | 95.70% ± 0.66% |
| F1 | 95.80% ± 0.65% |
| Precision | 96.23% ± 0.79% |
| Recall | 95.37% ± 0.93% |

### Full-Dataset Evaluation (Reference Only)

These numbers include training samples and overstate generalization by ~3pp:

| Metric | Value |
|--------|:-----:|
| Accuracy | 98.97% |
| F1 | 99.08% |
| Precision | 99.19% |
| Recall | 98.98% |
| False Positive Rate | 1.04% |

**Adversarial evaluation** (26 crafted attacks by informed attacker): 81% model-only detection rate. Known evasions: truncation, dilution in long code blocks, ROT13, fragmentation. Combined with Tier 0 regex: higher effective rate.

**Out-of-distribution evaluation** (144 MCP tool result samples from [ferentin-net/mcp-guard](https://github.com/ferentin-net/mcp-guard)): 100% recall, 43% FPR. Attack patterns generalize across domains; benign class is domain-specific.

## Limitations

- **Multilingual:** Limited non-English training data (~30 samples). Lower recall for non-English attacks.
- **256-token window:** Content beyond 256 WordPiece tokens is truncated.
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
