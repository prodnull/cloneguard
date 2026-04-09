# Evaluation Results

## Detection Performance

### Tier 0 (Pattern Matching)

240 compiled regex rules across 34 categories.

| Metric | Value |
|--------|-------|
| Precision | 91.33% |
| Recall | 23.26% |
| F1 | 37.08% |
| Speed | <50ms full scan |

High precision, low recall. Catches known patterns reliably but is evasion-prone
to creative rewording.

### Tier 1.5 (Semantic Classifier)

Fine-tuned MiniLM-L6-v2, 5-fold cross-validated on 6,472 samples.

| Metric | Value |
|--------|-------|
| F1 | 94.34% +/- 0.77% |
| Recall | 93.68% +/- 1.77% |
| Precision | 96.23% +/- 0.79% |
| Speed | ~16ms per sample |

Catches synonym substitution, social engineering, encoding evasion, and
homoglyphs that regex misses.

### Combined Pipeline

185 adversarial + 234 benign samples in production configuration.

| Metric | Value |
|--------|-------|
| Combined recall | 80.5% |
| False block rate | 3.8% |
| False warning rate | 18.4% |
| Combined FPR | 22.2% |

Tier 0 and Tier 1.5 compensate for each other: Tier 0 catches truncation and
fragmentation attacks (80% recall on those classes) while Tier 1.5 catches
semantic evasion (100% recall on those classes).

### Out-of-Distribution

144 MCP tool result samples from an independent source (mcp-guard):

| Metric | Value |
|--------|-------|
| Recall | 100% |
| FPR | 43% |

Attack patterns generalize across domains. Benign class is domain-specific,
leading to high FPR on unfamiliar content types.

## Behavioral Sequence Detection

Validated against 208,127 real coding-agent sessions:

| Rule | False Positives | FPR | Mode |
|------|:-:|:-:|------|
| SEQ-001 | 5 | 0.0024% | Enforce |
| SEQ-002 | 0 | 0% | Enforce |
| SEQ-005 | 1 | 0.0005% | Enforce |
| SEQ-004 | 32,887 | 15.80% | Advisory |

## Adaptive Red Team

| Evaluation | Detection Rate |
|------------|:-:|
| Naive (13,597 garak probes) | 95.65% |
| Adaptive (118 payloads, 3 models) | 97.5% |
| Claude iterative (30 payloads) | 83.3% |
| Mistral iterative (30 payloads) | 100% |

## Performance Overhead

| Operation | Time |
|-----------|------|
| Tier 0 full repo scan | <50ms |
| Tier 1.5 per sample | ~16ms |
| SEQ rule evaluation | <0.5ms per event |
| Hook invocation overhead | ~20ms |

## Model and Dataset

Published on HuggingFace:

- Model: [`prodnull/minilm-prompt-injection-classifier`](https://huggingface.co/prodnull/minilm-prompt-injection-classifier)
- Dataset: [`prodnull/prompt-injection-repo-dataset`](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset)
