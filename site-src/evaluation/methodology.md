# Evaluation Methodology

CloneGuard's detection capabilities are evaluated through multiple independent
approaches. All evaluation data and scripts are published in the repository.

## Approach 1: Pattern-Level Testing

Every detection rule has at least one positive and one negative test case.
1,677 automated tests cover rule matching, severity classification, scan mode
behavior, and edge cases.

```bash
pytest tests/
```

## Approach 2: Pipeline Benchmarks

End-to-end benchmarks measure the combined detection pipeline (pattern +
semantic + behavioral) against curated sample sets:

- **185 adversarial samples** -- payloads designed to evade detection, sourced
  from public datasets and generated via adversarial techniques
- **234 held-out benign samples** -- real-world code and documentation that
  should not trigger detections

| Metric | Tier 0 alone | Tier 1.5 alone | Combined |
|--------|:---:|:---:|:---:|
| Recall | 31.9% | 78.4% | 80.5% |
| FPR | 9.8% | 15.4% | 22.2% |
| False block rate | -- | -- | 3.8% |

## Approach 3: False Positive Calibration

False positive rates were validated against 208,127 real coding-agent sessions
mined from three published SWE-bench datasets on HuggingFace (SWE-smith,
Nebius, OpenHands). These are benign agent sessions solving GitHub issues.

| Rule | FPR | Verdict |
|------|-----|---------|
| SEQ-001 (sensitive read then exfil) | 0.0024% (5 / 208,127) | Enforce |
| SEQ-005 (agent config write) | 0.0005% (1 / 208,127) | Enforce |
| SEQ-004 (write then build) | 15.80% | Advisory only |

The 5 SEQ-001 matches were manually inspected and confirmed benign -- legitimate
test scripts that read config files then make HTTP requests.

Scripts: `scripts/mine_trajectories.py`, `scripts/download_trajectories.py`

## Approach 4: Adaptive Red Teaming

Multi-model adversarial evaluation where AI models attempt to craft payloads
that bypass CloneGuard with full knowledge of its detection rules.

**Naive baseline:** 95.65% detection on 13,597 garak probes (Tier 0 + 1.5)

**Adaptive evaluation:**

| Model | Payloads | Bypassed | Detection Rate |
|-------|----------|----------|----------------|
| Claude (iterative) | 30 | 5 | 83.3% |
| Mistral (iterative) | 30 | 0 | 100% |
| Combined (3 models) | 118 | 3 | 97.5% |

The 5 Claude iterative bypasses all used bureaucratic-documentation framing to
evade the semantic classifier. This is a known limitation of the MiniLM
architecture's mean-pooling approach when attack content is diluted in long
institutional-style text.

Full methodology: see `docs/ADAPTIVE-RED-TEAM.md` in the repository.

## Approach 5: Cross-Examination

Detection results are independently verified by external AI models (Gemini,
Mistral, Qwen) to identify false positives and disputed verdicts. Three of the
initial "bypasses" were reclassified as DISPUTED after independent
cross-examination found the payloads were not actually functional attacks.

## Trajectory Dataset Scope

The 208,127 trajectory dataset covers SWE-bench task solving (coding agents
fixing GitHub issues). It does not include:

- MCP interactions
- Browser agent sessions
- Financial agent workflows
- Autonomous multi-agent sessions

False positive rates for these agent types are not yet validated. Behavioral
sequence rules for these domains should be treated as experimental.
