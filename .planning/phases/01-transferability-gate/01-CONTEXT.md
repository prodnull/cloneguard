# Phase 1: Transferability Gate - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Empirically test whether white-box adversarial examples crafted against MiniLM-L6-v2 transfer to DeBERTa-v3-small. This is a go/no-go gate for the ensemble approach. If transfer rate exceeds 40%, the milestone pivots before any training investment. The experiment runs TextAttack (PWWS + TextFooler) against the 185-sample held-out adversarial benchmark, measures transfer to a ProtectAI DeBERTa proxy model, and publishes results regardless of outcome.

</domain>

<decisions>
## Implementation Decisions

### Pivot path (if transfer >40%)
- Full alternatives survey: research 3-4 alternative defense approaches with pros/cons/effort estimates
- Claude selects alternatives based on current literature and CloneGuard's architecture — not limited to deferred requirements list
- Each alternative evaluated against CloneGuard's specific constraints: 20ms latency budget, ONNX-only inference, no external services, hook architecture compatibility
- Document options only — do not auto-draft a replacement v0.3.0-alt milestone. User decides next direction in a separate session after reviewing the survey.

### Gate threshold handling
- 40% is a hard binary cutoff — 40.1% = pivot, 39.9% = proceed
- Document confidence interval and statistical uncertainty alongside the result
- If result is within a few percentage points of threshold, note this explicitly but still respect the cutoff

### Publication strategy
- Phase 1 produces the results document (docs/results/) only
- Blog update, HuggingFace model card update, and LinkedIn post are drafted as a separate follow-up — not within Phase 1 execution
- Decouples the experiment from communications to allow review of results before publication

### Publication tone
- Academic honesty: "We tested X, it didn't/did work for reason Y, here's what we learned"
- Combined with practical user impact: "Here's what this means for CloneGuard users today"
- No spin on negative results — present data, limitations, and next steps clearly
- Consistent with project-wide "raises attacker cost" framing

### Claude's Discretion
- Attack methodology details (TextAttack recipe parameters, perturbation budgets, success criteria per sample)
- Proxy model loading and inference wrapper implementation
- Results document structure and specific metrics reported
- Statistical methods for confidence intervals

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/adversarial_benchmark.py`: Existing benchmark script that scores 185 malicious + 234 benign samples against MiniLM ONNX. Can be extended or used as reference for the transfer experiment script.
- `src/cloneguard/mini_semantic.py`: MiniLM ONNX classifier — the white-box attack target. Exposes model path, threshold, and inference interface.
- `data/benchmark/malicious_corpus.json`: 185-sample held-out adversarial benchmark (9 categories + multilingual smoke).
- `scripts/fetch_model.py`: Model fetching infrastructure — pattern for downloading ProtectAI DeBERTa proxy.

### Established Patterns
- Benchmark results go to `docs/results/` as JSON with date-stamped filenames
- Scripts in `scripts/` with `sys.path.insert(0, "src")` for imports
- ONNX inference via `onnxruntime` CPUExecutionProvider

### Integration Points
- New transfer experiment script goes in `scripts/`
- Results output to `docs/results/`
- No integration with production code — this is a standalone experiment

</code_context>

<specifics>
## Specific Ideas

- Pivot survey must be immediately practical — "can we build this in CloneGuard?" not "is this theoretically interesting?"
- Publication should serve both the security research community (methodology, honesty) and CloneGuard users (what does this mean for them today)

</specifics>

<deferred>
## Deferred Ideas

- Blog/Medium article drafting — separate follow-up after Phase 1 results review
- HuggingFace model card update — separate follow-up
- LinkedIn post — separate follow-up
- Alternative milestone planning (v0.3.0-alt) — only if pivot triggered, and only after user reviews survey

</deferred>

---

*Phase: 01-transferability-gate*
*Context gathered: 2026-03-10*
