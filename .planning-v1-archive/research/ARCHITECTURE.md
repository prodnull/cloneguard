# Architecture Research

**Domain:** Ensemble ML classifier integration into a multi-tier prompt injection detection pipeline
**Researched:** 2026-03-10
**Confidence:** HIGH (codebase read directly; external sources verify ONNX export status and model choices)

## Standard Architecture

### System Overview — Current State (v0.2.3)

```
Agent Event (stdin JSON)
        │
        ▼
┌───────────────────────────────────────┐
│  hooks.py — L1/L2/L3 handlers        │
│  ┌────────────────┐ ┌──────────────┐  │
│  │  PatternEngine │ │ Mini         │  │
│  │  (Tier 0 regex)│ │ Semantic     │  │
│  │  patterns.py   │ │ Classifier   │  │
│  └────────────────┘ │ (Tier 1.5)   │  │
│          │           │ mini_       │  │
│          │           │ semantic.py │  │
│          └───────────┴──────────────┘  │
│       _classify_with_tier15() call     │
│       ONLY when Tier 0 says CLEAN      │
└───────────────────────────────────────┘
        │
        ▼
    exit 0 / 2

Layer 0 (pre-execution repo scan)
        │
        ▼
┌───────────────────────────────────────┐
│  scanner.py — RepoScanner            │
│  ┌────────────┐   ┌────────────────┐  │
│  │ PatternEng │   │ MiniSemantic   │  │
│  │ (Tier 0)   │──▶│ Classifier     │  │
│  └────────────┘   │ (Tier 1.5)     │  │
│                   └────────────────┘  │
│                   ┌────────────────┐  │
│                   │ SemanticClass. │  │
│                   │ Ollama Tier 2  │  │
│                   │ (fallback)     │  │
│                   └────────────────┘  │
└───────────────────────────────────────┘
```

### Current Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| PatternEngine | Tier 0 regex — 193 patterns, 24 categories, mode-restricted | `patterns.py` |
| MiniSemanticClassifier | Tier 1.5 ONNX — MiniLM-L6-v2, sliding window, line scan | `mini_semantic.py` |
| SemanticClassifier | Tier 2 Ollama fallback — qwen2.5:7b | `semantic.py` |
| RepoScanner | Layer 0 orchestration — collects files, runs all tiers | `scanner.py` |
| hook handlers | L1-L3 in-process defense — dispatches Tier 0 then Tier 1.5 | `hooks.py` |
| MCP Gateway | MCP plugin scanning tool output | `mcp_plugin.py` |
| TrustCache | SHA-256 content-hash caching of verified-clean files | `trust_cache.py` |

---

## Ensemble Integration Architecture — v0.3.0 Target

### Q1: Where does the second classifier live?

**Answer: New module `src/cloneguard/ensemble_semantic.py`.**

Do not extend `mini_semantic.py`. The current file is 297 lines and is a self-contained implementation of one specific model (MiniLM-L6-v2 with a specific ONNX path, tokenizer, and sliding window logic). Coupling a second architecture into it creates:

- Two different `MODEL_DIR` paths in one module
- Different tokenizer loading paths (DeBERTa-v3 uses SentencePiece via `use_fast=False`)
- Entangled `available` properties that govern different model files

Instead, create `ensemble_semantic.py` that owns the second classifier in isolation, with the same external interface as `MiniSemanticClassifier`:

```python
# src/cloneguard/ensemble_semantic.py
MODEL_DIR = Path(__file__).parent / "model_ensemble"
ONNX_MODEL = MODEL_DIR / "ensemble_semantic.onnx"

class EnsembleSemanticClassifier:
    """Tier 1.6: Architecturally diverse ONNX classifier (DeBERTa-v3-small)."""
    def __init__(self) -> None: ...
    @property
    def available(self) -> bool: ...
    def classify(self, text: str) -> MiniClassification: ...
    def classify_files(self, files: list[tuple[str, str]]) -> SemanticResult: ...
```

The `MiniClassification` dataclass (verdict/confidence/reason) is already the shared return type — reuse it. The `SemanticResult` / `SemanticFinding` types from `semantic.py` are also reused.

**Rationale:**
- Separation of concerns: each classifier is independently loadable, testable, and degradable
- Different model paths, different SHA-256 hashes in `fetch_model.py`
- Adding a third classifier in future does not require touching either existing file

### Q2: Where does voting logic live?

**Answer: New module `src/cloneguard/ensemble.py`.**

The voting logic is a coordination concern — it is not a scanner orchestration concern (`scanner.py`) nor a hook concern (`hooks.py`). Putting it in either would mix layers.

`ensemble.py` exposes a single entry point used by both callers:

```python
# src/cloneguard/ensemble.py

from dataclasses import dataclass
from cloneguard.mini_semantic import MiniClassification, MiniSemanticClassifier
from cloneguard.ensemble_semantic import EnsembleSemanticClassifier

@dataclass
class VoteResult:
    verdict: str          # "BLOCK" | "WARNING" | "SAFE"
    confidence: float
    reason: str
    tier15_verdict: str   # raw verdict from MiniLM
    tier16_verdict: str   # raw verdict from second classifier
    tier15_available: bool
    tier16_available: bool

class EnsembleClassifier:
    """Parallel vote ensemble: MiniLM (Tier 1.5) + DeBERTa (Tier 1.6)."""

    def __init__(self) -> None:
        self._mini = MiniSemanticClassifier()
        self._ensemble = EnsembleSemanticClassifier()

    def vote(self, text: str, source: str = "") -> VoteResult:
        """Run both classifiers and apply voting policy.

        Policy (parallel vote, option B):
          agree MALICIOUS → BLOCK
          agree SAFE      → SAFE
          disagree        → WARNING (conservative)
          one unavailable → fall through to available tier alone
          both unavailable → SAFE with availability flags set
        """
        ...

    def classify_files(
        self, files: list[tuple[str, str]]
    ) -> tuple[list[VoteResult], float]:
        """Classify file list, return vote results and total scan time ms."""
        ...
```

**Callers that change:**

- `hooks.py`: Replace `_classify_with_tier15(content, source)` with `_classify_with_ensemble(content, source)`. The singleton pattern is already there — add a parallel `_ensemble_classifier` singleton alongside `_mini_classifier`.
- `scanner.py` `_run_tier2()`: Replace `mini.classify_files(file_contents)` with `EnsembleClassifier().classify_files(file_contents)`. Update `report._active_tiers` string.

**What does NOT change in scanner.py:**
- The `_run_tier2()` method signature and call site stay the same
- The `SemanticResult` / `SemanticFinding` processing loop is unchanged — `classify_files` in `ensemble.py` returns the same `SemanticResult` type

### Q3: How should the second model be distributed?

**Answer: Separate HuggingFace repository, fetched by the existing `fetch_model.py` pattern — do not bundle in the wheel.**

The current MiniLM ONNX is ~87 MB. DeBERTa-v3-small ONNX is approximately 165-190 MB (F32, 44M parameters per ProtectAI's published model). Bundling both in the wheel makes `pip install cloneguard[mini]` a 250+ MB download — unacceptable for a security hook tool.

**Distribution pattern:**

- New HF repo: `prodnull/deberta-v3-small-prompt-injection-classifier` (mirror of training methodology)
- New model directory: `src/cloneguard/model_ensemble/` (separate from `src/cloneguard/model/`)
- New fetch script: `scripts/fetch_ensemble_model.py` — identical structure to `fetch_model.py` with a new SHA-256 pin and HF URL
- `pyproject.toml`: add `cloneguard[ensemble]` extra, or extend `cloneguard[mini]` to include both downloads in `post_install`

**Why not the same HF repo:** Separate repos let you version the two models independently. A retrain of DeBERTa does not force a re-download of MiniLM and vice versa.

**Why not ProtectAI's published model:** ProtectAI's `deberta-v3-small-prompt-injection-v2` is publicly available and is trained on a different, undisclosed dataset. Using it as the ensemble partner would mean the second classifier's training data is opaque. CloneGuard's value proposition requires knowing both models were trained on the same 6,340-sample dataset for fair transferability experiments. Train from scratch on `data/training/dataset.jsonl`.

### Q4: Graceful degradation when second model is not installed

**The degradation ladder (four states):**

| State | Tier 1.5 | Tier 1.6 | Behavior |
|-------|----------|----------|----------|
| Full ensemble | available | available | Parallel vote policy applies |
| Mini only | available | unavailable | Fall through to Tier 1.5 verdict alone (current behavior) |
| Ensemble only | unavailable | available | Fall through to Tier 1.6 verdict alone |
| Neither | unavailable | unavailable | Tier 0 only — emit WARNING to stderr, do not fail |

**Implementation in `ensemble.py`:**

```python
def vote(self, text: str, source: str = "") -> VoteResult:
    t15 = self._mini.classify(text) if self._mini.available else None
    t16 = self._ensemble.classify(text) if self._ensemble.available else None

    if t15 is None and t16 is None:
        return VoteResult(verdict="SAFE", confidence=0.0, reason="No semantic tier available",
                          tier15_verdict="unavailable", tier16_verdict="unavailable",
                          tier15_available=False, tier16_available=False)

    if t15 is None:
        # Tier 1.6 alone — treat same as current Tier 1.5 solo behavior
        return _solo_vote(t16, "tier16", tier15_available=False, tier16_available=True)

    if t16 is None:
        # Tier 1.5 alone — identical to current _classify_with_tier15() behavior
        return _solo_vote(t15, "tier15", tier15_available=True, tier16_available=False)

    # Both available — apply voting policy
    return _parallel_vote(t15, t16)
```

**hooks.py change:**

```python
_ensemble_classifier: Any = None
_ensemble_attempted: bool = False

def _get_ensemble() -> Any:
    global _ensemble_classifier, _ensemble_attempted
    if _ensemble_attempted:
        return _ensemble_classifier
    _ensemble_attempted = True
    try:
        from cloneguard.ensemble import EnsembleClassifier
        _ensemble_classifier = EnsembleClassifier()
    except ImportError:
        pass
    return _ensemble_classifier

def _classify_with_ensemble(content: str, source: str) -> tuple[str | None, str]:
    """Replace _classify_with_tier15(). Returns (verdict, reason) or (None, '')."""
    classifier = _get_ensemble()
    if classifier is None:
        return None, ""
    result = classifier.vote(content, source)
    if result.verdict == "SAFE":
        return None, ""
    return result.verdict, result.reason
```

The `_classify_with_tier15()` function in `hooks.py` is replaced entirely. `_get_mini_classifier()` becomes unused and can be removed. One fewer singleton.

**`scanner.py` stderr warning when both unavailable:**

```python
if not self._mini.available and not self._ensemble.available:
    print(
        "WARNING: Semantic ensemble unavailable — scanning with Tier 0 regex only"
        " (31.9% recall). Install cloneguard[mini] for semantic detection.",
        file=sys.stderr,
    )
```

### Q5: Training pipeline — extend or separate script?

**Answer: Separate script `scripts/train_ensemble_model.py`.**

`train_mini_model.py` is 280+ lines and is tightly coupled to MiniLM-L6-v2 (hardcoded `BASE_MODEL`, `hidden_size=384`, `MAX_SEQ_LEN=128`, specific ONNX export path). DeBERTa-v3-small has a different base model name (`microsoft/deberta-v3-small`), a 768-dimensional hidden layer, `MAX_SEQ_LEN=512`, and uses `use_fast=False` for the tokenizer (SentencePiece backend).

The only reusable pieces are:
- `load_dataset(path)` — extract to `scripts/training_utils.py` shared utility
- `evaluate()` — extract to `training_utils.py`
- The ONNX export logic (different output path, but same `torch.onnx.export` structure)

**Shared utility module: `scripts/training_utils.py`**

```python
def load_dataset(path: Path) -> tuple[list[str], list[int]]: ...
def evaluate(model, loader, device) -> tuple[float, float, str, np.ndarray, np.ndarray]: ...
def select_device() -> torch.device: ...
```

Both training scripts import from `training_utils.py`. This avoids duplication without coupling the two model architectures into one file.

**New script structure:**

```
scripts/
├── training_utils.py          # NEW: shared load_dataset, evaluate, select_device
├── train_mini_model.py        # MODIFIED: imports from training_utils
├── train_ensemble_model.py    # NEW: DeBERTa-v3-small, hidden=768, seq=512
├── fetch_model.py             # UNCHANGED
└── fetch_ensemble_model.py    # NEW: mirrors fetch_model.py for second ONNX
```

---

## Recommended Project Structure — After Integration

```
src/cloneguard/
├── __init__.py
├── allowlist.py
├── cli.py
├── devcontainer_scanner.py
├── ensemble.py              # NEW: EnsembleClassifier, VoteResult, voting policy
├── ensemble_semantic.py     # NEW: EnsembleSemanticClassifier (DeBERTa-v3-small ONNX)
├── env_scanner.py
├── hooks.py                 # MODIFIED: replace _classify_with_tier15 with _classify_with_ensemble
├── mcp_plugin.py            # MODIFIED: add ensemble vote call alongside Tier 0
├── mini_semantic.py         # UNCHANGED: MiniLM-L6-v2, stays as-is
├── model/                   # UNCHANGED: MiniLM ONNX + tokenizer files
│   ├── mini_semantic.onnx
│   ├── tokenizer.json
│   └── ...
├── model_ensemble/          # NEW: DeBERTa-v3-small ONNX + tokenizer files
│   ├── ensemble_semantic.onnx
│   ├── tokenizer.json       # SentencePiece-backed (use_fast=False)
│   └── ...
├── patterns.py              # UNCHANGED
├── rules/                   # UNCHANGED
├── scanner.py               # MODIFIED: _run_tier2 uses EnsembleClassifier
├── semantic.py              # UNCHANGED
├── settings_scanner.py      # UNCHANGED
└── trust_cache.py           # UNCHANGED
```

---

## Architectural Patterns

### Pattern 1: Lazy-loaded Singleton Classifiers (existing, extend)

**What:** Module-level globals `_engine`, `_mini_classifier` in `hooks.py` are loaded once per process, guarded by a `_*_attempted` boolean.
**When to use:** Hook handlers are called for every agent event — model load must be amortized over the process lifetime.
**Trade-offs:** Singleton pattern is process-scoped, not thread-safe (acceptable: hooks.py runs single-threaded in the agent process).

**Extension for ensemble:**

```python
_ensemble_classifier: Any = None
_ensemble_attempted: bool = False

def _get_ensemble() -> Any:
    global _ensemble_classifier, _ensemble_attempted
    if _ensemble_attempted:
        return _ensemble_classifier
    _ensemble_attempted = True
    try:
        from cloneguard.ensemble import EnsembleClassifier
        _ensemble_classifier = EnsembleClassifier()
    except ImportError:
        pass
    return _ensemble_classifier
```

### Pattern 2: Parallel Vote with Conservative Disagreement

**What:** Both classifiers run independently on all content. Disagreement defaults to WARNING, not SAFE. This is the correct choice for a security tool: a false warning is recoverable, a false clean is a miss.
**When to use:** When defending against adversarial evasion designed specifically to fool one model.
**Trade-offs:** Higher false-positive rate than either classifier alone on content where one model is miscalibrated for a specific domain. The latency budget (~70-120ms) allows parallel execution in sequence (not concurrency — ONNX sessions are CPU-bound, GIL contention makes threading counterproductive).

**Vote table:**

| Tier 1.5 | Tier 1.6 | Vote | Rationale |
|----------|----------|------|-----------|
| MALICIOUS | MALICIOUS | BLOCK | Both agree |
| MALICIOUS | SUSPICIOUS | BLOCK | At least one high-confidence flag |
| SUSPICIOUS | MALICIOUS | BLOCK | At least one high-confidence flag |
| MALICIOUS | SAFE | WARNING | Disagreement — conservative |
| SAFE | MALICIOUS | WARNING | Disagreement — conservative |
| SUSPICIOUS | SUSPICIOUS | WARNING | Both flag, neither high-confidence |
| SUSPICIOUS | SAFE | WARNING | Any flag → at least WARNING |
| SAFE | SUSPICIOUS | WARNING | Any flag → at least WARNING |
| SAFE | SAFE | SAFE | Both agree clean |

### Pattern 3: Shared Dataclass Interface (`MiniClassification`)

**What:** `EnsembleSemanticClassifier.classify()` returns `MiniClassification` (verdict/confidence/reason) — the same dataclass as `MiniSemanticClassifier.classify()`. This is not duck typing; import the dataclass from `mini_semantic.py`.
**When to use:** Avoids defining a parallel dataclass hierarchy for each new classifier. The vote logic in `ensemble.py` treats both outputs symmetrically.
**Trade-offs:** `EnsembleSemanticClassifier` imports from `mini_semantic.py`. Keep the dependency one-way — `mini_semantic.py` must not import from `ensemble_semantic.py`.

### Pattern 4: Graceful Degradation via `available` Property

**What:** Each classifier class exposes `available: bool` that returns `False` if the ONNX file is missing, `onnxruntime` is not installed, or the model fails to load. Callers check before invoking `classify()`.
**When to use:** All classifiers in CloneGuard — models are optional and must not prevent the tool from running.
**Trade-offs:** A model that loads but produces garbage is not caught by `available`. Add a smoke-test classification in `_try_load()` on a known-benign string to catch corrupt ONNX files at load time.

---

## Data Flow

### Ensemble Vote Flow (hooks.py, per event)

```
Agent stdin JSON
      │
      ▼
Tier 0 PatternEngine.scan(content)
      │
      ├─ DETECTED/SUSPICIOUS → output to stdout, return exit code
      │
      └─ CLEAN
            │
            ▼
      _classify_with_ensemble(content, source)
            │
            ├─ EnsembleClassifier.vote(content)
            │       │
            │       ├─ MiniSemanticClassifier.classify(content)   → t15 result
            │       └─ EnsembleSemanticClassifier.classify(content) → t16 result
            │               │
            │               ▼
            │         _parallel_vote(t15, t16) → VoteResult
            │
            ├─ verdict == BLOCK → print reason, return 2
            ├─ verdict == WARNING → print reason, return 0
            └─ verdict == SAFE → return 0
```

### Ensemble Vote Flow (scanner.py, repo scan)

```
file_contents: list[tuple[str, str]]
      │
      ▼
EnsembleClassifier.classify_files(file_contents)
      │
      ├─ For each (path, content):
      │       vote(content) → VoteResult
      │       if verdict != SAFE → SemanticFinding(verdict, confidence, reason, path)
      │
      └─ SemanticResult(findings, scan_time_ms, model="ensemble-v1")
            │
            ▼
  _run_tier2 existing loop processes SemanticResult.findings
  (no change to ScanReport assembly logic)
```

### Transferability Experiment Flow (new script, pre-training gate)

```
scripts/transferability_experiment.py  (NEW)
      │
      ├─ Load adversarial examples from adversarial_benchmark.py output
      │       (examples crafted to fool MiniLM via FGSM / TextFooler)
      │
      ├─ Run each example through EnsembleSemanticClassifier.classify()
      │
      ├─ Measure recall on adversarial examples (transfer rate)
      │       transfer_rate = 1 - recall_on_adversarials
      │
      └─ Report: if transfer_rate < 0.50 → ensemble is effective
                 if transfer_rate >= 0.50 → architectural similarity risk, flag for review
```

---

## Integration Points

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `ensemble.py` ↔ `mini_semantic.py` | Direct import of `MiniSemanticClassifier`, `MiniClassification` | One-way dependency: ensemble imports mini, not reverse |
| `ensemble.py` ↔ `ensemble_semantic.py` | Direct import of `EnsembleSemanticClassifier` | One-way |
| `ensemble.py` ↔ `semantic.py` | Import `SemanticResult`, `SemanticFinding`, `SemanticVerdict` | Reuses existing shared result types |
| `hooks.py` ↔ `ensemble.py` | Lazy singleton via `_get_ensemble()` | Replaces `_get_mini_classifier()` |
| `scanner.py` ↔ `ensemble.py` | `EnsembleClassifier().classify_files(file_contents)` in `_run_tier2` | Replaces direct `mini.classify_files()` call |
| `mcp_plugin.py` ↔ `ensemble.py` | `EnsembleClassifier().vote(content)` | Currently calls `MiniSemanticClassifier` directly — update call site |

### Build Order (dependency-respecting)

Implement in this order — each phase has no unresolved deps from later phases:

1. **`scripts/training_utils.py`** — shared load/evaluate utilities; no deps on new modules
2. **`scripts/train_ensemble_model.py`** — trains DeBERTa-v3-small, exports ONNX; depends on `training_utils.py`
3. **`scripts/fetch_ensemble_model.py`** — download + SHA-256 verify for the new ONNX; no runtime deps
4. **`src/cloneguard/ensemble_semantic.py`** — new classifier module; depends only on `mini_semantic.MiniClassification` and `semantic.SemanticResult`
5. **`src/cloneguard/ensemble.py`** — voting logic; depends on `mini_semantic.py`, `ensemble_semantic.py`, `semantic.py`
6. **`src/cloneguard/hooks.py`** — replace `_classify_with_tier15` with `_classify_with_ensemble`; depends on `ensemble.py`
7. **`src/cloneguard/scanner.py`** — replace `mini.classify_files()` with `EnsembleClassifier().classify_files()`; depends on `ensemble.py`
8. **`src/cloneguard/mcp_plugin.py`** — update Tier 1.5 call site; depends on `ensemble.py`
9. **`scripts/transferability_experiment.py`** — validation gate; depends on adversarial benchmark data + both classifiers

---

## Anti-Patterns

### Anti-Pattern 1: Putting Voting Logic in scanner.py or hooks.py

**What people do:** Add `if mini.verdict != ensemble.verdict` conditionals directly inside `_run_tier2()` or `_classify_with_tier15()`.
**Why it's wrong:** Both callers need identical vote semantics. Duplicating the vote table across two files creates drift risk. A future change to the disagreement policy requires two edits instead of one.
**Do this instead:** Centralize in `ensemble.py`. Both callers import `EnsembleClassifier.vote()`.

### Anti-Pattern 2: Extending mini_semantic.py to Hold Two Models

**What people do:** Add `self._deberta_session` and `self._deberta_tokenizer` to `MiniSemanticClassifier.__init__()`.
**Why it's wrong:** The `available` property conflates two independent availability conditions. A missing DeBERTa model breaks the `available` check even if MiniLM is healthy. The `classify()` method becomes responsible for routing between two tokenization pipelines.
**Do this instead:** One class per model in its own module. Compose in `ensemble.py`.

### Anti-Pattern 3: Hardcoding Vote Policy as MALICIOUS-only (ignoring SUSPICIOUS)

**What people do:** Only issue BLOCK when both classifiers say MALICIOUS. Treat all SUSPICIOUS verdicts as SAFE.
**Why it's wrong:** SUSPICIOUS verdicts exist precisely because the model has partial signal. Discarding them degrades recall. The adversarial threat model requires that any classifier flag triggers at least a WARNING.
**Do this instead:** Use the vote table in Pattern 2 above. Any non-SAFE verdict from either classifier produces at minimum WARNING.

### Anti-Pattern 4: Running Both Classifiers Concurrently with threading

**What people do:** Use `concurrent.futures.ThreadPoolExecutor` to run MiniLM and DeBERTa in parallel threads.
**Why it's wrong:** Both ONNX sessions use CPUExecutionProvider. They compete for the same CPU cores. Python's GIL means the numpy/ONNX C extension calls do release the GIL, but memory bandwidth contention on the shared L3 cache still increases latency. The total wall-clock time is not improved on a single machine under this workload.
**Do this instead:** Run sequentially. The latency budget (120ms) is achievable: MiniLM ~16ms + DeBERTa-v3-small ~40-60ms estimated on Apple M-series = ~56-76ms, within budget.

### Anti-Pattern 5: Using a Pre-Trained Third-Party Model as Tier 1.6

**What people do:** Use ProtectAI's `deberta-v3-small-prompt-injection-v2` directly as the ensemble partner rather than training from scratch.
**Why it's wrong:** ProtectAI's model was trained on an undisclosed dataset. You cannot run a fair transferability experiment if you don't control both training sets. The adversarial examples crafted against MiniLM may accidentally overlap with ProtectAI's training data, invalidating transferability measurements.
**Do this instead:** Train DeBERTa-v3-small on the same 6,340-sample dataset (`data/training/dataset.jsonl`) so both models have identical training exposure. Use ProtectAI's model only as a secondary validation reference, not as the production Tier 1.6.

---

## Scaling Considerations

| Concern | Per-event hook | Layer 0 repo scan |
|---------|---------------|-------------------|
| Latency budget | ~120ms total; sequential MiniLM + DeBERTa stays ~56-80ms | No per-event constraint; whole-repo scan acceptable at ~2s |
| Model load time | One-time at process start via singleton; ~500ms amortized over session | Instantiated per scan invocation; model load ~500ms first call |
| Memory | MiniLM ~87MB + DeBERTa-v3-small ~165MB ≈ 252MB RSS | Same; acceptable for a developer tool |
| Future third classifier | Add `Tier17Classifier` in its own module; `ensemble.py` vote() extends naturally | Same pattern |

---

## Sources

- Codebase read directly: `src/cloneguard/mini_semantic.py`, `scanner.py`, `hooks.py`, `semantic.py`, `scripts/train_mini_model.py`, `scripts/fetch_model.py` — HIGH confidence
- ProtectAI `deberta-v3-small-prompt-injection-v2` model card (HuggingFace) — DeBERTa-v3-small specs: 44M params, 768 hidden, ONNX available, F1 94.62% on held-out — [https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2) — MEDIUM confidence (their dataset is different from CloneGuard's)
- ModernBERT ONNX export issue and PR merge status — [https://github.com/huggingface/optimum/issues/2177](https://github.com/huggingface/optimum/issues/2177) — HIGH confidence: issue closed, PR merged in optimum v1.24.0
- ModernBERT vs DeBERTaV3 benchmark paper (arxiv 2504.08716, Apr 2025): DeBERTa-v3 superior on classification benchmarks; ModernBERT advantage is long-context and speed — [https://arxiv.org/abs/2504.08716](https://arxiv.org/abs/2504.08716) — MEDIUM confidence (classification domain, not prompt injection specifically)
- Adversarial transferability in ensemble models (arxiv 2303.09105, 2410.06851): architectural diversity reduces but does not eliminate transfer — MEDIUM confidence (vision domain, text transfer dynamics differ)
- ONNX Runtime CPUExecutionProvider inference patterns: [https://inworld.ai/blog/reducing-cpu-usage-in-machine-learning-model-inference-with-onnx-runtime](https://inworld.ai/blog/reducing-cpu-usage-in-machine-learning-model-inference-with-onnx-runtime) — MEDIUM confidence

---
*Architecture research for: CloneGuard ensemble adversarial resilience — v0.3.0*
*Researched: 2026-03-10*
