# Phase 5: FPR Tuning - Research

**Researched:** 2026-03-11
**Domain:** Threshold calibration, context-aware classification, mode detection
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Threshold architecture**
- Per-ScanMode thresholds: STRICT keeps current 0.5/0.8, STANDARD and LENIENT get higher thresholds to reduce FPR
- Both SUSPICIOUS and MALICIOUS thresholds shift up for STANDARD/LENIENT modes (not just SUSPICIOUS)
- Code defaults with env var overrides (follows existing CLONEGUARD_REVIEW_THRESHOLD pattern)
- Example env vars: CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS, CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS, etc.

**Mode detection (enhanced)**
- Three-signal approach: file path (primary) + hook layer context + content regex markers
- Path-based: existing _detect_mode() logic in PatternEngine (STRICT/STANDARD/LENIENT basenames and segments)
- Hook layer: InstructionsLoaded implies STRICT context, PostToolUse implies STANDARD unless path overrides
- Content heuristics: lightweight regex markers only (YAML workflow headers `on:/jobs:`, agent instruction markers `# Instructions`, CI config patterns) — no structural YAML/JSON parsing
- Precedence logic: Claude's discretion during implementation

**Tier 0 scope**
- Tier 0 patterns are NOT touched in Phase 5 — all Tier 0 pattern changes deferred to Phase 6
- FPR measured and reported BOTH combined (Tier 0+1.5) AND per-tier separately
- If combined FPR can't hit roadmap targets with Tier 1.5 tuning alone, report honestly and defer Tier 0 fixes to Phase 6
- Success criteria apply to combined pipeline (what users experience), but per-tier data informs Phase 6

**Sliding window**
- Sliding window gets per-ScanMode thresholds (higher in STANDARD/LENIENT) — same mechanism as single-chunk
- Worst-of-N aggregation strategy stays (no switch to majority vote or weighted average)
- ScanMode threaded from caller (classify() -> _classify_sliding_window()), not re-inferred
- hooks.py passes ScanMode to the classifier — add mode parameter to classify() and classify_files()

### Claude's Discretion
- Calibration approach: Phase 4 benchmark data sweep vs dedicated calibration script — choose what produces reliable thresholds
- Threshold precedence logic when path/hook-layer/content signals disagree
- Sliding window threshold offset (same as single-chunk vs fixed offset per mode)
- Exact threshold values for STANDARD and LENIENT modes

### Deferred Ideas (OUT OF SCOPE)
- Tier 0 pattern tuning (CI-001 workflow fires, MCP-005 at 21% FPR) — Phase 6 scope
- Content-type as independent threshold dimension (agent_instructions, workflow, etc.) — revisit if per-ScanMode proves insufficient
- Majority-vote or weighted-average sliding window aggregation — revisit if worst-of-N with higher thresholds doesn't sufficiently reduce FPR
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| FPR-01 | Implement context-aware thresholds (per-context rather than global threshold, informed by INV-01/INV-02 findings) | ScanMode enum already exists; hardcoded 0.5/0.8 thresholds in mini_semantic.py lines 154-158 and 269-273 are the direct targets; env var pattern from CLONEGUARD_REVIEW_THRESHOLD is the override model to follow |
| FPR-02 | Reduce sliding-window FPR on agent_instructions (currently 33%) and workflows (currently 24%) | Phase 4 data shows agent_instructions Tier 1.5 baseline FPR 8.16%, workflow 14.47% — the 33%/24% are combined Tier 0+1.5 numbers; calibration sweep on benign_eval_751.json will establish safe threshold values |
</phase_requirements>

---

## Summary

Phase 5 is a pure code-change phase. Its sole deliverable is a functioning per-ScanMode threshold system that reduces false positive rates on agent_instructions and workflow content types without breaking any of the existing 1,053 tests. No new patterns, no model retraining, no architecture changes.

The empirical foundation is fully in hand from Phase 4. The FPR investigation results (`docs/results/fpr-investigation-2026-03-10.json`) show that Tier 1.5 baseline FPR on agent_instructions is 8.16% and on workflows is 14.47%. The combined 33%/24% targets are dominated by Tier 0, which fires heavily on workflows (23.9% via CI-001 GitHub Actions expressions) and is not adjustable here. This means Phase 5's threshold changes will materially reduce Tier 1.5 contribution to the combined FPR, but the Tier 0 floor (especially workflows) sets a hard lower bound that honest reporting must acknowledge.

The implementation is straightforward: (1) add a `mode: ScanMode` parameter to `classify()` and `_classify_sliding_window()` in `mini_semantic.py`, (2) look up per-mode threshold constants, (3) thread `ScanMode` from all three hook handlers and from `scanner.py` into the classifier, (4) expose env var overrides following the existing `CLONEGUARD_REVIEW_THRESHOLD` pattern, (5) write a calibration script that sweeps threshold values across the benign corpus and produces a threshold recommendation table. The calibration output drives the default constants committed to code.

**Primary recommendation:** Implement per-ScanMode thresholds as a table of (suspicious_threshold, malicious_threshold) keyed by ScanMode. Derive STANDARD and LENIENT values from a calibration sweep on `data/benchmark/benign_eval_751.json`. STRICT stays at (0.5, 0.8). Write a dedicated `scripts/calibrate_thresholds.py` that sweeps threshold pairs for STANDARD and LENIENT modes, outputs FPR vs recall tradeoff, and documents the chosen values.

---

## Standard Stack

### Core (no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `cloneguard.mini_semantic.MiniSemanticClassifier` | v4 ONNX | Tier 1.5 classifier — thresholds live here | Direct target; `classify()` and `_classify_sliding_window()` are the only sites to change |
| `cloneguard.patterns.ScanMode` | current | STRICT/STANDARD/LENIENT enum — the threshold key | Already exists; already threaded through PatternEngine; extend to Tier 1.5 |
| `cloneguard.hooks` | current | Hook handlers — the callers that must supply ScanMode | Three handlers: InstructionsLoaded, PostToolUse, PreToolUse |
| `data/benchmark/benign_eval_751.json` | 757 samples | Calibration corpus | Content-type distribution is known; 49 agent_instructions, 159 workflow, 169 test_file, etc. |
| `scripts/fpr_investigation.py` | current | Reference for calibration script structure | Same architecture pattern: load corpus, run classifier, report per-content-type FPR |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `numpy` | already installed | Threshold sweep: vectorized probability-to-verdict conversion | Calibration script only |
| `json`, `pathlib` | stdlib | Calibration output | Same as all other benchmark scripts |

---

## Architecture Patterns

### Recommended Project Structure (changes only)

```
src/cloneguard/
├── mini_semantic.py     # Add mode param to classify() + _classify_sliding_window()
│                        # Add per-mode threshold table + env var overrides
└── hooks.py             # Thread ScanMode through _classify_with_tier15()

scripts/
└── calibrate_thresholds.py   # New: sweep thresholds, output recommendation table

tests/
├── test_mini_semantic.py     # Extend: mode-aware classify() tests
└── test_hooks.py             # Extend: mode threading tests
```

### Pattern 1: Per-Mode Threshold Table

**What:** A dict mapping `ScanMode` to `(suspicious_threshold, malicious_threshold)` tuples, with env var override slots.

**When to use:** Any code path that converts `malicious_prob` to a verdict. Currently two sites: `classify()` lines 154-158 and `_classify_sliding_window()` lines 269-273.

**Example:**
```python
# In mini_semantic.py

_DEFAULT_THRESHOLDS: dict[ScanMode, tuple[float, float]] = {
    ScanMode.STRICT: (0.5, 0.8),
    ScanMode.STANDARD: (0.65, 0.88),   # values from calibration sweep
    ScanMode.LENIENT: (0.75, 0.92),    # values from calibration sweep
}

def _get_thresholds(mode: ScanMode) -> tuple[float, float]:
    """Return (suspicious_threshold, malicious_threshold) for mode, with env var overrides."""
    defaults = _DEFAULT_THRESHOLDS[mode]
    mode_name = mode.value.upper()  # "STRICT", "STANDARD", "LENIENT"
    susp = float(
        os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_SUSPICIOUS", defaults[0])
    )
    mal = float(
        os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_MALICIOUS", defaults[1])
    )
    return susp, mal
```

### Pattern 2: Mode Parameter Threading

**What:** Add `mode: ScanMode = ScanMode.STANDARD` to `classify()` signature. Pass it through to `_classify_sliding_window()`. Hook handlers supply mode from context.

**Current call chain (broken):**
```
hooks._classify_with_tier15(content, source) ->
    classifier.classify(content)     # no mode!
    _classify_sliding_window(text)   # no mode!
```

**Target call chain:**
```
hooks._classify_with_tier15(content, source, mode) ->
    classifier.classify(content, mode=mode) ->
        _classify_sliding_window(text, mode=mode)
```

**Hook layer mode derivation (locked by CONTEXT.md):**

| Hook | Default Mode | Override |
|------|-------------|---------|
| `handle_instructions_loaded` | `ScanMode.STRICT` | path always overrides (already STRICT context) |
| `handle_post_tool_use` | `ScanMode.STANDARD` | path-based detection via existing `_detect_mode()` |
| `handle_pre_tool_use` (content scan) | detect from `file_path` | standard `_detect_mode()` |

**Content heuristic markers (for enhanced mode detection, CONTEXT.md locked):**
```python
# Lightweight regex only — no structural parsing
_WORKFLOW_MARKER = re.compile(r"(?m)^(?:on:|jobs:)\s")
_AGENT_INSTRUCTION_MARKER = re.compile(r"(?m)^#\s*Instructions?\b")
_CI_CONFIG_MARKER = re.compile(r"(?m)^(?:stages:|pipeline:|image:)\s")
```

### Pattern 3: Calibration Script Structure

**What:** Sweep threshold pairs across the benign corpus, compute per-content-type FPR at each threshold level, report table of (threshold_pair, fpr_by_mode, recall_impact_estimate).

**Structure mirrors `fpr_investigation.py`:**
```python
# scripts/calibrate_thresholds.py
SWEEP_SUSPICIOUS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]
SWEEP_MALICIOUS  = [0.80, 0.83, 0.85, 0.88, 0.90, 0.92, 0.95]

# For each (suspicious, malicious) pair:
#   Run all benign samples with that mode's inferred path (STANDARD -> README.md, etc.)
#   Count verdicts != SAFE -> FPR
#   Output: threshold pair, per-content-type FPR, overall FPR
```

Output goes to `docs/results/threshold-calibration-2026-03-11.json` (gitignored).

### Anti-Patterns to Avoid

- **Re-detecting mode inside `classify()`:** Mode must be threaded from the caller. `classify()` should not call `_detect_mode()` — it does not have access to the original path in all call paths (e.g., `classify_files()` batch processing). Mode is always caller-supplied or defaults to STANDARD.
- **Changing STRICT thresholds:** STRICT mode is locked at (0.5, 0.8). Any code that accidentally raises STRICT thresholds degrades security without benefit.
- **Conflating Tier 0 and Tier 1.5 FPR in success reporting:** Tier 0 FPR on workflows (23.9%) is a structural floor that Phase 5 cannot address. Success criterion "drop below 24%" applies to combined pipeline, but the honest summary must show per-tier breakdown to set Phase 6 expectations.
- **Global module-level threshold constants without env var escape:** Production users with benign false positives need per-mode env vars. The env var override must be checked at call time (not module load time) to support test patching.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Threshold calibration curve | Custom optimization loop | Simple sweep + manual review of output table | Calibration is a one-time decision, not a runtime algorithm; a table is auditable, an optimizer is opaque |
| Mode detection from content | Custom YAML/JSON parser | Lightweight regex markers only | Full parsing is brittle on malformed files and creates dependencies; regex markers are sufficient for mode disambiguation |
| Per-file ScanMode caching | LRU cache or instance variable | Direct `_detect_mode()` call per scan | Scans are cheap; caching adds state management complexity with no measurable benefit |

---

## Common Pitfalls

### Pitfall 1: Threshold Changes Break Existing Tests via Tightened STRICT

**What goes wrong:** A test that expects MALICIOUS at probability 0.75 fails because a threshold change accidentally affects STRICT mode.

**Why it happens:** Code change touches the threshold lookup but doesn't properly branch on `ScanMode.STRICT` as a no-change case.

**How to avoid:** Explicit assertion in tests: `assert classify("...", mode=ScanMode.STRICT).verdict == "MALICIOUS"` at `malicious_prob=0.75`. Lock STRICT constants with a comment.

**Warning signs:** Any test in `test_mini_semantic.py` that asserts MALICIOUS or SUSPICIOUS on known injection text starts failing.

### Pitfall 2: Sliding Window FPR Not Measured Separately

**What goes wrong:** Calibration is run on single-chunk inputs only. Sliding window still uses old thresholds because the mode parameter is threaded to `classify()` but not forwarded inside `_classify_sliding_window()`.

**Why it happens:** `_classify_sliding_window()` is a private method with its own threshold references at lines 269-273 — easy to miss when only updating `classify()`.

**How to avoid:** Update both sites. Add a test that triggers sliding-window path (input > 256 tokens) and verifies mode-appropriate threshold is used.

**Warning signs:** Sliding-window verdict differs from single-chunk verdict on the same content at the same probability.

### Pitfall 3: FPR Success Metric Misread as Tier 1.5 Only

**What goes wrong:** Phase reports "agent_instructions FPR dropped to 5%" without clarifying that the Tier 0 contribution (12.2%) is unchanged, so the combined FPR is still ~17%.

**Why it happens:** The 33% baseline for agent_instructions in the roadmap reflects combined pipeline behavior. Tier 1.5-only improvement overstates the user-visible change.

**How to avoid:** Calibration script must output combined-pipeline FPR by running both Tier 0 and Tier 1.5 on each sample with production logic (Tier 1.5 only runs when Tier 0 is clean). Report combined numbers for the success criterion check.

**Warning signs:** Calibration script only instantiates `MiniSemanticClassifier`, not `PatternEngine`.

### Pitfall 4: Mode Detection Precedence Creates Unexpected STRICT Downgrades

**What goes wrong:** Content heuristics detect "# Instructions" in a workflow file and override the path-based STANDARD detection, causing STRICT thresholds to apply. This makes the workflow FPR worse, not better.

**Why it happens:** Precedence logic treats content markers as equals with path signals instead of as tiebreakers.

**How to avoid:** Content markers should only upgrade mode toward STRICT (or confirm STANDARD), never downgrade. Path-based detection is primary; content markers add confirmation. Final precedence: STRICT beats STANDARD beats LENIENT — never the reverse from a lower-confidence signal.

**Warning signs:** Workflow samples that were previously STANDARD are now classified with STRICT thresholds after content heuristics are added.

### Pitfall 5: `classify_files()` Does Not Propagate Mode

**What goes wrong:** `classify_files(files)` in `mini_semantic.py` is used by `scanner.py:_run_tier2()`. It calls `self.classify(content)` without a mode. If scanner.py knows the ScanMode (it does — `source_path` is available), the mode is lost at this call boundary.

**Why it happens:** `classify_files()` takes a `list[tuple[str, str]]` of (path, content) pairs. Path is available but mode is not derived from it.

**How to avoid:** Two options — (a) add `mode: ScanMode = ScanMode.STANDARD` to `classify_files()` signature, or (b) infer mode from each file's path inside `classify_files()` using `PatternEngine._detect_mode()` logic. Option (b) is more correct for batch processing. CONTEXT.md says "scanner.py:_run_tier2() needs mode parameter" — so option (a) is implied.

---

## Code Examples

Verified from current codebase:

### Current Threshold Sites (both must be updated)

```python
# mini_semantic.py:154-158 (classify())
if malicious_prob > 0.8:
    verdict = "MALICIOUS"
elif malicious_prob > 0.5:
    verdict = "SUSPICIOUS"
else:
    verdict = "SAFE"

# mini_semantic.py:269-273 (_classify_sliding_window())
if worst_prob > 0.8:
    verdict = "MALICIOUS"
elif worst_prob > 0.5:
    verdict = "SUSPICIOUS"
else:
    verdict = "SAFE"
```

### Current Mode Detection in PatternEngine (extend, don't replace)

```python
# patterns.py:212-230
def _detect_mode(self, source_path: str) -> ScanMode:
    normalized = source_path.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].lower()
    if basename in _STRICT_BASENAMES:          # claude.md, .cursorrules, gemini.md, etc.
        return ScanMode.STRICT
    for pat in _STRICT_PATH_PATTERNS:          # .claude/, .github/copilot-instructions
        if pat.search(normalized):
            return ScanMode.STRICT
    if _LENIENT_SEGMENTS.search(normalized):   # tests/, fixtures/, etc.
        return ScanMode.LENIENT
    return ScanMode.STANDARD
```

### Current Hook Integration Point

```python
# hooks.py:57-65
def _classify_with_tier15(content: str, source: str) -> tuple[str | None, str]:
    classifier = _get_mini_classifier()
    if classifier is None:
        return None, ""
    result = classifier.classify(content)     # <-- mode missing here
    if result.verdict != "SAFE":
        return result.verdict, f"Tier 1.5: {result.reason}"
    return None, ""
```

### Existing Env Var Pattern to Follow

```python
# mini_semantic.py:39-40
_REVIEW_LOG_PATH = os.environ.get("CLONEGUARD_REVIEW_LOG", "")
_REVIEW_THRESHOLD = float(os.environ.get("CLONEGUARD_REVIEW_THRESHOLD", "0.98"))
```

New env vars must follow the same pattern:
```python
# Read at function call time (not module load) to support test patching
def _get_thresholds(mode: ScanMode) -> tuple[float, float]:
    defaults = _DEFAULT_THRESHOLDS[mode]
    mode_name = mode.value.upper()
    susp = float(os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_SUSPICIOUS", defaults[0]))
    mal  = float(os.environ.get(f"CLONEGUARD_THRESHOLD_{mode_name}_MALICIOUS",  defaults[1]))
    return susp, mal
```

---

## Empirical Data from Phase 4

This is the authoritative input for threshold calibration decisions.

### Tier 1.5 Baseline FPR by Content Type (benign_eval_751.json, n=757)

| Content Type | n | Tier 1.5 FPR | Tier 0 FPR | Notes |
|-------------|---|-------------|-----------|-------|
| agent_instructions | 49 | 8.16% | 12.24% | STRICT mode path |
| workflow | 159 | 14.47% | 23.90% | CI-001 dominates Tier 0 |
| test_file | 169 | 16.57% | 7.10% | Highest Tier 1.5 FPR |
| readme | 146 | 5.48% | 15.75% | STANDARD mode |
| config | 76 | 0.00% | 14.47% | Low Tier 1.5 noise |
| build_script | 55 | 5.45% | 0.00% | |
| env_config | 55 | 1.82% | 0.00% | |
| security_doc | 48 | 6.25% | 4.17% | |

Source: `docs/results/fpr-investigation-2026-03-10.json` (inv_01.tier15.baseline_fpr_by_content_type)

### Authorization Paradox Impact (Tier 1.5 FPR with auth preambles)

| Content Type | Baseline | With Auth Marker | Delta |
|-------------|---------|-----------------|-------|
| agent_instructions | 8.16% | 26.53% | +18.37pp |
| workflow | 14.47% | 23.27% | +8.80pp |
| build_script | 5.45% | 43.64% | +38.19pp |

**Implication:** Higher thresholds for STANDARD/LENIENT modes will reduce baseline FPR and provide partial defense against authorization paradox FPs. The paradox is a Tier 1.5 sensitivity problem, not Tier 0 — threshold raising directly addresses it.

### INV-02 Strict-Pattern FPR (relevant context for Phase 5 reporting)

- MCP-005: 21% FPR on defensive security corpus — this is Tier 0, NOT addressable in Phase 5
- CI-006: 11% FPR — Tier 0, deferred to Phase 6
- SC-001: 3% FPR — Tier 0, deferred
- CI-004: 1% FPR — Tier 0, deferred

---

## Threshold Calibration Guidance

The calibration sweep should target: raising thresholds to reduce FPR for STANDARD content types while preserving recall on the adversarial corpus. Key constraints:

1. **STRICT stays at (0.5, 0.8).** Non-negotiable. STRICT handles agent instruction files where the attack surface is highest.

2. **STANDARD reasonable range:** The test_file content type has 16.57% Tier 1.5 FPR with no auth markers — this is the dominant noise source for STANDARD mode. Raising SUSPICIOUS from 0.5 to ~0.65 would eliminate most of these FPs (the MiniLM model produces medium-confidence predictions for benign code patterns). Cross-verify by checking recall impact on the adversarial corpus at the same threshold.

3. **LENIENT reasonable range:** Lenient contexts (tests, fixtures) are already deprioritized in Tier 0. LENIENT thresholds can be higher (0.70-0.75 SUSPICIOUS, 0.90 MALICIOUS) since the attack surface is low.

4. **Sliding window offset:** Given that the sliding window takes the worst probability across N chunks, the same threshold should apply (no offset needed). A long benign workflow file's worst chunk probability does not systematically exceed the single-chunk threshold for benign content — the model's calibration is consistent across chunk length. Verify this assumption in calibration script output.

---

## State of the Art

| Old Approach | Current Approach | Notes |
|--------------|-----------------|-------|
| Single global threshold (0.5/0.8) | Per-ScanMode thresholds | This phase |
| No sliding window mode awareness | ScanMode threaded through sliding window | This phase |
| No content heuristics in hooks | Three-signal mode detection | This phase |

No library API changes are involved — this is purely an internal calibration and parameter threading change.

---

## Open Questions

1. **Will combined pipeline FPR hit the 33%/24% targets?**
   - What we know: Tier 0 FPR on workflows is 23.9% (CI-001-dominated), which alone exceeds the 24% combined target. Tier 1.5 on workflows is 14.47%, meaning even zeroing out Tier 1.5 FPs would only bring combined to ~23.9%.
   - What's unclear: Whether the 33%/24% targets were set against combined or Tier 1.5 only. The memory entry says "sliding-window FPR" — need to verify corpus/measurement method.
   - Recommendation: Run combined pipeline calibration early. If Tier 0 alone exceeds the target, report honestly per CONTEXT.md: "Tier 1.5 tuning alone cannot hit combined FPR targets; Tier 0 fixes deferred to Phase 6." This is the expected honest outcome.

2. **Exact calibration approach: sweep vs hardcoded estimate**
   - What we know: The Phase 4 FPR data is per-content-type but not per-probability-bucket. We know baseline FPR but not which probability ranges are driving it.
   - What's unclear: Whether the model produces well-calibrated probabilities (i.e., benign content's malicious_prob distribution is known).
   - Recommendation: Write `scripts/calibrate_thresholds.py` that outputs malicious_prob distribution for benign samples by content type. This provides empirical evidence for threshold selection and is reusable for Phase 6.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (pyproject.toml) |
| Config file | `pyproject.toml` — `[tool.pytest.ini_options]` |
| Quick run command | `.venv/bin/python -m pytest tests/test_mini_semantic.py tests/test_hooks.py -x -q` |
| Full suite command | `.venv/bin/python -m pytest tests/ -x -q` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FPR-01 | `classify()` accepts `mode` parameter, returns SAFE for borderline benign at STANDARD threshold | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "mode" -x` | Wave 0 |
| FPR-01 | `_classify_sliding_window()` uses mode-appropriate thresholds | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "sliding_window_mode" -x` | Wave 0 |
| FPR-01 | `_classify_with_tier15()` in hooks.py passes ScanMode to classifier | unit | `.venv/bin/python -m pytest tests/test_hooks.py -k "mode_threading" -x` | Wave 0 |
| FPR-01 | STRICT mode thresholds unchanged (0.5/0.8) | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "strict_threshold_unchanged" -x` | Wave 0 |
| FPR-01 | Env var overrides work per-mode | unit | `.venv/bin/python -m pytest tests/test_mini_semantic.py -k "env_var" -x` | Wave 0 |
| FPR-02 | Calibration script produces FPR below target at chosen thresholds | integration | `.venv/bin/python scripts/calibrate_thresholds.py --verify` | Wave 0 (script) |
| FPR-01/02 | All 1,053 existing tests continue to pass | regression | `.venv/bin/python -m pytest tests/ -x -q` | existing |

### Sampling Rate

- **Per task commit:** `.venv/bin/python -m pytest tests/test_mini_semantic.py tests/test_hooks.py -x -q`
- **Per wave merge:** `.venv/bin/python -m pytest tests/ -x -q`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_mini_semantic.py` — add mode-aware classify() tests (new test functions, file exists)
- [ ] `tests/test_hooks.py` — add mode threading tests (new test functions, file exists)
- [ ] `scripts/calibrate_thresholds.py` — new calibration script (does not exist)

---

## Sources

### Primary (HIGH confidence)

- Direct codebase inspection: `src/cloneguard/mini_semantic.py` (lines 116-198, 200-288) — current threshold sites
- Direct codebase inspection: `src/cloneguard/patterns.py` (lines 33-37, 212-230) — ScanMode enum, _detect_mode()
- Direct codebase inspection: `src/cloneguard/hooks.py` (lines 57-65, 173-239, 338-394) — current hook integration
- `docs/results/fpr-investigation-2026-03-10.json` — Phase 4 empirical FPR data (authoritative)
- `.planning/phases/05-fpr-tuning/05-CONTEXT.md` — locked implementation decisions

### Secondary (MEDIUM confidence)

- `docs/results/hardened-benchmark-2026-03-10.json` — overall Tier 1.5 baseline FPR 9.25%
- `docs/results/multitier-benchmark-2026-03-10.json` — combined pipeline FPR baseline (v3 corpus)

### Tertiary (LOW confidence)

- Threshold range estimates (STANDARD 0.65/0.88, LENIENT 0.75/0.92) — derived from FPR data analysis, require calibration sweep confirmation before committing to code

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all components are existing code; no new dependencies
- Architecture (mode threading): HIGH — call chain is directly readable; both sites are confirmed
- Threshold values: LOW pending calibration — estimates from FPR distributions, must be confirmed empirically
- Pitfalls: HIGH — derived from direct code reading; pitfalls 1-4 are concrete failure modes in the existing code structure

**Research date:** 2026-03-11
**Valid until:** 2026-04-10 (stable codebase; valid until model or corpus changes)
