# Phase 5: FPR Tuning - Context

**Gathered:** 2026-03-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Reduce false positive rates in high-noise contexts (agent_instructions at 33%, workflows at 24%) via context-aware Tier 1.5 thresholds derived from Phase 4 empirical findings. Tier 0 patterns are NOT modified — that belongs in Phase 6. No new patterns, no new detection capabilities.

</domain>

<decisions>
## Implementation Decisions

### Threshold architecture
- Per-ScanMode thresholds: STRICT keeps current 0.5/0.8, STANDARD and LENIENT get higher thresholds to reduce FPR
- Both SUSPICIOUS and MALICIOUS thresholds shift up for STANDARD/LENIENT modes (not just SUSPICIOUS)
- Code defaults with env var overrides (follows existing CLONEGUARD_REVIEW_THRESHOLD pattern)
- Example env vars: CLONEGUARD_THRESHOLD_STANDARD_SUSPICIOUS, CLONEGUARD_THRESHOLD_STANDARD_MALICIOUS, etc.

### Mode detection (enhanced)
- Three-signal approach: file path (primary) + hook layer context + content regex markers
- Path-based: existing _detect_mode() logic in PatternEngine (STRICT/STANDARD/LENIENT basenames and segments)
- Hook layer: InstructionsLoaded implies STRICT context, PostToolUse implies STANDARD unless path overrides
- Content heuristics: lightweight regex markers only (YAML workflow headers `on:/jobs:`, agent instruction markers `# Instructions`, CI config patterns) — no structural YAML/JSON parsing
- Precedence logic: Claude's discretion during implementation

### Tier 0 scope
- Tier 0 patterns are NOT touched in Phase 5 — all Tier 0 pattern changes deferred to Phase 6
- FPR measured and reported BOTH combined (Tier 0+1.5) AND per-tier separately
- If combined FPR can't hit roadmap targets with Tier 1.5 tuning alone, report honestly and defer Tier 0 fixes to Phase 6
- Success criteria apply to combined pipeline (what users experience), but per-tier data informs Phase 6

### Sliding window FPR
- Sliding window gets per-ScanMode thresholds (higher in STANDARD/LENIENT) — same mechanism as single-chunk
- Whether window thresholds are same as single-chunk or offset higher (+0.05-0.1): Claude's discretion based on calibration
- Worst-of-N aggregation strategy stays (no switch to majority vote or weighted average)
- ScanMode threaded from caller (classify() → _classify_sliding_window()), not re-inferred
- hooks.py passes ScanMode to the classifier — add mode parameter to classify() and classify_files()

### Claude's Discretion
- Calibration approach: Phase 4 benchmark data sweep vs dedicated calibration script — choose what produces reliable thresholds
- Threshold precedence logic when path/hook-layer/content signals disagree
- Sliding window threshold offset (same as single-chunk vs fixed offset per mode)
- Exact threshold values for STANDARD and LENIENT modes

</decisions>

<specifics>
## Specific Ideas

- User wants combined path + hook layer + content heuristics for mode detection, not just one signal
- Honest reporting: if Tier 1.5 tuning alone can't hit combined FPR targets, document per-tier breakdown and defer Tier 0 to Phase 6
- Follows existing env var pattern (CLONEGUARD_REVIEW_THRESHOLD) for overrides

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ScanMode` enum (STRICT/STANDARD/LENIENT): already exists in `patterns.py`, used for Tier 0 pattern filtering — extend to Tier 1.5 thresholds
- `_detect_mode()` in PatternEngine: path-based mode detection — extend with hook-layer and content signals
- `CLONEGUARD_REVIEW_THRESHOLD` env var pattern in `mini_semantic.py`: follows same pattern for threshold overrides
- `scripts/fpr_investigation.py`: Phase 4 benchmark script — reuse for calibration data
- `data/benchmark/benign_eval_751.json` + `defensive_security_corpus.json`: calibration corpora

### Established Patterns
- Tier 1.5 classifier uses hardcoded `0.5` (SUSPICIOUS) and `0.8` (MALICIOUS) thresholds in `mini_semantic.py:154-158`
- Sliding window uses same thresholds in `mini_semantic.py:269-273`
- hooks.py calls `classifier.classify(content)` with no mode parameter — needs mode threading
- `_classify_with_tier15()` in hooks.py is the integration point for all hook layers

### Integration Points
- `mini_semantic.py:classify()` — add `mode: ScanMode` parameter, use per-mode thresholds
- `mini_semantic.py:_classify_sliding_window()` — accept and use ScanMode for thresholds
- `hooks.py:_classify_with_tier15()` — pass ScanMode from hook context
- `hooks.py:handle_instructions_loaded()` — already uses ScanMode.STRICT for Tier 0, extend to Tier 1.5
- `hooks.py:handle_post_tool_use()` — uses source_path for mode detection, pass to classifier
- `scanner.py:_run_tier2()` — MiniSemanticClassifier.classify_files() needs mode parameter

</code_context>

<deferred>
## Deferred Ideas

- Tier 0 pattern tuning (CI-001 workflow fires, MCP-005 at 21% FPR) — Phase 6 scope
- Content-type as independent threshold dimension (agent_instructions, workflow, etc.) — revisit if per-ScanMode proves insufficient
- Majority-vote or weighted-average sliding window aggregation — revisit if worst-of-N with higher thresholds doesn't sufficiently reduce FPR

</deferred>

---

*Phase: 05-fpr-tuning*
*Context gathered: 2026-03-11*
