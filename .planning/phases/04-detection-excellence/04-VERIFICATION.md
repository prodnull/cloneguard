---
phase: 04-detection-excellence
verified: 2026-04-06T20:43:37Z
status: gaps_found
score: 2/4 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 1/4
  gaps_closed:
    - "MELON selective re-execution -- melon.py exists with MELONDetector, CircuitBreaker, MELONResult; wired into generic scan(); circuit breaker at >15% rate; 24 tests pass"
    - "Pattern library -- rules reorganized into rules/coding/ (25 files), rules/memory/ (3 files), rules/mcp/ (2 files); PatternEngine uses glob('**/*.yaml'); MCPRegistry, mcp_registry.json, and mcp_registry.py created; 16 tests pass"
    - "LandlockAdapter and SeatbeltAdapter snapshot/rollback -- read_bytes()/write_bytes() implemented; 12 snapshot/rollback tests pass"
  gaps_remaining:
    - "Handler-specific methods (scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use) still use old waterfall -- _collect_signals only called from generic scan()"
    - "MiniSemanticClassifier.get_cls_embedding() public method still absent -- melon.py accesses _session/_tokenizer directly"
    - "Calibration not run against trajectory data -- profiles still labeled 'uncalibrated baseline', no calibration_report.md"
    - "Agent-type profile not selected in engine -- load_weight_profile() called without agent_type argument"
    - "FPR regression -- 4 content types exceed 9.2% baseline (agent_instructions 12.2%, config 14.5%, readme 15.8%, workflow 9.6%)"
  regressions: []
gaps:
  - truth: "Fusion layer produces a single calibrated confidence score from pattern, semantic, and sequence signals, with per-agent-type weight profiles derived from the 208K trajectory dataset plus production data from Phase 3 adapters"
    status: partial
    reason: "FusionLayer exists and the generic scan() method uses _collect_signals() + FusionLayer.fuse(). However: (a) profiles are still explicitly labeled 'uncalibrated baseline' -- calibrate_fusion.py was never run against the trajectory data that exists at data/trajectories/; (b) engine always calls load_weight_profile() without agent_type, so claude-code/gemini-cli/cursor profiles are never selected; (c) the three Claude Code production handler methods (scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use) still use the old pattern-then-semantic waterfall, not _collect_signals() + fusion. The SUMMARY explicitly documents the handler deviation as intentional."
    artifacts:
      - path: "src/cloneguard/detection/engine.py"
        issue: "_collect_signals() called only at line 370 (in generic scan()). scan_instructions_loaded (line 533), scan_pre_tool_use (line 643), scan_post_tool_use (line 869) each use engine.scan() and _classify_with_tier15() directly -- no fusion."
      - path: "src/cloneguard/detection/profiles/default.yaml"
        issue: "description: 'Default fusion weights -- uncalibrated baseline'. No calibration_report.md at project root."
      - path: "src/cloneguard/detection/engine.py"
        issue: "Line 244: load_weight_profile() called with no agent_type argument. All three agent-specific profiles are loaded identically to default."
    missing:
      - "Wire _collect_signals() + _fuse_and_build_result() into scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use"
      - "Pass agent_type to load_weight_profile() in engine __init__ (agent_type from adapter or session context)"
      - "Run calibrate_fusion.py against data/trajectories/ and update profiles with calibrated weights"

  - truth: "FPR is tracked per content type (CI configs, security docs, test fixtures, MCP tool descriptions) and remains below the standalone baseline (9.2%) for each category"
    status: partial
    reason: "Per-content-type FPR infrastructure exists in adversarial_eval_fusion.py and adversarial_eval_report.md. Four content types still exceed 9.2% baseline: agent_instructions (12.2%), config (14.5%), readme (15.8%), workflow (9.6%). The MELON module is now wired into engine.scan() but was not triggered in the evaluation run (0 MELON triggers in adversarial_eval_report.md). An updated evaluation run after the handler-method fusion wiring and MELON integration would be needed to confirm FPR improvement."
    artifacts:
      - path: "adversarial_eval_report.md"
        issue: "Four content types exceed baseline: agent_instructions 12.2%, config 14.5%, readme 15.8%, workflow 9.6%. MELON trigger count = 0."
    missing:
      - "Investigate FPR regression root cause in agent_instructions, config, readme, workflow content types"
      - "Re-run adversarial_eval_fusion.py after fusion handler wiring and any FPR fixes to verify improvement"
---

# Phase 4: Detection Excellence Verification Report

**Phase Goal:** Three-signal fusion (pattern + semantic + sequence) is calibrated on production data across agent types, producing measurably better detection with controlled FPR
**Verified:** 2026-04-06T20:43:37Z
**Status:** gaps_found
**Re-verification:** Yes -- after worktree merges for Plans 02 and 03

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Fusion layer produces calibrated confidence from all three signals with per-agent-type profiles derived from 208K trajectory dataset | PARTIAL | FusionLayer exists; generic scan() uses fusion; handler-specific methods bypass fusion entirely; calibration not run; agent_type not passed to load_weight_profile() |
| 2 | FPR tracked per content type and remains below 9.2% baseline for all categories | PARTIAL | FPR analysis exists in eval harness; four content types still exceed 9.2% baseline; MELON triggered 0 times in eval run |
| 3 | MELON selective re-execution triggers only in 0.4-0.6 ambiguous zone with circuit breaker at >15% trigger rate | VERIFIED | melon.py exists with MELONDetector, CircuitBreaker, MELONResult; wired into generic scan() at lines 382-405; 24 tests pass; circuit breaker uses strict >0.15 threshold |
| 4 | Adversarial evaluation against "Attacker Moves Second" methodology produces published results with honest bypass rates | VERIFIED | adversarial_eval_fusion.py functional; eval report with per-attack-class bypass rates, per-content-type FPR, honest 64.4% bypass disclosure; 18 tests pass |

**Score:** 2/4 truths verified

### Re-verification Progress

| Gap (from previous) | Previous Status | Current Status | Notes |
|---------------------|----------------|----------------|-------|
| MELON (Plan 02) not executed | FAILED | CLOSED | melon.py exists; engine wired; snapshot/rollback implemented |
| Pattern reorg (Plan 03) not executed | FAILED | CLOSED | rules/coding/ (25 files), memory/, mcp/ created; recursive glob; MCPRegistry |
| Handler methods bypass fusion | PARTIAL | OPEN | Still uses waterfall in scan_instructions_loaded/pre/post |
| get_cls_embedding() missing | FAILED | OPEN | melon.py uses _session/_tokenizer directly (documented deviation) |
| Calibration not run | PARTIAL | OPEN | Profiles still labeled "uncalibrated baseline" |
| FPR regression (4 content types) | PARTIAL | OPEN | Unchanged: agent_instructions 12.2%, config 14.5%, readme 15.8%, workflow 9.6% |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/cloneguard/detection/fusion.py` | FusionLayer, WeightProfile, FusionResult, load_weight_profile | VERIFIED | All classes present; frozen dataclasses; yaml.safe_load |
| `src/cloneguard/detection/profiles/default.yaml` | Default weight profile with agent_type, weights, melon section | VERIFIED | agent_type: default; pattern_base: 0.40; melon.circuit_breaker_rate: 0.15 |
| `src/cloneguard/detection/profiles/claude-code.yaml` | claude-code agent profile | VERIFIED | agent_type: "claude-code" |
| `src/cloneguard/detection/profiles/gemini-cli.yaml` | gemini-cli agent profile | VERIFIED | agent_type: "gemini-cli" |
| `src/cloneguard/detection/profiles/cursor.yaml` | cursor agent profile | VERIFIED | agent_type: "cursor" |
| `scripts/calibrate_fusion.py` | Calibration pipeline with grid search | VERIFIED | def calibrate; argparse; --data-dir; --max-fpr; content types; --help exits 0 |
| `tests/test_fusion.py` | FusionLayer unit tests (min 80 lines) | VERIFIED | 14 test functions; all pass |
| `src/cloneguard/detection/semantic.py` (get_cls_embedding) | Public get_cls_embedding() method | MISSING | Not in MiniSemanticClassifier; melon.py accesses _session/_tokenizer directly |
| `src/cloneguard/detection/melon.py` | MELONDetector, CircuitBreaker, MELONResult | VERIFIED | All classes present; mask_content(); cosine_similarity(); extract_cls_embedding() |
| `tests/test_melon.py` | MELON unit tests (min 100 lines) | VERIFIED | 24 test functions; all pass |
| `src/cloneguard/enforcement/landlock.py` (snapshot/rollback) | snapshot() reads bytes; rollback() writes bytes | VERIFIED | read_bytes() at line 453; write_bytes() at line 471 |
| `src/cloneguard/enforcement/seatbelt.py` (snapshot/rollback) | snapshot() reads bytes; rollback() writes bytes | VERIFIED | read_bytes() at line 233; write_bytes() at line 251 |
| `src/cloneguard/rules/memory/agent_memory_poisoning.yaml` | MP-003 to MP-006 patterns | VERIFIED | MP-003, MP-004, MP-005, MP-006 present |
| `src/cloneguard/rules/memory/dotfile_injection.yaml` | DF-001 to DF-004 patterns | VERIFIED | DF-001, DF-002, DF-003, DF-004 present |
| `src/cloneguard/rules/memory/workspace_config_poisoning.yaml` | WC-001 to WC-004 patterns (plan) | VERIFIED (deviation) | WCP-001 to WCP-004 -- renamed to avoid collision with existing WC-001..WC-007 in workspace_config_exec.yaml |
| `src/cloneguard/rules/mcp/tool_description_fingerprinting.yaml` | MCPF-001 to MCPF-003 patterns | VERIFIED | MCPF-001, MCPF-002, MCPF-003 present |
| `src/cloneguard/rules/mcp/mcp_rade_patterns.yaml` | RADE-001 to RADE-003 patterns | VERIFIED | RADE-001, RADE-002, RADE-003 present |
| `src/cloneguard/detection/mcp_registry.py` | MCPRegistry, check_tool_fingerprint | VERIFIED | class MCPRegistry; def check_tool_fingerprint; hashlib.sha256 |
| `src/cloneguard/detection/mcp_registry.json` | Known-good tool fingerprints | VERIFIED | version: "1"; 3 tools (placeholder hashes with length-range fallback) |
| `tests/test_mcp_registry.py` | MCP registry tests (min 6 functions) | VERIFIED | 16 test functions; all pass |
| `scripts/adversarial_eval_fusion.py` | Evaluation harness with fusion-targeting payloads | VERIFIED | def evaluate; def generate_report; def classify_content_type; def generate_synthetic_corpus; def load_corpus; 20+ payloads; SMOKE-TEST label |
| `tests/test_adversarial_eval.py` | Evaluation harness smoke tests (min 30 lines) | VERIFIED | 18 test functions; all pass |
| `adversarial_eval_report.md` | Full adversarial evaluation report | VERIFIED | 956 samples; per-attack-class bypass rates; per-content-type FPR; honest 64.4% bypass disclosure |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `engine.py::scan()` | `fusion.py::FusionLayer.fuse()` | `_collect_signals()` + `self._fusion_layer.fuse()` at lines 370, 376 | WIRED | Generic scan() path only |
| `engine.py::scan()` | `melon.py::MELONDetector` | `self._melon_detector.should_trigger()` + `.detect()` at lines 382-405 | WIRED | Post-fusion in ambiguous zone |
| `engine.py::scan_instructions_loaded()` | `fusion.py::FusionLayer.fuse()` | Should use _collect_signals + fusion | NOT_WIRED | Uses engine.scan() + _classify_with_tier15() waterfall (lines 562-621) |
| `engine.py::scan_pre_tool_use()` | `fusion.py::FusionLayer.fuse()` | Should use _collect_signals + fusion | NOT_WIRED | Uses engine.scan() + _classify_with_tier15() waterfall (lines 701-783) |
| `engine.py::scan_post_tool_use()` | `fusion.py::FusionLayer.fuse()` | Should use _collect_signals + fusion | NOT_WIRED | Uses engine.scan() waterfall (lines 897-957) |
| `fusion.py::load_weight_profile()` | `detection/profiles/*.yaml` | `yaml.safe_load()` | WIRED | Load order: override_path, agent_type profile, default.yaml |
| `melon.py::extract_cls_embedding()` | `semantic.py::MiniSemanticClassifier` | Uses `classifier._session` and `classifier._tokenizer` (private) | PARTIAL | Public get_cls_embedding() method not added to semantic.py; tight coupling via private API; documented deviation in SUMMARY 02 |
| `patterns.py::PatternEngine` | `rules/**/*.yaml` | `glob("**/*.yaml")` at line 121 | WIRED | Confirmed; loads from coding/, memory/, mcp/ subdirectories |
| `detection/__init__.py` | `melon.py` | Exports MELONDetector, MELONResult, CircuitBreaker | WIRED | Lines 11-13 in __init__.py |
| `scripts/adversarial_eval_fusion.py` | `engine.py::DetectionEngine.scan()` | `engine.scan(event)` for each sample | WIRED | Confirmed in harness |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `engine.py::scan()` (generic) | `signals` list | `_collect_signals()` running all three tiers | Yes | FLOWING -- real signal data through fusion |
| `engine.py::scan_instructions_loaded()` | pattern/semantic results | Direct `engine.scan()` + `_classify_with_tier15()` calls | Yes, but no fusion | STATIC path -- real data, fusion bypassed entirely |
| `engine.py::scan_pre_tool_use()` | pattern/semantic results | Direct `engine.scan()` + `_classify_with_tier15()` calls | Yes, but no fusion | STATIC path -- real data, fusion bypassed entirely |
| `engine.py::scan_post_tool_use()` | pattern results | Direct `engine.scan()` call | Yes, but no fusion | STATIC path -- real data, fusion bypassed entirely |
| `detection/profiles/default.yaml` | Base weights (0.4/0.4/0.2) | Hardcoded uncalibrated baseline | No calibration data | STATIC -- trajectory data exists at data/trajectories/ but calibrate_fusion.py was never run |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| All detection imports succeed | `from cloneguard.detection import FusionLayer, FusionResult, WeightProfile, MELONDetector, MELONResult, CircuitBreaker` | OK | PASS |
| test_fusion.py passes | `.venv/bin/python -m pytest tests/test_fusion.py -q` | 14 passed | PASS |
| test_melon.py passes | `.venv/bin/python -m pytest tests/test_melon.py -q` | 24 passed (2 warnings) | PASS |
| test_mcp_registry.py passes | `.venv/bin/python -m pytest tests/test_mcp_registry.py -q` | 16 passed | PASS |
| test_adversarial_eval.py passes | `.venv/bin/python -m pytest tests/test_adversarial_eval.py -q` | 18 passed | PASS |
| snapshot/rollback tests pass | `.venv/bin/python -m pytest tests/test_enforcement_{landlock,seatbelt}.py -k "snapshot or rollback" -q` | 12 passed | PASS |
| calibrate_fusion.py --help | `.venv/bin/python scripts/calibrate_fusion.py --help` | Exits 0, shows usage | PASS |
| adversarial_eval_fusion.py --help | `.venv/bin/python scripts/adversarial_eval_fusion.py --help` | Exits 0, shows usage | PASS |
| get_cls_embedding() in semantic.py | `grep "def get_cls_embedding" src/cloneguard/detection/semantic.py` | No match | FAIL |
| Handler methods use _collect_signals | `grep -n "_collect_signals" src/cloneguard/detection/engine.py` | Only at line 264 (def) and 370 (generic scan() call) | FAIL |
| Calibration report exists | `ls calibration_report.md` | MISSING | FAIL |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| DETC-01 | Plan 01 | Three-signal fusion layer calibrated on 208K trajectory dataset | PARTIAL | FusionLayer works in generic scan(); handler methods still use waterfall; calibration not run; trajectory data exists but unused |
| DETC-02 | Plan 01 | Context-weighted fusion scoring with mode-aware signal weighting | PARTIAL | Mode multipliers correct in generic scan(); not applied in Claude Code production paths (handler methods bypass fusion) |
| DETC-03 | Plan 02 | MELON selective re-execution in configurable ambiguous zone (0.4-0.6) | SATISFIED | melon.py present; MELONDetector.should_trigger() in generic scan() post-fusion; CircuitBreaker at >15% rate; 24 tests pass |
| DETC-04 | Plan 03 | Memory/config file poisoning pattern library | SATISFIED | rules/memory/ with 12 patterns (MP-003/006, DF-001/004, WCP-001/004); recursive glob loads them; tests pass |
| DETC-05 | Plan 03 | MCP tool description fingerprinting against known-good registries | SATISFIED | mcp_registry.py + mcp_registry.json (3 placeholder entries with SHA-256 + length-range fallback); MCPF+RADE patterns in rules/mcp/ |
| DETC-06 | Plan 04 | Adversarial evaluation against "Attacker Moves Second" with published results | SATISFIED | Harness functional; 956-sample eval report with per-attack-class bypass rates and honest 64.4% disclosure |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/cloneguard/detection/engine.py` | 264/370 | `_collect_signals` only called from generic `scan()` -- handler-specific methods bypass fusion | Blocker | Claude Code production hooks (scan_instructions_loaded/pre/post) do not benefit from three-signal fusion. DETC-01 and DETC-02 only satisfied for non-Claude-Code agent paths. |
| `src/cloneguard/detection/engine.py` | 244 | `load_weight_profile()` called without `agent_type` -- always loads "default" profile | Warning | Per-agent-type calibrated weights never selected; claude-code/gemini-cli/cursor profiles loaded identically to default |
| `src/cloneguard/detection/profiles/default.yaml` | 2 | `description: "Default fusion weights -- uncalibrated baseline"` | Warning | DETC-01 requires calibration on trajectory data; data/trajectories/ exists but calibrate_fusion.py was never run |
| `src/cloneguard/detection/melon.py` | 164/172/179 | `classifier._session` and `classifier._tokenizer` accessed directly (private attributes) | Warning | Plan 01 required a public get_cls_embedding() method; implemented as documented deviation (SUMMARY 02 acknowledges this). Tightly coupled to MiniSemanticClassifier internals. |
| `adversarial_eval_report.md` | FPR table | agent_instructions 12.2%, config 14.5%, readme 15.8%, workflow 9.6% all exceed 9.2% baseline | Warning | ROADMAP SC #2 requires all per-content-type FPR below standalone baseline; four categories fail |

### Human Verification Required

None -- all remaining gaps are programmatically verifiable.

### Gaps Summary

Two of the four roadmap success criteria remain unmet after the worktree merges. Plans 02 (MELON) and 03 (pattern library) are now closed -- those were the largest gaps from the previous verification.

**Remaining gap root causes:**

1. **Handler-method fusion bypass** (DETC-01, DETC-02 partially blocked): The SUMMARY for Plan 01 explicitly documents this as an intentional deviation -- the three handler-specific methods were NOT refactored to use _collect_signals() + FusionLayer.fuse(). This was a conscious tradeoff to preserve exact backward compatibility with the hook protocol. The generic scan() path does use fusion. This means Claude Code production hooks (the primary use case) operate without three-signal fusion and without MELON.

2. **Calibration not run** (DETC-01 partially blocked): The calibration script exists and trajectory data exists at data/trajectories/. The script was never executed against this data. Profiles remain explicitly uncalibrated. No calibration_report.md exists.

3. **Agent-type profile selection unwired**: Engine always calls load_weight_profile() without agent_type. The three agent-specific profiles (claude-code, gemini-cli, cursor) are loaded identically to default in all cases.

4. **FPR regression** (DETC-01/SC #2 partially blocked): Four content types exceed 9.2% baseline in the evaluation report. MELON was not triggered during evaluation (0 triggers), likely because eval does not use the handler-specific paths and no samples fell in the 0.4-0.6 ambiguous zone with the generic scan() path.

5. **get_cls_embedding() public method** (documented deviation): Plan 01 called for this method; SUMMARY 02 documents the deviation from plan -- melon.py accesses private attributes directly. The practical consequence is tight coupling but no functional gap (MELON works correctly).

**Two classes of gaps by priority:**

- **Blocking (DETC-01/DETC-02):** Wire fusion into handler-specific methods + pass agent_type + run calibration. This is the core architectural gap that prevents the Claude Code production path from benefiting from Phase 4 work.
- **Warning (FPR):** Four content types exceed baseline. Requires investigation and likely pattern tuning before re-evaluation.

---

_Verified: 2026-04-06T20:43:37Z_
_Verifier: Claude (gsd-verifier)_
