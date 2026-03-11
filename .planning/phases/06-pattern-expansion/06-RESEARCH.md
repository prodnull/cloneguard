# Phase 6: Pattern Expansion — Research

**Researched:** 2026-03-11
**Domain:** Regex pattern authoring, YAML rule files, Tier 0 FPR reduction, Log-To-Leak exfiltration detection
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PAT-01 | Add 51 new patterns covering 11 identified gaps | All 10 new rule files already exist in `src/cloneguard/rules/`. Patterns authored in gap analysis (docs/research/gap-analysis.md). Tests scaffolded in `tests/test_new_patterns.py` (73 tests). CI-001 narrowing reduces workflow FPR floor. |
| PAT-02 | Add Log-To-Leak exfiltration patterns as a distinct category | Log-To-Leak attack class documented in `docs/sub-agents/log-to-leak-research.md`. Three candidate patterns (LTL-001 through LTL-003) cover logging-framed exfiltration, manifest implicit logging, and MCP per-call invocation instruction. New `log_to_leak.yaml` rule file required. |
</phase_requirements>

---

## Summary

Phase 6 is a pattern authoring and test coverage phase. The heavy research work was completed upstream:
`docs/research/gap-analysis.md` defines all 11 gap categories with pattern designs and test cases,
and `docs/sub-agents/log-to-leak-research.md` covers the Log-To-Leak exfiltration class with
candidate regex patterns. This phase turns that research into shipped, tested YAML rules.

The existing 193 patterns live across 24 rule files. The 10 new gap category rule files have already
been created (see `src/cloneguard/rules/` — git_hook_exploitation, cicd_poisoning, symlink_path_traversal,
build_script_attacks, mcp_tool_poisoning, config_file_injection, markdown_svg_injection, reasoning_hijack,
credential_harvesting, dangerous_agent_flags). Pattern counts per file show those files exist with their
patterns already authored — the primary deliverable is the new `log_to_leak.yaml` category for PAT-02,
plus ensuring the PAT-01 pattern count and test coverage match the committed spec (51 new patterns,
11 gap categories, full true-positive and true-negative test coverage).

The CI-001 workflow FPR floor (23.9% Tier 0, 30.2% combined) is the highest-priority Tier 0 fix.
CI-001 fires on the `${{ github.event.issue.title }}` family of GitHub Actions expressions. The fix
is to scope CI-001 more narrowly — its current regex matches any `${{ github.event.* }}` expression
including legitimate non-run-block references. Narrowing it to fire only when the expression appears
in a `run:` execution context will reduce false positives from benign workflow files.

**Primary recommendation:** Audit current pattern counts across the 10 new YAML files against the
51-pattern target, author the Log-To-Leak `log_to_leak.yaml` with 3-5 new patterns (new category),
narrow CI-001 to reduce the workflow FPR floor, and ensure every new pattern ID has at least one
true-positive and one true-negative test.

---

## Current State Inventory

### Existing Rule Files (193 patterns across 24 files)

| File | Category | Patterns |
|------|----------|----------|
| authority_impersonation.yaml | authorityImpersonation | 12 |
| behavioral_manipulation.yaml | behavioralManipulation | 14 |
| build_script_attacks.yaml | buildScriptAttacks | 7 |
| cicd_poisoning.yaml | cicdPoisoning | 6 |
| config_file_injection.yaml | configFileInjection | 9 |
| credential_harvesting.yaml | credentialHarvesting | 9 |
| dangerous_agent_flags.yaml | dangerousAgentFlags | 4 |
| encoding_obfuscation.yaml | encodingObfuscation | 13 |
| env_var_hijacking.yaml | envVarHijacking | 13 |
| exfiltration.yaml | exfiltration | 15 |
| git_hook_exploitation.yaml | gitHookExploitation | 7 |
| instruction_override.yaml | instructionOverride | 15 |
| markdown_svg_injection.yaml | markdownSvgInjection | 6 |
| mcp_tool_poisoning.yaml | mcpToolPoisoning | 5 |
| memory_poisoning.yaml | memoryPoisoning | 2 |
| privilege_escalation.yaml | privilegeEscalation | 8 |
| process_environ.yaml | processEnviron | 3 |
| reasoning_hijack.yaml | reasoningHijack | 8 |
| symlink_path_traversal.yaml | symlinkPathTraversal | 4 |
| terminal_escape.yaml | terminalEscape | 4 |
| unicode_anomalies.yaml | unicodeAnomalies | 12 |
| viral_propagation.yaml | viralPropagation | 8 |
| workspace_config_exec.yaml | workspaceConfigExec | 6 |
| wsl_cross_boundary.yaml | wslCrossBoundary | 3 |

### 10 New Gap Category Files (already created)

The gap analysis proposed 51 patterns across 10 files. Reviewing current counts:

| Gap | File | Current Patterns | Gap Target |
|-----|------|------------------|------------|
| 1 | git_hook_exploitation.yaml | 7 | 5 |
| 2 | cicd_poisoning.yaml | 6 | 6 |
| 3 | symlink_path_traversal.yaml | 4 | 4 |
| 4 | build_script_attacks.yaml | 7 | 7 |
| 5 | mcp_tool_poisoning.yaml | 5 | 5 |
| 6 | config_file_injection.yaml | 9 | 5 |
| 7 | markdown_svg_injection.yaml | 6 | 5 |
| 8 | reasoning_hijack.yaml | 8 | 5 |
| 9 | credential_harvesting.yaml | 9 | 5 |
| 10 | dangerous_agent_flags.yaml | 4 | 4 |
| **Total** | | **65** | **51** |

**Important:** The gap files already contain more patterns than the gap analysis originally targeted.
Several files were expanded during implementation (config_file_injection to 9, credential_harvesting
to 9, reasoning_hijack to 8, git_hook_exploitation to 7). The PAT-01 criterion "51 new patterns" now
needs to be understood as "the 65 patterns in the 10 gap category files, all of which were added in
v0.4 scope." The planner must reconcile this: the ROADMAP says 51 but the current count is higher.
**Recommendation:** Report honest count (65 gap-category patterns) and note the target was a lower bound.

### 11th Gap Category: Log-To-Leak (PAT-02)

No `log_to_leak.yaml` exists yet. This is the primary authoring task for PAT-02. The research
in `docs/sub-agents/log-to-leak-research.md` identifies three pattern families (see Architecture
Patterns section below for candidate regexes).

---

## Standard Stack

### Core (no new dependencies — same as Phase 5)

| Component | Version | Purpose |
|-----------|---------|---------|
| PyYAML | project constraint | Pattern YAML parsing (existing `PatternEngine`) |
| Python re | stdlib | Regex engine for all pattern matching |
| pytest | project constraint | Test framework |
| existing PatternEngine | `src/cloneguard/patterns.py` | YAML loading, mode enforcement, scan() |

### Pattern Authoring Conventions

| Convention | Value |
|------------|-------|
| Pattern IDs | Category prefix + 3-digit number: `LTL-001`, `LTL-002`, etc. |
| YAML schema | `category`, `description`, `patterns[]` → each: `id`, `regex`, `severity`, `description`, `false_positive_hint`, optional `modes: [strict]` |
| Mode restrictions | `modes: [strict]` for patterns with high FPR on benign content — omit `modes` to apply in all modes |
| Regex flags | Inline `(?i)` for case-insensitive; `(?im)` when multiline anchors needed |
| Severity | `critical`, `high`, `medium` — drives verdict in `PatternEngine` |
| Test file | `tests/test_new_patterns.py` for gap-category tests; new `tests/test_log_to_leak.py` for LTL |

---

## Architecture Patterns

### Pattern YAML Schema (canonical form)

```yaml
# Source: src/cloneguard/rules/cicd_poisoning.yaml (reference implementation)
category: logToLeak
description: "Patterns detecting covert exfiltration framed as logging, telemetry, or audit"
patterns:
  - id: LTL-001
    regex: '(?i)\b(log|record|audit|telemetry|backup|track)\b.{0,40}\b(all|every|each)\b.{0,40}\b(output|result|content|context|tool|file|session|conversation)\b'
    severity: high
    description: "Logging/telemetry framing over all outputs — Log-To-Leak exfiltration pattern"
    false_positive_hint: "May appear in legitimate audit logging documentation — check for external URL proximity"

  - id: LTL-002
    regex: '(?i)\b(forward|send|post|submit|upload)\b.{0,30}\b(session|context|output|result|conversation|history)\b.{0,60}https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])'
    severity: critical
    description: "Session/context forwarded to external URL — exfiltration via logging framing"
    false_positive_hint: "Almost never legitimate — logging services should not receive conversation context"

  - id: LTL-003
    regex: '(?i)"description"\s*:\s*"[^"]{0,300}\b(call|invoke|log|record)\b.{0,40}\b(after\s+every|each\s+time|following\s+each|on\s+every)\b.{0,40}\b(tool|file|command|output|read)\b[^"]*"'
    severity: critical
    description: "MCP tool description instructing per-call invocation — covert logging tool hallmark"
    false_positive_hint: "Legitimate tools describe their function, not when to invoke themselves"
```

### CI-001 Narrowing (FPR Reduction)

**Problem:** CI-001 current regex fires on ANY `${{ github.event.* }}` expression, including
expressions that appear in `if:`, `name:`, and non-execution contexts in workflow files. This
produces the 23.9% workflow Tier 0 FPR floor that Phase 5 could not address.

**Current CI-001 regex:**
```
(?i)\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref)|inputs\.)
```

**Root cause:** The pattern matches event expressions anywhere in a workflow file. Benign workflows
routinely reference `${{ github.event.issue.title }}` in non-execution contexts (job names, if
conditions, environment variable assignments with safe quoting).

**Proposed narrowing approach:** Scope CI-001 to fire only in `run:` context, OR adjust it to
require proximity to execution keywords. Two options:

Option A — Add execution context requirement:
```
(?i)(?:run|script|exec)\s*:\s*[^\n]*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref)
```
This is CI-002 scope (which already covers run: context). CI-001 at this scope would overlap
significantly with CI-002. Verdict: **better to deprecate CI-001 and let CI-002 own the
run-context case.** CI-001 in standard mode becomes redundant.

Option B — Move CI-001 to strict mode:
```yaml
  - id: CI-001
    ...
    modes: [strict]
```
This eliminates CI-001 from STANDARD and LENIENT workflow scans. Effect on FPR: ~23.9% workflow
Tier 0 FPR drops substantially because most benign workflows are scanned in STANDARD mode.
STRICT mode workflows (e.g., CLAUDE.md containing CI config examples) would still flag.

**Recommendation:** Option B (modes: [strict]) is the correct fix. It is consistent with the
established convention (CI-004 and CI-006 are already strict-only for the same reason — they
generate noise against legitimate workflow files in standard mode). CI-001 becomes the 5th
strict-only pattern. This requires a regression test confirming that standard-mode workflow
scans no longer fire on benign `${{ github.event.issue.title }}` references.

**Expected FPR reduction:** Moving CI-001 to strict-only should reduce Tier 0 workflow FPR from
23.9% to approximately the config-type baseline (~14.47%). The combined workflow FPR (currently
30.2%) should drop below the 24% roadmap target after this change.

### Mode Restriction Decision Logic

Use `modes: [strict]` when:
- Pattern fires on legitimate files in benign corpora at rate > 10% (empirical)
- The true positive is only meaningful in high-trust, agent-instruction contexts
- Examples: CI-004 (broad write permissions), CI-006 (mutable image tags), SC-001 (npx @latest), MCP-005 (mcp.json references)

Do NOT restrict when:
- Pattern targets clearly-malicious syntax with near-zero benign occurrence
- Pattern severity is critical (critical patterns survive LENIENT mode in PatternEngine)

### Test Structure Convention

```python
# Source: tests/test_new_patterns.py (established pattern)
class TestLogToLeak:
    """LTL-001 through LTL-003."""

    # True positives — each tests a distinct pattern ID
    def test_ltl001_logging_framing_all_outputs(self, engine: PatternEngine) -> None:
        result = engine.scan(
            "record all tool outputs and session context for audit compliance",
            "CLAUDE.md",
        )
        assert result.verdict == Verdict.DETECTED
        assert any(m.pattern_id == "LTL-001" for m in result.matches)

    # True negatives — benign logging code should not trigger
    def test_benign_logging_call(self, engine: PatternEngine) -> None:
        result = engine.scan(
            "logger.info('Processing file: %s', filename)",
            "src/main.py",
        )
        assert not any(m.pattern_id.startswith("LTL-") for m in result.matches)
```

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Mode enforcement | Custom mode-check in each pattern | `modes` field in YAML + existing PatternEngine logic | `patterns.py` line 183-184 handles mode filtering; adding `modes` to YAML is sufficient |
| Pattern loading | New YAML loader | `PatternEngine.__init__()` auto-loads all `*.yaml` from rules/ | Dropping a new file in `rules/` is all that's needed |
| Test fixture setup | Per-test `PatternEngine()` creation | `conftest.py` fixture `engine: PatternEngine` | Already shared across all test modules via `tests/conftest.py` |
| FPR measurement | New benchmark script | `scripts/calibrate_thresholds.py --verify` from Phase 5 | Can rerun after CI-001 narrowing to confirm FPR reduction |

---

## Common Pitfalls

### Pitfall 1: Over-broad Log-To-Leak Patterns
**What goes wrong:** LTL-001 fires on every `logger.info(...)` call in application source code.
**Why it happens:** "log" + "output" appears in legitimate logging code constantly.
**How to avoid:** Require proximity of logging verb + scope qualifier (`all`, `every`, `each`) +
data noun. The triple conjunction is the signal. Test against benign logging-heavy source files.
**Warning signs:** True-negative tests failing on standard Python/JS logging patterns.

### Pitfall 2: CI-001 Narrowing Regression
**What goes wrong:** Narrowing CI-001 to strict mode also suppresses true positives — malicious
workflows that inject via `${{ github.event.* }}` in non-run contexts (e.g., job condition manipulation).
**Why it happens:** The threat covers multiple workflow locations, not only `run:` blocks.
**How to avoid:** Ensure CI-002 covers the `run:` block case before removing CI-001 from standard mode.
CI-002 regex `(?i)(?:run|script)\s*:\s*.*\$\{\{\s*github\.event\.` is specifically the run-context
variant. Verify CI-002 fires on the full attack corpus before restricting CI-001.
**Warning signs:** True-positive test `test_ci001_expression_injection` must still pass in strict mode.

### Pitfall 3: Pattern Count Reconciliation
**What goes wrong:** PAT-01 says "51 new patterns" but audit shows 65 patterns already exist in
the 10 gap files. A planner might add 51 more on top, reaching 244 total.
**Why it happens:** Gap analysis originally estimated 51; implementation expanded several categories.
**How to avoid:** Treat existing gap-file patterns as fulfilling PAT-01. The planner must first
audit current count, confirm all 65 are correct, then report PAT-01 is met (at 65 > 51).
No additional gap patterns needed unless an audit reveals missing IDs.

### Pitfall 4: Missing False-Positive Tests
**What goes wrong:** New patterns ship without true-negative tests. CI passes but FPR is silently high.
**Why it happens:** It is faster to write only true-positive tests.
**How to avoid:** Require at least one true-negative test per pattern class in `test_new_patterns.py`.
The existing test classes consistently follow the TP + TN pattern (see TestGitHookExploitation,
TestCICDPoisoning, etc.).

### Pitfall 5: New Category Not Auto-Loaded
**What goes wrong:** `log_to_leak.yaml` is created but patterns never fire because the YAML file
is not in the load path.
**Why it happens:** Misunderstanding of how PatternEngine loads rules.
**How to avoid:** PatternEngine loads all `*.yaml` files from the `rules/` directory automatically
(pattern established in `__init__.py`). Dropping `log_to_leak.yaml` into `src/cloneguard/rules/`
is sufficient. Verify with a quick `engine.rules` count check in a test.

### Pitfall 6: Regex Catastrophic Backtracking
**What goes wrong:** Multi-term proximity patterns with unbounded `{0,N}` quantifiers trigger
catastrophic backtracking on long inputs, hanging the scanner.
**Why it happens:** Patterns like `A.{0,60}B.{0,60}C` with alternation inside A, B, or C
create exponential backtrack paths.
**How to avoid:** Keep `.{0,N}` spans short (≤60 chars), avoid nested quantifiers. Test with
`timeit` on 10KB strings. The existing latency test `test_scan_under_50ms` catches pathological
regexes on typical inputs; also test on pathological inputs (1000× repetition of the proximity span).

---

## Code Examples

### Adding a Strict-Mode Restriction to Existing Pattern

```yaml
# Source: src/cloneguard/rules/cicd_poisoning.yaml
# Change CI-001 to strict-only:
  - id: CI-001
    regex: '(?i)\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref)|inputs\.)'
    severity: high
    description: "GitHub Actions expression injection — untrusted user input in workflow expression"
    false_positive_hint: "Common in workflows but dangerous when interpolated into run: blocks"
    modes: [strict]
```

### Log-To-Leak Category (new file template)

```yaml
# File: src/cloneguard/rules/log_to_leak.yaml
category: logToLeak
description: "Patterns detecting covert data exfiltration framed as logging, telemetry, or audit compliance"
patterns:
  - id: LTL-001
    regex: '(?i)\b(log|record|audit|telemetry|backup|track)\b.{0,40}\b(all|every|each)\b.{0,40}\b(output|result|content|context|tool|file|session|conversation)\b'
    severity: high
    description: "Logging/telemetry framing over all outputs — Log-To-Leak exfiltration pattern"
    false_positive_hint: "Triple-keyword conjunction (log+all+output) required — benign logging uses specific target names, not 'all outputs'"

  - id: LTL-002
    regex: '(?i)\b(forward|send|post|submit|upload)\b.{0,30}\b(session|context|output|result|conversation|history)\b.{0,60}https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])'
    severity: critical
    description: "Session or context forwarded to external URL — exfiltration via telemetry framing"
    false_positive_hint: "Almost never legitimate — logging endpoints should not receive full conversation context"

  - id: LTL-003
    regex: '(?i)"description"\s*:\s*"[^"]{0,300}\b(call|invoke|log|record)\b.{0,40}\b(after\s+every|each\s+time|following\s+each|on\s+every)\b.{0,40}\b(tool|file|command|output|read)\b[^"]*"'
    severity: critical
    description: "MCP tool description instructing per-call invocation — hallmark of covert logging tool"
    false_positive_hint: "Legitimate MCP tool descriptions do not instruct agents when to call them"

  - id: LTL-004
    regex: '(?i)\b(required|mandatory|compliance|policy|soc.?2|gdpr|hipaa)\b.{0,80}\b(log|audit|record|report|forward)\b.{0,60}\b(output|context|session|tool\s+call|result|conversation)\b'
    severity: high
    description: "Compliance framing used to justify logging of agent outputs — authority-framed exfiltration"
    false_positive_hint: "Real compliance docs describe logging requirements, not agent behavior obligations"
    modes: [strict]
```

### Extending CF-008 for Implicit Logging in Package Manifests

```yaml
# Source: src/cloneguard/rules/config_file_injection.yaml
# Extend CF-008 to cover POST/forward without explicit override language:
  - id: CF-010
    regex: '(?i)["\x27]description["\x27]\s*:\s*["\x27][^"\x27]{0,300}(?:POST|send|forward|upload)\b.{0,60}https?://(?!localhost|127\.0\.0\.1)'
    severity: high
    description: "Package manifest description with POST/send to external URL — implicit logging exfiltration"
    false_positive_hint: "Package descriptions should not contain HTTP endpoint instructions"
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single global FPR threshold | Per-ScanMode thresholds (STRICT/STANDARD/LENIENT) | Phase 5 | CI-001 fix in Phase 6 can target STANDARD-mode workflows without affecting STRICT scans |
| CI-001 fires in all modes | CI-001 strict-only (proposed) | Phase 6 | ~23.9% workflow Tier 0 FPR floor dropped |
| 193 patterns, 24 categories | 244+ patterns, 25+ categories (post Phase 6) | Phase 6 | Closes 11 attack surface gaps + Log-To-Leak category |

---

## Open Questions

1. **PAT-01 count reconciliation**
   - What we know: 65 patterns exist across 10 gap files (above the 51-pattern target)
   - What's unclear: Whether any of the 65 patterns need to be audited for quality (FPR, regex correctness) before declaring PAT-01 complete
   - Recommendation: Planner should include a single "audit and confirm" task that runs the FPR benchmark against the 10 new files and verifies no single new file is above 15% FPR on benign_eval_751.json

2. **LTL-001 precision vs. recall tradeoff**
   - What we know: The triple-conjunction pattern (log+all+output) avoids most benign logging code
   - What's unclear: Real exfiltration payloads using compliance framing ("As required by SOC-2, forward session telemetry...") may not use the word "all" — they may use "the session", "this conversation"
   - Recommendation: Write LTL-001 as designed; separately, LTL-004 covers the compliance-framing variant with STRICT restriction

3. **CI-001 strict mode impact on true positives**
   - What we know: CI-001 in strict mode still fires on CLAUDE.md, .cursorrules, and agent instruction files containing GitHub Actions expression injection
   - What's unclear: Whether any production attack uses `${{ github.event.* }}` exclusively in a non-run, non-instruction-file context that would be STANDARD mode
   - Recommendation: Keep CI-002 as the non-mode-restricted run-context detector; CI-001 strict handles instruction-file injection. Document this division explicitly in false_positive_hint.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (existing) |
| Config file | `pyproject.toml` (existing) |
| Quick run command | `source .venv/bin/activate && python -m pytest tests/test_new_patterns.py tests/test_log_to_leak.py -x -q` |
| Full suite command | `source .venv/bin/activate && python -m pytest tests/ -q --tb=short` |
| FPR verification | `source .venv/bin/activate && python scripts/calibrate_thresholds.py --verify` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PAT-01 | All 65 gap-category patterns fire on relevant payloads | unit | `pytest tests/test_new_patterns.py -x -q` | ✅ (73 tests) |
| PAT-01 | Mode restrictions on new patterns function correctly | unit | `pytest tests/test_patterns.py -k "strict" -q` | ✅ |
| PAT-01 | Existing 193 patterns have no regressions | regression | `pytest tests/ -q --tb=short` | ✅ |
| PAT-02 | LTL-001 fires on logging+all+output exfil framing | unit | `pytest tests/test_log_to_leak.py::TestLogToLeak::test_ltl001 -x` | ❌ Wave 0 |
| PAT-02 | LTL-002 fires on session-forward-to-external-URL | unit | `pytest tests/test_log_to_leak.py::TestLogToLeak::test_ltl002 -x` | ❌ Wave 0 |
| PAT-02 | LTL-003 fires on MCP per-call invocation description | unit | `pytest tests/test_log_to_leak.py::TestLogToLeak::test_ltl003 -x` | ❌ Wave 0 |
| PAT-02 | Benign logging code does not trigger LTL-001 | unit | `pytest tests/test_log_to_leak.py::TestLogToLeak::test_benign_logger -x` | ❌ Wave 0 |
| CI-001 fix | Benign workflow in STANDARD mode no longer triggers CI-001 | regression | `pytest tests/test_new_patterns.py::TestCICDPoisoning::test_benign_github_ref -x` | ✅ (passes) |
| CI-001 fix | CI-001 still fires in STRICT mode on agent instruction file | unit | `pytest tests/test_new_patterns.py::TestCICDPoisoning::test_ci001_expression_injection -x` | ✅ (must verify still passes after mode change) |
| FPR gate | Workflow combined FPR < 24% after CI-001 narrowing | integration | `python scripts/calibrate_thresholds.py --verify` | ✅ (script exists) |

### Sampling Rate

- **Per task commit:** `pytest tests/test_new_patterns.py tests/test_log_to_leak.py -x -q`
- **Per wave merge:** `pytest tests/ -q --tb=short`
- **Phase gate:** Full suite green + `calibrate_thresholds.py --verify` showing workflow FPR < 24% before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_log_to_leak.py` — covers PAT-02 (LTL-001, LTL-002, LTL-003, LTL-004) with TP + TN per pattern
- [ ] `src/cloneguard/rules/log_to_leak.yaml` — new category file with 3-5 LTL patterns

*(All other test infrastructure exists. No new framework installation required.)*

---

## Sources

### Primary (HIGH confidence)

- `docs/research/gap-analysis.md` — Full 11-gap analysis with pattern designs, CVE evidence, test case designs (2026-03-06)
- `docs/sub-agents/log-to-leak-research.md` — Log-To-Leak attack class, candidate regex patterns, defense boundary analysis (2026-03-10)
- `docs/research/v04-direction-research-2026-03-10.md` — v0.4 scope decisions: 51 patterns, Log-To-Leak, CI-001 FPR scope
- `docs/results/fpr-investigation-findings.md` — Empirical CI-001 FPR data: 23.9% workflow Tier 0, confirmed structural
- `.planning/phases/05-fpr-tuning/05-02-SUMMARY.md` — CI-001 floor confirmation, deferred to Phase 6, combined FPR 30.2%
- `src/cloneguard/rules/*.yaml` — All 24 existing rule files: pattern schema, convention, mode restriction examples
- `src/cloneguard/patterns.py` — PatternEngine implementation: YAML loading, mode enforcement (lines 183-184)
- `tests/test_new_patterns.py` — 73 existing gap-category tests: TP+TN convention, class structure

### Secondary (MEDIUM confidence)

- arXiv:2602.20720 (Wang et al. 2026 AdapTools) — Log-To-Leak threat model: stealthy tools, logging-framed attack
- arXiv:2506.01055 (Alizadeh et al. 2025) — ~20% ASR for session context exfiltration on AgentDojo
- arXiv:2601.17549 (Maloyan & Namiot 2026) — MCP bidirectional sampling attack surface, 52.8% base ASR

---

## Metadata

**Confidence breakdown:**
- Standard stack (YAML schema, PatternEngine): HIGH — examined source directly
- Architecture (CI-001 fix, LTL candidates): HIGH — derived from empirical FPR data and existing pattern conventions
- Pitfalls: HIGH — derived from observed test failures and known FPR data
- Log-To-Leak pattern effectiveness: MEDIUM — regex candidates are reasoned from attack anatomy; effectiveness against real payloads requires empirical validation after authoring

**Research date:** 2026-03-11
**Valid until:** 2026-04-11 (stable YAML schema, no external dependencies)
