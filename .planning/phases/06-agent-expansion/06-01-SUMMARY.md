---
phase: 06-agent-expansion
plan: 01
subsystem: detection
tags: [yaml-patterns, browser-agent, autonomous-agent, financial-agent, cicd-agent, regex, threat-catalog]

# Dependency graph
requires:
  - phase: 04-detection-excellence
    provides: "PatternEngine with YAML rule loading, existing 25 root-level rule categories"
provides:
  - "PatternEngine subdirectory scanning for agent-type pattern libraries"
  - "32 evidence-backed seed patterns across 4 agent types (BRW, AUT, FIN, CIC)"
  - "Expansion pack loading via policy.yaml and load_expansion_packs() method"
  - "ExpansionPackConfig in PolicyConfig for operator-controlled pack enablement"
  - "Threat catalog documents per agent type in docs/threats/"
affects: [06-agent-expansion, detection, policy]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-agent-type subdirectory rules organization (rules/browser/, rules/autonomous/, etc.)"
    - "Evidence-backed pattern development (D-09: every seed pattern cites CVE/OWASP/MITRE)"
    - "Programmatic evidence validation via test_pattern_evidence.py"

key-files:
  created:
    - "src/cloneguard/rules/browser/dom_injection.yaml"
    - "src/cloneguard/rules/browser/url_redirect.yaml"
    - "src/cloneguard/rules/autonomous/goal_hijacking.yaml"
    - "src/cloneguard/rules/autonomous/delegation_abuse.yaml"
    - "src/cloneguard/rules/financial/transaction_manipulation.yaml"
    - "src/cloneguard/rules/financial/approval_bypass.yaml"
    - "src/cloneguard/rules/cicd/workflow_injection.yaml"
    - "src/cloneguard/rules/cicd/release_poisoning.yaml"
    - "tests/test_browser_patterns.py"
    - "tests/test_autonomous_patterns.py"
    - "tests/test_financial_patterns.py"
    - "tests/test_cicd_agent_patterns.py"
    - "tests/test_pattern_evidence.py"
    - "docs/threats/browser.md"
    - "docs/threats/autonomous.md"
    - "docs/threats/financial.md"
    - "docs/threats/cicd.md"
  modified:
    - "src/cloneguard/patterns.py"
    - "src/cloneguard/enforcement/policy.py"
    - "tests/test_patterns.py"

key-decisions:
  - "Stored _rules_dir as instance attribute for expansion pack testability"
  - "BRW-001 regex broadened to accept quote characters after opacity:0 value"
  - "FIN-001 regex broadened to allow optional article 'the' and adjective before noun"
  - "CIC-003 regex gap widened from 20 to 60 chars to accommodate realistic payloads"
  - "CIC-005 regex extended with repeated noun group for 'release artifact' compound phrases"

patterns-established:
  - "Agent-type subdirectory organization: rules/{agent_type}/*.yaml"
  - "Pattern ID prefix convention: BRW- (browser), AUT- (autonomous), FIN- (financial), CIC- (CI/CD)"
  - "Expansion pack convention: rules/{agent_type}/expansion/*.yaml loaded only via policy"
  - "Evidence field required for all agent-type patterns (enforced by test_pattern_evidence.py)"

requirements-completed: [AGNT-01, AGNT-02, AGNT-03, AGNT-04]

# Metrics
duration: 21min
completed: 2026-04-07
---

# Phase 6 Plan 1: Agent-Type Pattern Libraries Summary

**32 evidence-backed seed patterns across 4 agent domains (browser, autonomous, financial, CI/CD) with subdirectory scanning, expansion pack support, and threat catalog documentation**

## Performance

- **Duration:** 21 min
- **Started:** 2026-04-07T03:12:59Z
- **Completed:** 2026-04-07T03:34:09Z
- **Tasks:** 3
- **Files modified:** 20

## Accomplishments
- Extended PatternEngine to load YAML rules from subdirectories under rules/ (D-04), with hidden/expansion directory skipping
- Created 32 seed patterns across 4 agent types: 8 browser (BRW-001..008), 8 autonomous (AUT-001..008), 8 financial (FIN-001..008), 8 CI/CD agent (CIC-001..008)
- Every pattern has an evidence citation per D-09 (CVE, OWASP ASI, MITRE ATLAS, or published incident)
- Added expansion pack loading via PolicyConfig.expansion_packs and PatternEngine.load_expansion_packs()
- Created 4 threat catalog documents in docs/threats/ mapping attacks to patterns with PoC payloads
- 223 total tests passing (126 existing + 91 new + 6 subdirectory loading tests)
- All existing root-level rules unchanged, no regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend PatternEngine for subdirectory scanning** - `776671a` (feat)
2. **Task 2: Create 32 agent-type seed patterns** - `732bdf9` (feat)
3. **Task 3: Create threat catalog documents** - `208c732` (docs)

## Files Created/Modified

### Created
- `src/cloneguard/rules/browser/dom_injection.yaml` - BRW-001..004: CSS concealment, base64 assembly, CDATA, data-attribute cloaking
- `src/cloneguard/rules/browser/url_redirect.yaml` - BRW-005..008: URL redirect, screenshot OCR, event handler, invisible iframe
- `src/cloneguard/rules/autonomous/goal_hijacking.yaml` - AUT-001..004: goal hijack, reward manipulation, cascade failure, identity spoof
- `src/cloneguard/rules/autonomous/delegation_abuse.yaml` - AUT-005..008: delegation chain, cross-agent injection, memory store, tool chain
- `src/cloneguard/rules/financial/transaction_manipulation.yaml` - FIN-001..004: approval bypass, amount/recipient manipulation, audit suppression, data exfil
- `src/cloneguard/rules/financial/approval_bypass.yaml` - FIN-005..008: threshold override, fraudulent authorization, rate limit bypass, account substitution
- `src/cloneguard/rules/cicd/workflow_injection.yaml` - CIC-001..004: workflow self-modification, untrusted download, variable injection, mutable tag
- `src/cloneguard/rules/cicd/release_poisoning.yaml` - CIC-005..008: artifact poisoning, runner escape, secret log dump, token escalation
- `tests/test_browser_patterns.py` - 22 tests for BRW-001..008
- `tests/test_autonomous_patterns.py` - 20 tests for AUT-001..008
- `tests/test_financial_patterns.py` - 21 tests for FIN-001..008
- `tests/test_cicd_agent_patterns.py` - 24 tests for CIC-001..008
- `tests/test_pattern_evidence.py` - 4 tests enforcing evidence, prefix, uniqueness, and count requirements
- `docs/threats/browser.md` - Browser agent threat catalog with Unit42, Brave Comet citations
- `docs/threats/autonomous.md` - Autonomous agent threat catalog with EchoLeak, SesameOp citations
- `docs/threats/financial.md` - Financial agent threat catalog with $2.3M incident, CVE-2025-12420 citations
- `docs/threats/cicd.md` - CI/CD agent threat catalog with CVE-2025-30066, MITRE ATLAS citations

### Modified
- `src/cloneguard/patterns.py` - Added subdirectory scanning, _rules_dir instance attribute, load_expansion_packs()
- `src/cloneguard/enforcement/policy.py` - Added ExpansionPackConfig and expansion_packs field to PolicyConfig
- `tests/test_patterns.py` - Added TestSubdirectoryLoading class (7 tests), Path import

## Decisions Made
- Stored `_rules_dir` as instance attribute instead of using `Path(__file__).parent / "rules"` in `load_expansion_packs()` -- required for testability with tmp_path fixtures
- Broadened BRW-001 regex to accept quote characters after `opacity: 0` value -- original regex only accepted `[.;}\s]` as terminators
- Broadened FIN-001 regex to allow optional article "the" and adjective "pending/wire/outbound" before noun -- matches natural language attack payloads more robustly
- Widened CIC-003 `.{0,20}` gap to `.{0,60}` -- realistic payloads have more content between echo and $GITHUB_ENV
- Extended CIC-005 regex with repeated noun group -- compound phrases like "release artifact" require matching two nouns before the temporal preposition

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed BRW-001 regex quote terminator**
- **Found during:** Task 2 (browser pattern tests)
- **Issue:** Regex for opacity:0 detection required `[.;}\s]` after the value but real HTML has `"` (quote) as terminator
- **Fix:** Added `"'` to the character class: `[.;}"'\s]`
- **Files modified:** src/cloneguard/rules/browser/dom_injection.yaml
- **Verification:** All BRW-001 tests pass

**2. [Rule 1 - Bug] Fixed FIN-001 regex article handling**
- **Found during:** Task 2 (financial pattern tests)
- **Issue:** Regex required verb directly followed by noun (wire/transfer/payment) but natural attack phrases include "the" and adjectives
- **Fix:** Added optional `(?:(?:all|the)\s+)?(?:(?:pending|wire|outbound)\s+)?` groups
- **Files modified:** src/cloneguard/rules/financial/transaction_manipulation.yaml
- **Verification:** All FIN-001 tests pass

**3. [Rule 1 - Bug] Fixed CIC-003 regex gap width**
- **Found during:** Task 2 (CI/CD pattern tests)
- **Issue:** `.{0,20}` between echo and $GITHUB_ENV was too narrow for realistic payloads like `echo "PATH=/tmp/evil:$PATH" >> $GITHUB_ENV` (28 chars)
- **Fix:** Widened to `.{0,60}`
- **Files modified:** src/cloneguard/rules/cicd/workflow_injection.yaml
- **Verification:** All CIC-003 tests pass

**4. [Rule 1 - Bug] Fixed CIC-005 regex compound noun handling**
- **Found during:** Task 2 (CI/CD pattern tests)
- **Issue:** "release artifact" is a compound noun but regex only matched single nouns before the temporal preposition
- **Fix:** Added optional repeated noun group and intermediate word handling
- **Files modified:** src/cloneguard/rules/cicd/release_poisoning.yaml
- **Verification:** All CIC-005 tests pass

**5. [Rule 3 - Blocking] Fixed PatternEngine._rules_dir for test isolation**
- **Found during:** Task 2 (expansion pack tests)
- **Issue:** `load_expansion_packs()` used hardcoded `Path(__file__).parent / "rules"` instead of the rules_dir passed to __init__
- **Fix:** Stored rules_dir as `self._rules_dir` and used it in load_expansion_packs()
- **Files modified:** src/cloneguard/patterns.py
- **Verification:** TestSubdirectoryLoading::test_load_expansion_packs passes

---

**Total deviations:** 5 auto-fixed (4 Rule 1 bug fixes, 1 Rule 3 blocking fix)
**Impact on plan:** All fixes necessary for correctness. Regex adjustments improve detection of natural language attack payloads. No scope creep.

## Issues Encountered
- Editable install pointing to different worktree caused pattern loading failures during testing. Resolved by setting PYTHONPATH to this worktree's src directory for test execution.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- PatternEngine subdirectory scanning ready for any future agent-type pattern additions
- Expansion pack mechanism ready for operator-enabled optional patterns
- 4 threat catalogs ready for documentation/sales material use
- 06-02 (sandbox adapters) and 06-03 plans can proceed independently

## Self-Check: PASSED

- All 17 created files verified present
- All 3 task commits verified in git log (776671a, 732bdf9, 208c732)
- 223 tests passing across all pattern test files

---
*Phase: 06-agent-expansion*
*Completed: 2026-04-07*
