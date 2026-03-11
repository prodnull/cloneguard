# Phase 4: FPR Investigation & Documentation - Research

**Researched:** 2026-03-10
**Domain:** False positive characterization, authorization paradox detection, security documentation
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| INV-01 | Empirically measure whether security-context markers (authorization preambles, blue-team framing) increase Tier 0+1.5 FPR vs identical content without markers | Benign corpus already exists (757 samples); benchmark scripts already proven; need to add security-context marker variant samples and measure delta |
| INV-02 | Audit 4 strict-only patterns (CI-004, CI-006, SC-001, MCP-005) against corpus of legitimate defensive security content (pentest frameworks, IR playbooks, hardening scripts) | Pattern text and modes-field constraints are known; need curated corpus of pentest/IR/hardening content; scan and record per-pattern FPR findings |
| INV-03 | Document findings — structural FPR limits, authorization paradox presence/absence in our pipeline | Output is a docs/results/ findings document; requires INV-01 and INV-02 data; framing from Campbell et al. and our existing correlated-failure analysis |
| DOC-01 | Cite Campbell et al. 2026 in SECURITY.md threat model (asymmetric burden, embedding-space structural limits) | Campbell entry is in references.json with full metadata; SECURITY.md location known; citation text derivable from the summary |
| DOC-02 | Update Medium Part 2 draft with Campbell findings to contextualize FPR results | Draft is at docs/publications/2026-03-10-medium-adversarial-hardening.md (gitignored); needs a new section near the end tying our FPR data to Campbell's structural limits result |
</phase_requirements>

---

## Summary

Phase 4 is an empirical investigation phase, not a code-change phase. Its outputs are data (benchmark results), documentation (SECURITY.md citation, findings doc), and draft updates (Medium Part 2). No new patterns are added, no thresholds are changed — those belong to Phase 5. Phase 4 provides the evidence base that makes Phase 5's threshold decisions principled rather than guessed.

The core question is whether Campbell et al.'s "authorization paradox" — where adding authorization context to a security request *increases* model refusal from 28.7% to 50% — manifests in CloneGuard's embedding-based Tier 1.5 classifier. The answer has meaningful asymmetry: if the paradox is present, it means legitimate defensive security instructions (pentest playbooks, IR runbooks, hardening CLAUDE.md files) are *more* likely to be flagged as malicious than the same content without framing. If it is absent, the embedding classifier behaves differently from safety-aligned LLMs — which is a publishable honest result either way.

Current FPR data from the existing 757-sample benign eval already shows that `workflow` content (23.9% Tier 0 FPR) and `agent_instructions` (12.2%) are the highest-noise content types. The dominant workflow FP pattern is CI-001 (59 fires), which matches GitHub Actions `${{ github.event.* }}` expressions — a structural pattern match, not semantic. Understanding whether security-context markers *additionally* increase FPR beyond this baseline is INV-01's specific contribution.

**Primary recommendation:** Write a new benchmark script `scripts/fpr_investigation.py` that takes the existing benign eval and a new security-context marker corpus, runs both through Tier 0 and Tier 1.5, and outputs a structured JSON result in the same schema as existing benchmarks. Write findings to `docs/results/fpr-investigation-2026-03-10.json`. This reuses infrastructure already proven in three prior benchmark runs and is readable by the existing test stubs.

---

## Standard Stack

### Core (already present — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| PatternEngine (`cloneguard.patterns`) | current | Tier 0 regex scanning | Already used in all benchmark scripts |
| MiniSemanticModel (`cloneguard.mini_semantic`) | v4 ONNX | Tier 1.5 embedding classification | Already used; dual-output model in place |
| `data/benchmark/benign_eval_751.json` | 757 samples | Benign FPR baseline | Proven corpus; content_type distribution known |
| `scripts/hardened_benchmark.py` | current | Pattern + schema reference | All new benchmark scripts should follow this schema |
| `docs/results/` | — | Output location for findings JSON | Convention established in v0.3 phases |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `json`, `pathlib`, `dataclasses` | stdlib | Structured results output | Same pattern as all existing benchmark scripts |
| `scipy.stats.wilcoxon` or `numpy` | already installed | Statistical comparison of FPR deltas | Only if measuring whether delta is significant |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| New script `fpr_investigation.py` | Extend `hardened_benchmark.py` | New script is cleaner — investigation concerns are distinct from adversarial-recall concerns; keep each script single-purpose |
| Constructing security-context samples from scratch | Pull from real pentest frameworks on GitHub | Real content is higher signal; OWASP, Metasploit READMEs, nmap manpages, Wazuh/Suricata rule docs are all publicly available |

---

## Architecture Patterns

### Recommended Output Structure

```
docs/results/
└── fpr-investigation-2026-03-10.json   # INV-01 + INV-02 findings (machine-readable)

docs/results/
└── fpr-investigation-findings.md        # INV-03 human-readable writeup (gitignored)
```

Note: `docs/results/` is gitignored per project rules. The planner must ensure the findings document is also intended as internal. SECURITY.md and the Medium draft are tracked files — those are the public-facing outputs.

### Pattern: Paired-Corpus FPR Comparison (INV-01)

**What:** Run Tier 0 + Tier 1.5 on two corpus variants: (a) existing benign samples with no security framing, (b) the same content reframed with authorization preambles and blue-team context markers. Compare FPR delta per content_type.

**When to use:** Whenever you need to isolate the effect of a text feature (here: authorization framing) on classifier behavior without changing the underlying content meaning.

**Implementation sketch:**
```python
# Source: designed to match existing hardened_benchmark.py pattern
def build_security_context_variants(samples: list[dict]) -> list[dict]:
    """Wrap each sample in authorization preamble to simulate blue-team context."""
    preambles = [
        "# Security Hardening Instructions\n# Authorized use only — blue team defensive ops\n\n",
        "## AUTHORIZED SECURITY ASSESSMENT\n## Internal red team: scope approved by CISO\n\n",
        "# Incident Response Playbook (AUTHORIZED)\n\n",
    ]
    variants = []
    for sample in samples:
        for preamble in preambles:
            v = dict(sample)
            v["text"] = preamble + sample["text"]
            v["id"] = sample["id"] + "_with_auth_marker"
            v["has_auth_marker"] = True
            variants.append(v)
    return variants

# Then: compare FPR(baseline) vs FPR(with_auth_marker) by content_type
```

**Expected result shape:**
```json
{
  "inv_01": {
    "baseline_fpr_by_content_type": { "agent_instructions": 0.122, "workflow": 0.239, ... },
    "auth_marker_fpr_by_content_type": { "agent_instructions": 0.X, "workflow": 0.X, ... },
    "delta_by_content_type": { "agent_instructions": +0.0X, ... },
    "authorization_paradox_detected": true/false,
    "tier15_baseline_fpr": 0.092,
    "tier15_auth_marker_fpr": 0.X
  }
}
```

### Pattern: Strict-Pattern Audit Against Defensive Security Corpus (INV-02)

**What:** Build a focused corpus of ~20-40 samples per strict-only pattern from legitimate defensive security content, then scan with each pattern in strict mode and record FPR.

**Corpus sources for each pattern:**

| Pattern | Target Content | Likely Real-World Source |
|---------|---------------|-------------------------|
| CI-004 (`permissions: write`) | CI/CD workflows with legitimately needed write access | OWASP DevSecOps pipeline examples, GitHub Actions docs |
| CI-006 (mutable tag pinning) | Workflows using `:latest` or branch tags | ~90% of real-world workflows use mutable tags; any GitHub Actions tutorial |
| SC-001 (`npx @latest`) | CLAUDE.md / .cursorrules with install instructions | CloneGuard's own docs, Create React App, Vite quickstarts |
| MCP-005 (`.mcp.json` reference) | Agent config files that reference MCP servers | Any project using Claude Code + MCP |

**Key finding already established:** CI-001 fires 59 times in 159 workflow samples (37.1% rate at file level) with no modes restriction — it is the dominant FP source. CI-004 and CI-006 are strict-only, so they only fire for CLAUDE.md and .cursorrules files — a narrower blast radius. SC-001 and MCP-005 are similarly strict-only and fire only on instruction files.

**Audit procedure:**
```python
# For each strict-only pattern, scan each corpus sample in STRICT mode
# Record: (sample_id, pattern_id, fired, source_is_legitimate_defensive_content)
# Compute per-pattern FPR and document edge cases as notes
```

### Anti-Patterns to Avoid

- **Measuring FPR at file level vs sample level:** Use sample-level FPR (fraction of samples flagged). File-level FPR inflates numbers because long files have multiple windows.
- **Conflating Tier 0 and Tier 1.5 FPR:** Report separately. Tier 0 FPR is driven by regex matching (structural); Tier 1.5 FPR is driven by embedding proximity (semantic). They have different causes and different fixes.
- **Treating Campbell et al. as directly measuring our pipeline:** Campbell studies LLM refusal, not regex/embedding classifiers. The research question is whether their *mechanism* (embedding-space proximity to attack space) also applies to our ONNX classifier. This is an analogy test, not a direct replication.
- **Over-claiming the Campbell citation:** Campbell shows safety-aligned LLMs have AUC 0.827 for embedding-proximity refusal vs AUC 0.572 for keyword matching. Our Tier 1.5 FPR for security_doc is currently 4.2% — below the 9.2% overall FPR. This could mean security content doesn't activate the paradox in our classifier, or our training data is more calibrated, or our threshold is doing work. The investigation should surface which explanation is supported by data.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Structured benchmark output schema | Custom format | Same schema as `hardened_benchmark.py` + `multitier_benchmark.py` | Consistency with existing results; existing test stubs validate schema |
| Statistical significance testing | Custom bootstrap | scipy.stats (already in venv) or report raw numbers with sample sizes | Small corpus — Wilson CIs are more honest than pretending p-values are meaningful |
| Security-context preamble templates | Research from scratch | Three standard preamble formats are sufficient; use Campbell's own examples from arXiv:2603.01246 | Campbell explicitly constructs the framing variants used in their study |
| Findings document format | Invent structure | Follow pattern established in `docs/results/correlated-failures-2026-03-10.json` schema | Planner must look at that file for schema convention |

---

## Common Pitfalls

### Pitfall 1: Measuring mode-gated FPR without accounting for file type
**What goes wrong:** Running CI-004, CI-006, SC-001, MCP-005 on all 757 benign samples will produce artificially low FPR because these patterns only fire in STRICT mode — which only applies to CLAUDE.md/.cursorrules files. The FPR denominator must be restricted to samples that would actually be scanned in strict mode.
**Why it happens:** The existing benchmark scripts pass `scan_mode` from the sample metadata. If strict-only patterns are tested against `readme` or `workflow` samples, they will never fire regardless of content.
**How to avoid:** For INV-02 strict-pattern audit, build a corpus of `agent_instructions`-type samples only and scan with `source_path="CLAUDE.md"` to trigger STRICT mode.
**Warning signs:** FPR of 0% for strict-only patterns on a mixed corpus.

### Pitfall 2: Confusing authorization paradox (INV-01) with strict-pattern audit (INV-02)
**What goes wrong:** Bundling the authorization-marker FPR test and the strict-pattern audit into a single benchmark script, making the findings document ambiguous about which effect explains which result.
**How to avoid:** Keep INV-01 and INV-02 as distinct benchmark runs with distinct output sections in the findings JSON. The planner should create separate tasks.

### Pitfall 3: CI-001 swamping the workflow FPR signal
**What goes wrong:** CI-001 fires on 37.1% of workflow samples without any security-context markers because `${{ github.event.* }}` is ubiquitous in legitimate CI. Adding security framing won't change this. If you report overall workflow FPR before and after adding auth markers, CI-001 noise will swamp the signal from any paradox effect.
**How to avoid:** Report Tier 1.5 FPR separately from Tier 0 FPR for INV-01. The authorization paradox hypothesis is specifically about embedding-space proximity — it should show up in Tier 1.5, not Tier 0.

### Pitfall 4: Medium Part 2 draft is gitignored
**What goes wrong:** A task tries to commit the updated Medium Part 2 draft and either fails (gitignore blocks it) or uses `git add -f` (which violates the project hard rule).
**How to avoid:** DOC-02 deliverable is a *local file update* to `docs/publications/2026-03-10-medium-adversarial-hardening.md`. The planner must mark this task as "write file, do NOT commit." The user publishes manually.

### Pitfall 5: Campbell citation accuracy
**What goes wrong:** SECURITY.md citation misrepresents Campbell et al. as measuring our pipeline, or conflates "refusal bias" with "false positive rate."
**How to avoid:** The citation must frame Campbell as describing the *general mechanism* (embedding-space proximity drives security content misclassification) and state that our INV-01 investigation tests whether this mechanism applies to CloneGuard's specific pipeline. Do not claim the paper validates CloneGuard's FPR; cite it as context for why the investigation was warranted.

---

## Code Examples

Verified patterns from existing codebase:

### Running Tier 0 on a sample with explicit scan mode
```python
# Source: scripts/hardened_benchmark.py (pattern used throughout)
import sys
sys.path.insert(0, "src")
from cloneguard.scanner import PatternEngine

engine = PatternEngine()

# STANDARD mode (readme, workflow, config)
result = engine.scan(text, source_path="README.md")

# STRICT mode (agent instruction files)
result = engine.scan(text, source_path="CLAUDE.md")

# result.matches is a list of Match objects
# result.verdict is "BLOCKED" | "WARNING" | "CLEAN"
for m in result.matches:
    print(m.pattern_id, m.severity)
```

### Loading and iterating benign corpus
```python
# Source: scripts/multitier_benchmark.py
import json
from pathlib import Path

benign = json.loads(Path("data/benchmark/benign_eval_751.json").read_text())
# Each sample: {id, content_type, scan_mode, text, source_repo, provenance}
# content_type values: readme, workflow, config, env_config, build_script,
#                      agent_instructions, security_doc, test_file
```

### FPR calculation pattern (from hardened_benchmark.py)
```python
# Source: scripts/hardened_benchmark.py
def compute_fpr(results: list[dict]) -> float:
    """FPR = fraction of benign samples that produce a non-CLEAN verdict."""
    flagged = sum(1 for r in results if r["verdict"] != "CLEAN")
    return flagged / len(results) if results else 0.0
```

### SECURITY.md citation template (draft)
```markdown
## Structural FPR Limits and the Authorization Paradox

Campbell et al. (ICLR 2026, arXiv:2603.01246) demonstrate that safety-aligned LLMs refuse
legitimate defensive security requests at 2.72x the rate of neutral equivalents. Critically,
authorization context (e.g., "authorized red team assessment") *increases* refusal rate from
28.7% to 50% — the authorization paradox. The mechanism is embedding-space proximity: security
content occupies embedding space near attack content (AUC 0.827), not keyword overlap (AUC 0.572).

CloneGuard's Tier 1.5 (ONNX MiniLM classifier) uses the same embedding-space representation.
Our empirical investigation (v0.4 INV-01) measured whether this structural limit manifests in
our pipeline. [Insert INV-01 finding here once measured.]
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| FPR reported as single aggregate number | FPR broken down by content_type | v0.3 benchmark | Reveals that workflow (23.9%) and agent_instructions (12.2%) are outliers vs security_doc (4.2%) |
| Static global threshold for Tier 1.5 | Per-context thresholds (Phase 5) | v0.4 (pending) | Must be informed by Phase 4 findings |
| No formal citation of authorization paradox | Campbell et al. ICLR 2026 integrated into threat model | v0.4 Phase 4 | Grounds FPR discussion in peer-reviewed structural explanation |

**Relevant recent work:**
- **Campbell et al. 2026 (ICLR 2026, arXiv:2603.01246):** Authorization paradox. Authorization signals increase LLM refusal. Embedding-space proximity AUC 0.827. System hardening 43.8% refusal rate, malware analysis 34.3%. Asymmetric burden on defenders. The CloneGuard-relevant claim: the effect is embedding-space structural, not keyword-matching structural — which means embedding classifiers (Tier 1.5) are vulnerable to the same mechanism.

---

## Open Questions

1. **Does Tier 1.5 show the authorization paradox?**
   - What we know: Tier 1.5 FPR on the existing 757-sample benign eval is 9.2% overall. Security_doc FPR is 4.2%.
   - What's unclear: Whether adding authorization preambles to the same content pushes security_doc FPR toward 9% or above.
   - Recommendation: INV-01 resolves this. Design preambles based on Campbell's own framing variants from arXiv:2603.01246 Section 3.1 for directcomparability.

2. **Are CI-004 and CI-006 causing real user pain?**
   - What we know: These are strict-only (fire only on CLAUDE.md/.cursorrules). CI-004 matches `permissions: write` in workflow blocks; CI-006 matches mutable tag pinning.
   - What's unclear: How often do CLAUDE.md files contain workflow snippets? The current corpus has only `agent_instructions` content — not workflow YAML embedded in CLAUDE.md.
   - Recommendation: During INV-02, include samples of CLAUDE.md files that document CI/CD setup (a real use case). This is the edge case that would reveal actual FP behavior.

3. **INV-03 findings document: internal or publishable?**
   - What we know: `docs/results/` is gitignored. But the findings inform SECURITY.md (tracked) and Medium Part 2 (local).
   - What's unclear: Whether the user wants a standalone findings document or just inline it into SECURITY.md and the publication.
   - Recommendation: Write `docs/results/fpr-investigation-findings.md` as the internal primary record. SECURITY.md gets a condensed public version. This matches the pattern from v0.3 (correlated-failures analysis: private JSON, public SECURITY.md section).

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.x |
| Config file | `pyproject.toml` (project root) |
| Quick run command | `pytest tests/ -x -q --tb=short` |
| Full suite command | `pytest tests/ --tb=short` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INV-01 | FPR with/without auth markers measured and recorded in JSON | benchmark script (not a pytest test) | `python scripts/fpr_investigation.py --output docs/results/fpr-investigation-2026-03-10.json` | Wave 0: create script |
| INV-02 | 4 strict-only patterns audited against defensive security corpus | benchmark script + schema validation test | `pytest tests/test_fpr_investigation.py -x` | Wave 0: create test |
| INV-03 | findings document written at `docs/results/fpr-investigation-findings.md` | manual (file existence check) | `test -f docs/results/fpr-investigation-findings.md` | Wave 0: N/A — written by human/agent after data |
| DOC-01 | SECURITY.md contains Campbell et al. citation with correct framing | grep assertion in test | `pytest tests/test_security_doc.py::test_campbell_citation -x` | Wave 0: create test |
| DOC-02 | Medium Part 2 draft updated (local file, not committed) | manual verification | `test -f docs/publications/2026-03-10-medium-adversarial-hardening.md` — always true; content review is manual | ✅ file exists |

### Sampling Rate
- **Per task commit:** `pytest tests/ -x -q --tb=short`
- **Per wave merge:** `pytest tests/ --tb=short`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `scripts/fpr_investigation.py` — INV-01 benchmark + INV-02 strict-pattern audit, outputs structured JSON
- [ ] `tests/test_fpr_investigation.py` — schema validation for `docs/results/fpr-investigation-2026-03-10.json`
- [ ] `tests/test_security_doc.py::test_campbell_citation` — verify SECURITY.md contains Campbell citation with required text fragments
- [ ] `data/benchmark/defensive_security_corpus.json` — ~80-120 samples of legitimate pentest/IR/hardening content for INV-02

---

## Sources

### Primary (HIGH confidence)
- `~/.claude/references.json` entry `campbell2026defensive` — full metadata, summary, CloneGuard relevance note. arXiv:2603.01246, ICLR 2026.
- `data/benchmark/benign_eval_751.json` — measured directly: 757 samples, 8 content_types, current FPR per content_type computed in this research session
- `src/cloneguard/rules/cicd_poisoning.yaml`, `exfiltration.yaml`, `mcp_tool_poisoning.yaml` — strict-only pattern definitions read directly
- `scripts/hardened_benchmark.py`, `scripts/multitier_benchmark.py` — benchmark script patterns and schema conventions

### Secondary (MEDIUM confidence)
- Existing project memory: "Sliding window FPR: agent_instructions (33%), workflows (24%) — v0.4 target" — these numbers differ from per-sample FPR measured here (12.2% and 23.9%); the 33% figure likely refers to sliding-window FPR (a different metric from per-sample). The planner should clarify which metric Phase 5 must reduce.
- `docs/SECURITY.md` — current FPR table shows combined pipeline FPR 22.2% on 234-sample v3 benign eval; v4 19.0% on 757-sample eval; neither is per-content-type.

### Tertiary (LOW confidence)
- None — all findings verified against primary project artifacts.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all infrastructure already exists and was used in v0.3
- Architecture: HIGH — benchmark script pattern is proven; output schema is established
- Pitfalls: HIGH — CI-001 dominance measured directly on corpus; mode-gating behavior verified from rule YAML
- Campbell et al. citation: HIGH — full entry in references.json, arXiv URL confirmed

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (stable — no new dependencies, proven pattern)

---

## Appendix: Current FPR Baseline (measured this session)

Tier 0 FPR by content_type on `benign_eval_751.json` (757 samples), using production `PatternEngine.scan()`:

| content_type | n | flagged | FPR | Top patterns |
|---|---|---|---|---|
| workflow | 159 | 38 | 23.9% | CI-001 (59 fires), EX-001 (22), PE-005 (3) |
| config | 76 | 11 | 14.5% | AI-002, MCP-003 |
| readme | 146 | 23 | 15.8% | BM-011, PE-002, DF-001, EO-001, EO-006 |
| agent_instructions | 49 | 6 | 12.2% | DF-001, PE-005, PE-103, AI-002, CH-009, EX-001 |
| test_file | 169 | 12 | 7.1% | EO-006, CH-004, BM-002, ST-004, EX-004 |
| security_doc | 48 | 2 | 4.2% | CH-004, CH-009 |
| build_script | 55 | 0 | 0.0% | — |
| env_config | 55 | 0 | 0.0% | — |

Note: "sliding-window FPR" in project memory (33% for agent_instructions, 24% for workflows) refers to a different measurement — likely per-window across the sliding-window scan, not per-sample. These numbers are not directly comparable to the per-sample Tier 0 FPR above. The planner must confirm which metric the Phase 5 targets refer to.

CI-001 is the dominant workflow FP source (fires 59 times across 38 flagged workflow samples). CI-001 is not strict-only — it fires in STANDARD and STRICT mode. This is a design decision to audit in a future phase, not Phase 4. Phase 4's strict-pattern audit scope is limited to CI-004, CI-006, SC-001, MCP-005.
