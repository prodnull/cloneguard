# Phase 6: Agent Expansion - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-07
**Phase:** 06-agent-expansion
**Areas discussed:** Pattern library depth, Pattern organization, Sandbox adapter scope, Evidence standard

---

## Pattern Library Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Seed libraries (5-10 per type) | Cover highest-impact attack classes with CVE/incident-backed patterns | |
| Comprehensive (15-25 per type) | Cover all documented attack classes in OWASP/MITRE | |
| Tiered approach | Seed library (~8 per type) as core + optional expansion packs | ✓ |

**User's choice:** Tiered approach
**Notes:** Keeps FPR tight on the default set while allowing operators to expand coverage.

| Option | Description | Selected |
|--------|-------------|----------|
| Strictly additive | New rules only cover attacks unique to each agent domain | ✓ |
| Domain-specialized variants | Agent-specific versions of existing patterns | |

**User's choice:** Strictly additive
**Notes:** Existing patterns already fire for all agent types via fusion weights.

| Option | Description | Selected |
|--------|-------------|----------|
| CI/CD first, then browser | Prioritize by immediate real-world attack surface | |
| All four in parallel | Pattern libraries are independent YAML files | ✓ |
| You decide based on evidence | Let research determine priority | |

**User's choice:** All four in parallel

---

## Pattern Organization

| Option | Description | Selected |
|--------|-------------|----------|
| Per-agent-type subdirs | rules/browser/, rules/autonomous/, rules/financial/, rules/cicd/ | ✓ |
| Per-attack-class subdirs | rules/dom_injection/, rules/goal_hijacking/ | |
| Flat with naming prefix | browser_dom_injection.yaml, cicd_workflow_injection.yaml | |

**User's choice:** Per-agent-type subdirectories
**Notes:** Matches agent-type concept from Phase 3 adapters.

| Option | Description | Selected |
|--------|-------------|----------|
| Leave existing rules in place | Existing 27 rules stay at rules/ root | ✓ |
| Migrate to subdirs | Move cicd_poisoning.yaml, memory_poisoning.yaml to agent subdirs | |

**User's choice:** Leave existing rules in place
**Notes:** Avoids breaking existing pattern IDs and test references.

---

## Sandbox Adapter Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Docker only | Ubiquitous, stub the rest | |
| Docker + WASM | Two complementary isolation models | |
| All four as specified | gVisor, Firecracker, WASM, Docker | ✓ |
| You decide based on research | Let researcher determine which are worth implementing | |

**User's choice:** All four as specified

| Option | Description | Selected |
|--------|-------------|----------|
| Full enforcement | restrict_filesystem + restrict_network + restrict_syscalls | ✓ |
| Tiered by adapter maturity | Docker full, others restricted | |
| Detection stubs + Docker full | Docker full, others stubbed | |

**User's choice:** Full enforcement

| Option | Description | Selected |
|--------|-------------|----------|
| Strongest isolation wins | Firecracker > gVisor > Docker > WASM > Landlock/Seatbelt > Noop | ✓ |
| Operator-configured priority | No default ranking, operator must specify | |
| Environment-aware default | Auto-detect runtime environment for ranking | |

**User's choice:** Strongest isolation wins
**Notes:** Operator can override via policy.yaml.

---

## Evidence Standard

| Option | Description | Selected |
|--------|-------------|----------|
| Documented attack only | CVE, incident, or paper required | |
| Documented + expert consensus | CVE/incident/paper preferred, OWASP/MITRE + PoC acceptable | ✓ |
| Any plausible attack with PoC | Working PoC sufficient, no citation required | |

**User's choice:** Documented + expert consensus

| Option | Description | Selected |
|--------|-------------|----------|
| Expansion pack only | Weak-evidence patterns in optional expansion pack | ✓ |
| Advisory severity | Include at advisory severity in main library | |
| Exclude entirely | Don't ship if evidence bar not met | |

**User's choice:** Expansion pack only

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — citable threat catalogs | docs/threats/{agent_type}.md per agent type | ✓ |
| No — evidence in YAML comments | Pattern YAML includes reference field | |

**User's choice:** Citable threat catalogs per agent type

---

## Claude's Discretion

- Exact seed pattern selection per agent type
- Expansion pack packaging mechanism
- PatternEngine loader changes for subdirectory scanning
- Sandbox adapter internal implementation details
- Auto-selection probe strategy
- Threat catalog document format
- Test organization

## Deferred Ideas

None — discussion stayed within phase scope. All deferrals are pre-existing v2 requirements.
