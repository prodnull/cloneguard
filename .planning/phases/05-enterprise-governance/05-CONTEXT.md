# Phase 5: Enterprise Governance - Context

**Gathered:** 2026-04-06
**Status:** Ready for planning

<domain>
## Phase Boundary

Enterprise teams can express enforcement policy in OPA/Rego or Cedar (evaluated in-process), deploy CloneGuard at fleet scale via MDM and Ansible, consume NDJSON audit events in Splunk/Sentinel/Chronicle via tested connectors, and attribute hook events to SPIFFE agent identities.

**Scope change from ROADMAP.md:** This phase was originally "Enterprise Governance and Agent Expansion" (GOVN-01..06 + AGNT-01..05). Split into two phases during discuss-phase:
- **Phase 5 (this phase):** Governance only (GOVN-01 through GOVN-06)
- **Phase 6 (new):** Agent Expansion (AGNT-01 through AGNT-05) — browser, autonomous, financial, CI/CD pattern libraries + additional sandbox adapters

Rationale: The two domains have no technical dependency. Governance has clearer enterprise buyer signal and builds on existing policy.py.

</domain>

<decisions>
## Implementation Decisions

### Policy Backend Priority
- **D-01:** Implement OPA/Rego (regopy) and Cedar (cedarpy) simultaneously, not sequentially. Design the IR first, then both backends implement against it.
- **D-02:** YAML is the canonical IR. OPA and Cedar are frontend parsers that compile to YAML policy semantics internally. Existing `enforcement/policy.py` remains the evaluator. This avoids designing a new IR from scratch and keeps the existing YAML policy path as the authoritative execution model.

### SIEM Integration
- **D-03:** Ship tested connectors with example configs for all three major SIEMs: Splunk HEC, Microsoft Sentinel, and Chronicle (Google SecOps). Not just documentation — actual config files tested in CI against mock endpoints.
- **D-04:** NDJSON format is the interface contract. Connectors translate NDJSON to each SIEM's native ingestion format (HEC JSON, Sentinel DCR, Chronicle UDM).

### Fleet Deployment
- **D-05:** Ship both MDM profiles (Jamf/Intune for macOS managed fleets) and Ansible playbooks (Linux server fleets and CI/CD runners). Covers developer workstations and server-side deployment.

### SPIFFE Identity
- **D-06:** SPIFFE agent identity (GOVN-06) stays in Phase 5 scope. Hook events should carry SPIFFE identity for zero-trust attribution — which agent on which machine triggered which detection.

### Claude's Discretion
- Policy IR intermediate representation structure (as long as YAML semantics are canonical)
- SIEM mock endpoint implementation for CI testing
- Ansible role structure and MDM profile format details
- SPIFFE integration depth (full SPIRE workload API vs. simpler SVIDs-from-environment)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Policy Engine
- `src/cloneguard/enforcement/policy.py` -- Existing YAML policy engine (the canonical IR evaluator)
- `src/cloneguard/enforcement/types.py` -- PolicyDecision and enforcement types
- `src/cloneguard/enforcement/__init__.py` -- Enforcement module public API

### Sandbox & Enforcement
- `src/cloneguard/enforcement/adapter.py` -- Sandbox adapter interface (Protocol-based)
- `src/cloneguard/enforcement/landlock.py` -- Linux Landlock adapter (reference for adapter pattern)
- `src/cloneguard/enforcement/seatbelt.py` -- macOS Seatbelt adapter

### Adapters
- `src/cloneguard/adapters/` -- Existing agent-type adapters (Claude Code, Gemini, Cursor, AGT, MCP, CI/CD)

### Project
- `.planning/PROJECT.md` -- Core value, constraints, open-core split
- `.planning/REQUIREMENTS.md` -- GOVN-01 through GOVN-06 requirement definitions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `enforcement/policy.py`: YAML policy engine with PolicyDecision types — becomes the canonical IR evaluator
- `enforcement/types.py`: PolicyDecision, EnforcementVerdict — IR compilation targets
- `enforcement/adapter.py`: Protocol-based sandbox adapter interface — pattern for policy backend Protocol

### Established Patterns
- Protocol-based interfaces throughout enforcement/ — OPA and Cedar backends should follow same Protocol pattern
- NDJSON event emission already exists in hooks.py — SIEM connectors consume this output
- Agent-type adapter pattern in adapters/ — each adapter translates a platform's protocol to CloneGuard's internal types

### Integration Points
- `hooks.py` emits NDJSON events — SIEM connectors read this stream
- `enforcement/policy.py` evaluates YAML policy — OPA/Cedar frontends compile to this
- Hook events need SPIFFE identity field added to event schema
- Fleet deployment provisions `~/.cloneguard/policy.yaml` and hook configs to `~/.claude/settings.json`

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches for OPA/Cedar integration, SIEM connectors, and fleet tooling.

</specifics>

<deferred>
## Deferred Ideas

- **Agent Expansion (AGNT-01..05)** — Split to Phase 6. Browser, autonomous, financial, CI/CD pattern libraries and additional sandbox adapters (gVisor, Firecracker, WASM, Docker).
- **Pattern library depth decision** — Deferred to Phase 6 discuss-phase. User did not select this area for Phase 5 discussion.

</deferred>

---

*Phase: 05-enterprise-governance*
*Context gathered: 2026-04-06*
