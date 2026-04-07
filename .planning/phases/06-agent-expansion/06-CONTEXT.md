# Phase 6: Agent Expansion - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

CloneGuard detects domain-specific attacks targeting browser, autonomous, financial, and CI/CD agent types with dedicated pattern libraries, and provides additional sandbox adapters for container and WASM environments (gVisor, Firecracker, WASM, Docker) with auto-selection of the strongest available adapter.

This phase was split from Phase 5 during Phase 5 discuss-phase. The two domains have no technical dependency — governance had clearer enterprise buyer signal while agent expansion extends detection breadth.

</domain>

<decisions>
## Implementation Decisions

### Pattern Library Depth
- **D-01:** Tiered approach — ship a seed library (~8 patterns per agent type) as core. Additional patterns available as optional expansion packs that operators can enable via policy.yaml. Keeps FPR tight on the default set.
- **D-02:** Strictly additive — new rules only cover attacks unique to each agent domain. Existing patterns (exfiltration, credential_harvesting, cicd_poisoning, memory_poisoning, etc.) already fire for all agent types via fusion weights. No domain-specialized variants of existing rules.
- **D-03:** All four agent types (browser, autonomous, financial, CI/CD) developed in parallel. Pattern libraries are independent YAML files with no technical dependency between them.

### Pattern Organization
- **D-04:** Per-agent-type subdirectories: `rules/browser/`, `rules/autonomous/`, `rules/financial/`, `rules/cicd/`. Matches the agent-type concept from Phase 3 input adapters. PatternEngine loader extended to scan subdirectories.
- **D-05:** Existing 27 YAML rules stay at `rules/` root — they are coding-agent patterns and serve their current purpose. No migration of existing patterns. This avoids breaking existing pattern IDs and test references.

### Sandbox Adapter Scope
- **D-06:** Implement all four additional sandbox adapters: gVisor, Firecracker, WASM (Wasmtime/Wasmer), and Docker. Each conforms to the existing SandboxAdapter Protocol from Phase 2.
- **D-07:** Full enforcement depth for all adapters: `restrict_filesystem` + `restrict_network` + `restrict_syscalls`. Consistent with Landlock/Seatbelt depth from Phase 2.
- **D-08:** Auto-selection ranking by strongest isolation: Firecracker (VM) > gVisor (kernel) > Docker (container) > WASM (process) > Landlock/Seatbelt (OS) > Noop. Operator can override via `~/.cloneguard/policy.yaml`. Probe order at startup determines availability.

### Evidence Standard
- **D-09:** Every seed pattern must cite a CVE, published incident, research paper, OR appear in OWASP Agentic Top 10 / MITRE ATLAS taxonomy with a concrete PoC payload that validates the regex. No speculative patterns in the seed library.
- **D-10:** Patterns that don't meet the evidence bar go in the optional expansion pack, not the seed library. Operators opt in to expansion patterns via policy.yaml configuration.
- **D-11:** Research phase produces a citable threat catalog document per agent type (`docs/threats/browser.md`, `docs/threats/autonomous.md`, `docs/threats/financial.md`, `docs/threats/cicd.md`). Each maps attack classes to patterns, evidence sources, and PoC payloads. Doubles as documentation and sales material.

### Claude's Discretion
- Exact seed pattern selection per agent type (within evidence standard constraints)
- Expansion pack pattern selection and packaging mechanism
- PatternEngine loader changes for subdirectory scanning
- Sandbox adapter internal implementation details (gVisor/Firecracker/WASM/Docker APIs)
- Auto-selection probe strategy and startup overhead management
- Threat catalog document format and depth
- Test organization for new pattern libraries and sandbox adapters

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Pattern Engine & Rules
- `src/cloneguard/rules/` — Existing 27 YAML pattern rule files (new subdirs go here)
- `src/cloneguard/rules/cicd_poisoning.yaml` — Existing CI/CD patterns (reference for new CI/CD agent library)
- `src/cloneguard/rules/memory_poisoning.yaml` — Existing memory poisoning patterns (reference for autonomous agent library)
- `src/cloneguard/rules/mcp_tool_poisoning.yaml` — Existing MCP patterns (reference style)

### Sandbox Adapter Interface
- `src/cloneguard/enforcement/adapter.py` — SandboxAdapter Protocol with deferred methods (restrict_syscalls, get_audit_log)
- `src/cloneguard/enforcement/landlock.py` — Linux Landlock adapter (reference implementation for new adapters)
- `src/cloneguard/enforcement/seatbelt.py` — macOS Seatbelt adapter (reference implementation)
- `src/cloneguard/enforcement/sandbox_exec.py` — Sandbox execution wrapper
- `src/cloneguard/enforcement/registry.py` — Adapter registry with auto-selection logic

### Detection & Fusion (Phase 4 — patterns feed into this)
- `src/cloneguard/detection/` — Detection engine, fusion layer, signal types
- `src/cloneguard/enforcement/types.py` — PolicyDecision, EnforcementVerdict types

### Prior Phase Context
- `.planning/phases/04-detection-excellence/04-CONTEXT.md` — D-15 (subdirectory reorganization), D-18 (agent-type-agnostic rules)
- `.planning/phases/05-enterprise-governance/05-CONTEXT.md` — Phase split rationale, deferred pattern library decisions

### Project
- `.planning/PROJECT.md` — Core value, constraints, open-core split
- `.planning/REQUIREMENTS.md` — AGNT-01 through AGNT-05 requirement definitions

### External Standards
- OWASP Agentic AI Top 10 — Attack taxonomy for agent-type pattern mapping
- MITRE ATLAS v5.4.0 — Adversarial ML threat framework
- NIST CAISI — AI security guidelines

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SandboxAdapter` Protocol (enforcement/adapter.py): Already defines the interface new adapters must implement, including deferred methods for restrict_syscalls and get_audit_log
- `LandlockAdapter` (enforcement/landlock.py): Reference implementation for Linux sandbox — new adapters follow this pattern
- `SeatbeltAdapter` (enforcement/seatbelt.py): Reference implementation for macOS sandbox
- `enforcement/registry.py`: Adapter registry with auto-selection — extend with new adapter probing
- Existing YAML rule files: Pattern format (id, regex, severity, description, false_positive_hint) is the template for new rules

### Established Patterns
- Protocol-based interfaces (PEP 544): New sandbox adapters must conform to SandboxAdapter Protocol
- YAML rule loading: PatternEngine loads from `rules/` directory at init — extend to scan subdirectories
- Graceful degradation: If sandbox runtime unavailable, adapter probe returns None and auto-selection falls through to next option
- Frozen dataclasses on hot path: Pattern match results are frozen dataclasses

### Integration Points
- `enforcement/adapter.py::auto_select_adapter()`: Add probing for gVisor, Firecracker, WASM, Docker availability
- `PatternEngine._load_rules()`: Extend to recursively scan subdirectories under `rules/`
- `~/.cloneguard/policy.yaml`: Expansion pack enable/disable configuration, sandbox adapter override
- Fusion weight profiles: New agent-type pattern libraries may need corresponding weight profiles

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches for pattern development and sandbox adapter implementation. Key constraint: evidence standard (D-09) means the research phase needs to produce concrete threat catalogs before pattern writing begins.

</specifics>

<deferred>
## Deferred Ideas

- Browser agent CDP input adapter (XDET-01) — v2 requirement, beyond pattern library scope
- Autonomous agent SDK middleware adapters for LangChain/AutoGen/ADK/CrewAI (XDET-03) — v2 requirement
- Financial agent custom API middleware (XDET-02) — v2 requirement
- Windows AppContainer sandbox adapter (XPLT-01) — v2 requirement
- User-provided ONNX model support (XDET-04) — v2 requirement

None of these were raised during discussion — all are pre-existing v2 deferrals.

</deferred>

---

*Phase: 06-agent-expansion*
*Context gathered: 2026-04-07*
