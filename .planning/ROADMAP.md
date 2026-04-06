# Roadmap: CloneGuard v2 Universal Agentic Defense

## Overview

CloneGuard evolves from a detection-only coding-agent scanner into a universal agentic defense layer. The roadmap proceeds bottom-up through five phases: extract the detection engine and ship structured audit (EU AI Act compliance), build adaptive enforcement with sandbox adapters, integrate with multi-agent platforms, calibrate three-signal fusion on production data, then add enterprise governance backends and agent-type expansion. Each phase delivers a coherent, verifiable capability that unblocks the next.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Foundation** - Extract detection engine, ship NDJSON/SARIF audit, fix packaging, establish backward compatibility
- [ ] **Phase 2: Adaptive Enforcement** - Three-verdict model, YAML policy engine, sandbox adapters (Noop/Landlock/Seatbelt), dry-run default
- [ ] **Phase 3: Framework Integration** - Input adapter abstraction, AGT plugin, MCP middleware, OTel spans, CI/CD deployment, package hallucination detection
- [ ] **Phase 4: Detection Excellence** - Three-signal fusion calibrated on trajectory data, MELON selective re-execution, cross-agent pattern libraries, adversarial evaluation
- [ ] **Phase 5: Enterprise Governance and Agent Expansion** - OPA/Cedar policy backends, fleet tooling, SIEM guides, SPIFFE identity, browser/autonomous/financial/CI-CD pattern libraries, additional sandbox adapters

## Phase Details

### Phase 1: Foundation
**Goal**: Detection engine is modular with typed contracts, structured audit meets EU AI Act Article 12, and existing users see zero behavior change
**Depends on**: Nothing (first phase)
**Requirements**: FNDN-01, FNDN-02, FNDN-03, FNDN-04, FNDN-05, FNDN-06
**Success Criteria** (what must be TRUE):
  1. Running `cloneguard` via `uv tool install` or `pipx` produces a working standalone binary that passes existing hook protocol tests
  2. Every detection event emits a valid NDJSON line containing session_id, verdict, confidence, signals, and enforcement_action fields
  3. Running `cloneguard --sarif` produces output that validates against the OASIS SARIF 2.1.0 schema and is consumable by GitHub Advanced Security
  4. Existing Claude Code hook integration (JSON stdin/stdout, exit 0/2) behaves identically to v0.5.0 via thin shims -- all 1,321 existing tests pass
  5. Hook config integrity self-check detects and rejects tampered configuration (CVE-2025-59536 class defense)
**Plans**: 4 plans

Plans:
- [x] 01-01-PLAN.md -- Extract detection engine into cloneguard.detection package with typed Protocol interfaces
- [x] 01-02-PLAN.md -- Create NDJSON audit layer and convert hooks.py/scanner.py to thin shims
- [x] 01-03-PLAN.md -- Implement SARIF 2.1.0 emitter, fix packaging, add hook config integrity check
- [x] 01-04-PLAN.md -- Gap closure: Make hooks.py thin shims delegate to DetectionEngine, fix broken test

### Phase 2: Adaptive Enforcement
**Goal**: Operators can configure three-verdict outcomes with YAML policy and optionally constrain tool calls via OS-level sandbox adapters, with dry-run as the safe default
**Depends on**: Phase 1
**Requirements**: ENFC-01, ENFC-02, ENFC-03, ENFC-04, ENFC-05, ENFC-06, ENFC-07, ENFC-08, ENFC-09
**Success Criteria** (what must be TRUE):
  1. Detection produces SAFE, SUSPICIOUS, or MALICIOUS verdicts with operator-configurable confidence thresholds via YAML in ~/.cloneguard/
  2. On Linux 5.13+, a SUSPICIOUS verdict with enforcement enabled restricts the tool call subprocess to operator-specified filesystem and network boundaries via Landlock, without affecting the CloneGuard process itself
  3. On macOS, a SUSPICIOUS verdict with enforcement enabled restricts the tool call subprocess via Seatbelt sandbox profiles
  4. With no enforcement configured (default), CloneGuard behaves identically to v0.5.0 detection-only mode (NoopAdapter, exit 0/2)
  5. Dry-run mode logs what constraints would apply without enforcing them, and is the default for all new installations
**Plans**: 5 plans

Plans:
- [x] 02-01-PLAN.md -- Enforcement types, verdict transition (SAFE/SUSPICIOUS/MALICIOUS), SandboxAdapter Protocol, NoopAdapter
- [x] 02-02-PLAN.md -- YAML policy engine with Pydantic validation, threshold gating, per-tool overrides, dry-run default
- [x] 02-03-PLAN.md -- OS-level sandbox adapters: LandlockAdapter (Linux) and SeatbeltAdapter (macOS)
- [x] 02-04-PLAN.md -- Package hallucination detection via npm/PyPI registry cross-reference
- [x] 02-05-PLAN.md -- Pipeline integration: wire enforcement into hooks.py, update audit events, end-to-end tests

### Phase 3: Framework Integration
**Goal**: CloneGuard scans tool calls from any major agent platform (not just Claude Code) and emits observability signals that enterprise SOC teams can consume
**Depends on**: Phase 2
**Requirements**: INTG-01, INTG-02, INTG-03, INTG-04, INTG-05
**Success Criteria** (what must be TRUE):
  1. The same detection+enforcement pipeline processes tool calls from Claude Code, Gemini CLI, and MCP protocol sources without agent-specific logic in the detection engine
  2. Microsoft AGT ToolCallInterceptor plugin exposes CloneGuard as a semantic sensor within the AGT governance pipeline
  3. A GitHub Actions workflow runs CloneGuard on PR events and uploads SARIF results to the repository Security tab
  4. OTel spans conforming to GenAI semantic conventions appear in any OTel-compatible collector when OTel emission is enabled
  5. Input adapters normalize tool call events from at least two additional agent platforms (Gemini CLI, Cursor) into the unified ToolCallEvent schema, with adapter-specific tests
**Plans**: TBD

Plans:
- [ ] 03-01: TBD
- [ ] 03-02: TBD

### Phase 4: Detection Excellence
**Goal**: Three-signal fusion (pattern + semantic + sequence) is calibrated on production data across agent types, producing measurably better detection with controlled FPR
**Depends on**: Phase 3
**Requirements**: DETC-01, DETC-02, DETC-03, DETC-04, DETC-05, DETC-06
**Success Criteria** (what must be TRUE):
  1. Fusion layer produces a single calibrated confidence score from pattern, semantic, and sequence signals, with per-agent-type weight profiles derived from the 208K trajectory dataset plus production data from Phase 3 adapters
  2. FPR is tracked per content type (CI configs, security docs, test fixtures, MCP tool descriptions) and remains below the standalone baseline (9.2%) for each category
  3. MELON selective re-execution triggers only in the configurable ambiguous confidence zone (default 0.4-0.6) with a circuit breaker at >15% trigger rate
  4. Adversarial evaluation against "Attacker Moves Second" methodology produces published results with honest bypass rates
**Plans**: TBD

Plans:
- [ ] 04-01: TBD
- [ ] 04-02: TBD

### Phase 5: Enterprise Governance and Agent Expansion
**Goal**: Enterprise teams can express enforcement policy in OPA/Cedar, deploy CloneGuard at fleet scale, and detect attacks targeting browser, autonomous, financial, and CI/CD agent types
**Depends on**: Phase 4
**Requirements**: GOVN-01, GOVN-02, GOVN-03, GOVN-04, GOVN-05, GOVN-06, AGNT-01, AGNT-02, AGNT-03, AGNT-04, AGNT-05
**Success Criteria** (what must be TRUE):
  1. Operators can write enforcement policy in OPA/Rego or Cedar and have it evaluated in-process (no external server) alongside YAML policy, producing identical PolicyDecision types
  2. Fleet deployment via MDM or Ansible playbooks provisions CloneGuard with centralized policy to N machines with a single configuration push
  3. NDJSON audit events flow into Splunk HEC, Microsoft Sentinel, or Chronicle via documented integration guides without custom parsing
  4. Agent-type-specific pattern libraries (browser, autonomous, financial, CI/CD) detect domain-specific attacks (DOM injection, goal hijacking, transaction manipulation, workflow injection) when the corresponding agent adapter is active
  5. Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) are available with auto-selection of the strongest available adapter on the host
**Plans**: TBD

Plans:
- [ ] 05-01: TBD
- [ ] 05-02: TBD
- [ ] 05-03: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 4/4 | Complete | - |
| 2. Adaptive Enforcement | 0/5 | Planning complete | - |
| 3. Framework Integration | 0/2 | Not started | - |
| 4. Detection Excellence | 0/2 | Not started | - |
| 5. Enterprise Governance and Agent Expansion | 0/3 | Not started | - |
