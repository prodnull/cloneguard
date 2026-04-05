# Requirements: CloneGuard v2 Universal Agentic Defense

**Defined:** 2026-04-05
**Core Value:** The only vendor-neutral, sandbox-agnostic defense layer that fuses pattern + semantic + behavioral signals and enforces adaptive constraints across any agent type.

## v1 Requirements

Requirements for v2 initial release. Each maps to roadmap phases.

### Foundation

- [ ] **FNDN-01**: Detection engine extracted from hooks.py into standalone module with typed Protocol interfaces
- [ ] **FNDN-02**: Structured event schema emitting NDJSON for every detection event (session_id, verdict, confidence, signals, enforcement_action)
- [ ] **FNDN-03**: SARIF 2.1.0 emitter producing valid output consumable by GitHub Advanced Security, VS Code, SonarQube
- [ ] **FNDN-04**: Packaging supports `uv tool install` / `pipx` standalone binary installation
- [ ] **FNDN-05**: Hook config integrity self-check (CVE-2025-59536 class defense)
- [ ] **FNDN-06**: Backward compatibility preserved — existing Claude Code hook protocol (exit 0/2) works identically via thin shims

### Enforcement

- [ ] **ENFC-01**: Three-verdict model (SAFE / SUSPICIOUS / MALICIOUS) with configurable thresholds
- [ ] **ENFC-02**: Sandbox adapter interface (Protocol-based) with auto-selection of strongest available adapter
- [ ] **ENFC-03**: NoopAdapter preserving current v0.5.0 detection-only behavior exactly
- [ ] **ENFC-04**: LandlockAdapter restricting filesystem and network for Linux 5.13+
- [ ] **ENFC-05**: SeatbeltAdapter restricting filesystem and network for macOS
- [ ] **ENFC-06**: Policy engine with YAML configuration (threshold tuning, per-tool overrides, per-agent-type defaults)
- [ ] **ENFC-07**: Dry-run enforcement mode as default for first release (log constraints that would apply, don't enforce)
- [ ] **ENFC-08**: Package hallucination detection cross-referencing npm/PyPI registry at `npm install`/`pip install` time
- [ ] **ENFC-09**: Enforcement config lives exclusively in operator-controlled paths (~/.cloneguard/), never repo-resident

### Integration

- [ ] **INTG-01**: Input adapter abstraction decoupling detection engine from Claude Code hook protocol
- [ ] **INTG-02**: Microsoft AGT ToolCallInterceptor plugin exposing CloneGuard as a semantic sensor
- [ ] **INTG-03**: MCP protocol middleware adapter for scanning MCP tool calls
- [ ] **INTG-04**: CI/CD runner deployment (GitHub Actions) with SARIF upload to Security tab
- [ ] **INTG-05**: OTel span emission conforming to GenAI semantic conventions

### Detection

- [ ] **DETC-01**: Three-signal fusion layer (pattern + semantic + sequence) calibrated on 208K trajectory dataset
- [ ] **DETC-02**: Context-weighted fusion scoring (not naive max(scores)) with mode-aware signal weighting
- [ ] **DETC-03**: MELON selective re-execution triggering only in configurable ambiguous confidence zone (default 0.4-0.6)
- [ ] **DETC-04**: Memory/config file poisoning pattern library
- [ ] **DETC-05**: MCP tool description fingerprinting against known-good registries
- [ ] **DETC-06**: Adversarial evaluation against "Attacker Moves Second" methodology with published results

### Governance

- [ ] **GOVN-01**: OPA/Rego policy backend via regopy (in-process evaluation, no server)
- [ ] **GOVN-02**: Cedar policy backend via cedarpy for AWS Bedrock AgentCore integration
- [ ] **GOVN-03**: Policy IR compiler (YAML + OPA + Cedar compile to same intermediate representation)
- [ ] **GOVN-04**: SIEM integration guides for Splunk HEC, Sentinel, Chronicle
- [ ] **GOVN-05**: Fleet deployment tooling (MDM/Ansible playbooks)
- [ ] **GOVN-06**: SPIFFE agent identity on hook events

### Agent Expansion

- [ ] **AGNT-01**: Browser agent pattern library (DOM injection, invisible text, URL redirect)
- [ ] **AGNT-02**: Autonomous agent pattern library (goal hijacking, delegation abuse, memory poisoning)
- [ ] **AGNT-03**: Financial agent pattern library (transaction manipulation, approval bypass)
- [ ] **AGNT-04**: CI/CD agent pattern library (workflow injection, secret exfil, release poisoning)
- [ ] **AGNT-05**: Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) with auto-selection

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Extended Detection

- **XDET-01**: Browser agent CDP input adapter for runtime interception
- **XDET-02**: Financial agent custom API middleware adapter
- **XDET-03**: Autonomous agent SDK middleware adapters (LangChain, AutoGen, ADK, CrewAI)
- **XDET-04**: User-provided ONNX model support (bring-your-own classifier)

### Extended Compliance

- **XCMP-01**: SOC 2 Type II aggregated quarterly reports from structured events
- **XCMP-02**: Full EU AI Act Article 12 compliance package (retention policy, risk categorization)
- **XCMP-03**: ISO 42001 A.6.2.8 evidence generation

### Extended Platform

- **XPLT-01**: Windows AppContainer sandbox adapter
- **XPLT-02**: Policy distribution service for fleet-wide configuration sync

## Out of Scope

| Feature | Reason |
|---------|--------|
| SaaS/cloud-hosted detection | Defeats trust model — CloneGuard runs on-device, in position agent can't compromise |
| Custom ML model training platform | IPI Arena retraining showed unacceptable FPR regression (9% to 20-42%). Value is in fusion, not classifier |
| Full governance framework | CloneGuard is a sensor that feeds governance (AGT/OPA/Cedar), not a governance platform |
| Building a sandbox | Orchestrate existing sandboxes via adapters; don't maintain OS-level security primitives |
| Real-time dashboard / web UI | Months of engineering that doesn't improve detection. SARIF/OTel/NDJSON in existing tools |
| LLM-as-judge for every tool call | 200-2000ms per call is unacceptable. Selective Tier 2 for ambiguous cases only |
| Agent-internal prompt hardening | Wrong architectural layer. CloneGuard operates at Layer 0, can't modify agent system prompt |
| Claiming to block all attacks | Dishonest. 16.7% bypass rate reported. Frame as raising attacker cost |
| Windows sandbox adapter (v1) | Linux + macOS cover developer workstations + CI/CD. Windows gets NoopAdapter (detection-only) |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| FNDN-01 | Phase 1 | Pending |
| FNDN-02 | Phase 1 | Pending |
| FNDN-03 | Phase 1 | Pending |
| FNDN-04 | Phase 1 | Pending |
| FNDN-05 | Phase 1 | Pending |
| FNDN-06 | Phase 1 | Pending |
| ENFC-01 | Phase 2 | Pending |
| ENFC-02 | Phase 2 | Pending |
| ENFC-03 | Phase 2 | Pending |
| ENFC-04 | Phase 2 | Pending |
| ENFC-05 | Phase 2 | Pending |
| ENFC-06 | Phase 2 | Pending |
| ENFC-07 | Phase 2 | Pending |
| ENFC-08 | Phase 2 | Pending |
| ENFC-09 | Phase 2 | Pending |
| INTG-01 | Phase 3 | Pending |
| INTG-02 | Phase 3 | Pending |
| INTG-03 | Phase 3 | Pending |
| INTG-04 | Phase 3 | Pending |
| INTG-05 | Phase 3 | Pending |
| DETC-01 | Phase 4 | Pending |
| DETC-02 | Phase 4 | Pending |
| DETC-03 | Phase 4 | Pending |
| DETC-04 | Phase 4 | Pending |
| DETC-05 | Phase 4 | Pending |
| DETC-06 | Phase 4 | Pending |
| GOVN-01 | Phase 5 | Pending |
| GOVN-02 | Phase 5 | Pending |
| GOVN-03 | Phase 5 | Pending |
| GOVN-04 | Phase 5 | Pending |
| GOVN-05 | Phase 5 | Pending |
| GOVN-06 | Phase 5 | Pending |
| AGNT-01 | Phase 5 | Pending |
| AGNT-02 | Phase 5 | Pending |
| AGNT-03 | Phase 5 | Pending |
| AGNT-04 | Phase 5 | Pending |
| AGNT-05 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 37 total
- Mapped to phases: 37
- Unmapped: 0

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after roadmap creation*
