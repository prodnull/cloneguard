# Phase 5: Enterprise Governance - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-04-06
**Phase:** 05-enterprise-governance
**Areas discussed:** Phase splitting, Policy backend priority, Fleet & SIEM scope

---

## Phase Splitting

| Option | Description | Selected |
|--------|-------------|----------|
| Split: Governance first | Phase 5 = GOVN-01..06, Phase 6 = AGNT-01..05. Governance has clearer enterprise buyer signal. | ✓ |
| Split: Agent Expansion first | Phase 5 = AGNT-01..05, Phase 6 = GOVN-01..06. Detection breadth first. | |
| Keep as one phase | 11 requirements in one phase. Larger execution. | |

**User's choice:** Split: Governance first
**Notes:** No technical dependency between governance and agent expansion domains. Governance builds on existing policy.py.

---

## Policy Backend Priority

| Option | Description | Selected |
|--------|-------------|----------|
| OPA/Rego first | Larger CNCF ecosystem, regopy pure Python | |
| Cedar first | AWS Bedrock AgentCore native | |
| Both simultaneously | Design IR first, implement both against it | ✓ |

**User's choice:** Both simultaneously

| Option | Description | Selected |
|--------|-------------|----------|
| YAML as canonical IR | OPA/Cedar compile to YAML semantics. Existing policy.py is evaluator. | ✓ |
| New IR, all three compile to it | Design superset IR. More work but future-proof. | |
| You decide | Claude picks based on regopy/cedarpy capabilities | |

**User's choice:** YAML as canonical, others compile to it
**Notes:** Keeps existing policy.py as the authoritative execution model. OPA and Cedar become frontends only.

---

## SIEM Integration

| Option | Description | Selected |
|--------|-------------|----------|
| Splunk HEC | Dominant in enterprise SOC, HTTP JSON | ✓ |
| Microsoft Sentinel | Azure-native, growing with Copilot shops | ✓ |
| Chronicle | Google Cloud SecOps, UDM ingestion | ✓ |

**User's choice:** All three SIEMs

| Option | Description | Selected |
|--------|-------------|----------|
| Integration guides only | Markdown docs, NDJSON format is the interface | |
| Tested connectors with example configs | Ship config files, test in CI against mock endpoints | ✓ |
| You decide | | |

**User's choice:** Tested connectors with example configs

---

## Fleet Deployment

| Option | Description | Selected |
|--------|-------------|----------|
| Both MDM + Ansible | macOS managed fleets + Linux servers/CI | ✓ |
| Ansible only | Linux-focused, skip MDM | |
| MDM only | macOS developer workstation focus | |

**User's choice:** Both MDM + Ansible

---

## SPIFFE Identity

| Option | Description | Selected |
|--------|-------------|----------|
| Include in Phase 5 | Zero-trust attribution on hook events | ✓ |
| Defer to Phase 6 or backlog | Early adoption, wait for demand | |
| You decide | | |

**User's choice:** Include in Phase 5

---

## Claude's Discretion

- Policy IR intermediate representation structure
- SIEM mock endpoint implementation for CI testing
- Ansible role structure and MDM profile format details
- SPIFFE integration depth

## Deferred Ideas

- Agent Expansion (AGNT-01..05) -- split to Phase 6
- Pattern library depth decision -- deferred to Phase 6 discuss-phase
