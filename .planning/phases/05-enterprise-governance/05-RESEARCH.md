# Phase 5: Enterprise Governance - Research

**Researched:** 2026-04-06
**Domain:** Policy engines (OPA/Cedar), SIEM integration, fleet deployment, SPIFFE identity
**Confidence:** MEDIUM-HIGH

## Summary

Phase 5 adds enterprise governance capabilities to CloneGuard: operators can write enforcement policy in OPA/Rego or Cedar (evaluated in-process, no external server), deploy at fleet scale via MDM profiles and Ansible playbooks, consume structured audit events in three major SIEMs via tested connectors, and attribute hook events to SPIFFE agent identities.

The architecture decision (D-02) to use YAML as the canonical IR with OPA/Cedar as frontend parsers is well-suited to the existing codebase. The `YAMLPolicyEngine` in `enforcement/policy.py` already evaluates `PolicyConfig` objects to produce `PolicyDecision` types. Both `regopy` (Microsoft's C++ Rego interpreter, PyO3-wrapped) and `cedarpy` (Rust Cedar evaluator, PyO3-wrapped) provide in-process evaluation without external servers. The key design challenge is building two "compilers" that translate Rego/Cedar policy semantics into the existing `PolicyConfig` Pydantic model, preserving all existing YAML policy behavior.

**Primary recommendation:** Implement a `PolicyBackend` Protocol with three implementations (YAML, OPA, Cedar). Each backend's `compile()` method produces a `PolicyConfig` object. The existing `YAMLPolicyEngine.evaluate()` remains the sole evaluation path. SIEM connectors are thin transformers that read NDJSON from the existing `NDJSONEmitter` output and POST to SIEM-specific endpoints. SPIFFE identity is injected into `AuditEvent` via an optional `agent_identity` field populated from the Workload API at hook startup.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- D-01: Implement OPA/Rego (regopy) and Cedar (cedarpy) simultaneously, not sequentially. Design the IR first, then both backends implement against it.
- D-02: YAML is the canonical IR. OPA and Cedar are frontend parsers that compile to YAML policy semantics internally. Existing `enforcement/policy.py` remains the evaluator. This avoids designing a new IR from scratch and keeps the existing YAML policy path as the authoritative execution model.
- D-03: Ship tested connectors with example configs for all three major SIEMs: Splunk HEC, Microsoft Sentinel, and Chronicle (Google SecOps). Not just documentation -- actual config files tested in CI against mock endpoints.
- D-04: NDJSON format is the interface contract. Connectors translate NDJSON to each SIEM's native ingestion format (HEC JSON, Sentinel DCR, Chronicle UDM).
- D-05: Ship both MDM profiles (Jamf/Intune for macOS managed fleets) and Ansible playbooks (Linux server fleets and CI/CD runners). Covers developer workstations and server-side deployment.
- D-06: SPIFFE agent identity (GOVN-06) stays in Phase 5 scope. Hook events should carry SPIFFE identity for zero-trust attribution -- which agent on which machine triggered which detection.

### Claude's Discretion
- Policy IR intermediate representation structure (as long as YAML semantics are canonical)
- SIEM mock endpoint implementation for CI testing
- Ansible role structure and MDM profile format details
- SPIFFE integration depth (full SPIRE workload API vs. simpler SVIDs-from-environment)

### Deferred Ideas (OUT OF SCOPE)
- Agent Expansion (AGNT-01..05) -- Split to Phase 6
- Pattern library depth decision -- Deferred to Phase 6 discuss-phase
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| GOVN-01 | OPA/Rego policy backend via regopy (in-process evaluation, no server) | regopy 1.3.0 verified on PyPI; Interpreter.add_module() + query() API documented; compiles to PolicyConfig IR |
| GOVN-02 | Cedar policy backend via cedarpy for AWS Bedrock AgentCore integration | cedarpy 4.8.0 verified on PyPI; is_authorized() + validate_policies() API documented; compiles to PolicyConfig IR |
| GOVN-03 | Policy IR compiler (YAML + OPA + Cedar compile to same intermediate representation) | PolicyConfig Pydantic model is the IR; OPA/Cedar frontends parse native syntax and produce PolicyConfig objects |
| GOVN-04 | SIEM integration guides for Splunk HEC, Sentinel, Chronicle | Splunk HEC JSON wrapper documented; Sentinel via azure-monitor-ingestion 1.1.0; Chronicle via secops 0.40.0 or direct UDM API |
| GOVN-05 | Fleet deployment tooling (MDM/Ansible playbooks) | Jamf/Intune .mobileconfig profiles for macOS; Ansible roles for Linux; provisions policy.yaml + hook configs |
| GOVN-06 | SPIFFE agent identity on hook events | spiffe 0.2.6 (Python >=3.10) provides WorkloadApiClient; fallback to SPIFFE_ENDPOINT_SOCKET env var parsing |
</phase_requirements>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| regopy | 1.3.0 | In-process Rego evaluation | Microsoft's C++ Rego interpreter with Python bindings; no OPA server needed [VERIFIED: PyPI registry] |
| cedarpy | 4.8.0 | In-process Cedar evaluation | Rust Cedar engine with Python bindings via PyO3; batch auth support [VERIFIED: PyPI registry] |
| spiffe | 0.2.6 | SPIFFE Workload API client | Official HPE py-spiffe; X509/JWT SVIDs, auto-renewal [VERIFIED: PyPI registry] |
| pydantic | >=2.0 | PolicyConfig validation | Already in project dependencies; frozen models for policy IR [VERIFIED: pyproject.toml] |
| pyyaml | >=6.0 | YAML policy parsing | Already in project dependencies [VERIFIED: pyproject.toml] |

### Supporting (SIEM Connectors -- optional extras)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| azure-monitor-ingestion | 1.1.0 | Sentinel DCR log upload | Sentinel connector; requires azure-identity [VERIFIED: PyPI registry] |
| azure-identity | >=1.15 | Azure auth for Sentinel | Required by azure-monitor-ingestion [ASSUMED] |
| secops | 0.40.0 | Chronicle/Google SecOps ingestion | Chronicle connector; wraps UDM batchCreate API [VERIFIED: PyPI registry] |
| requests | >=2.31 | Splunk HEC HTTP client | Splunk connector; stdlib urllib is insufficient for HEC batching [ASSUMED] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| regopy (C++ FFI) | regorus (Rust via PyO3) | regorus is Microsoft's newer Rust implementation; faster but less mature Python bindings. regopy is better documented for Python. |
| cedarpy | Hand-rolled Cedar parser | Cedar syntax is complex; cedarpy uses the official Rust engine. Never hand-roll. |
| spiffe (full SDK) | Manual SPIFFE_ENDPOINT_SOCKET parsing + gRPC | Full SDK handles certificate rotation, JWT validation, and reconnection. Manual approach misses renewal. |
| requests (Splunk HEC) | urllib.request (stdlib) | urllib works for simple POSTs but lacks connection pooling, retry, and session management needed for reliable SIEM delivery. |

**Installation:**
```bash
# Core policy backends (new optional extras)
pip install "cloneguard[opa]"    # regopy>=1.3
pip install "cloneguard[cedar]"  # cedarpy>=4.8
pip install "cloneguard[spiffe]" # spiffe>=0.2.6

# SIEM connectors (new optional extras)
pip install "cloneguard[splunk]"    # requests>=2.31
pip install "cloneguard[sentinel]"  # azure-monitor-ingestion>=1.1,azure-identity>=1.15
pip install "cloneguard[chronicle]" # secops>=0.40

# Everything
pip install "cloneguard[governance]"  # all of the above
```

## Architecture Patterns

### Recommended Project Structure
```
src/cloneguard/
  enforcement/
    policy.py              # YAMLPolicyEngine (UNCHANGED -- canonical IR evaluator)
    types.py               # PolicyDecision, Constraints (UNCHANGED)
    adapter.py             # SandboxAdapter Protocol (UNCHANGED)
    backends/
      __init__.py          # PolicyBackend Protocol + get_policy_backend()
      opa.py               # OPAPolicyBackend -- Rego -> PolicyConfig compiler
      cedar.py             # CedarPolicyBackend -- Cedar -> PolicyConfig compiler
      yaml_backend.py      # YAMLPolicyBackend -- thin wrapper around existing engine
  audit/
    ndjson.py              # NDJSONEmitter (UNCHANGED)
    types.py               # AuditEvent (ADD agent_identity field for SPIFFE)
    otel.py                # OTelEmitter (UNCHANGED)
    connectors/
      __init__.py          # SIEMConnector Protocol + connector registry
      splunk.py            # SplunkHECConnector -- NDJSON -> HEC JSON
      sentinel.py          # SentinelConnector -- NDJSON -> DCR upload
      chronicle.py         # ChronicleConnector -- NDJSON -> UDM events
  identity/
    __init__.py            # get_agent_identity() entry point
    spiffe.py              # SPIFFEIdentityProvider -- WorkloadApiClient wrapper
    types.py               # AgentIdentity frozen dataclass
  fleet/                   # NOT Python code -- deployment artifacts
    ansible/
      roles/
        cloneguard/
          tasks/main.yml
          defaults/main.yml
          templates/
            policy.yaml.j2
            settings.json.j2
          handlers/main.yml
          meta/main.yml
    mdm/
      jamf/
        cloneguard-install.mobileconfig
        cloneguard-policy.mobileconfig
      intune/
        cloneguard-install.mobileconfig
        cloneguard-policy.mobileconfig
```

### Pattern 1: PolicyBackend Protocol (Compiler Pattern)

**What:** Each policy language has a backend that compiles its native syntax into the existing `PolicyConfig` Pydantic model. The `YAMLPolicyEngine.evaluate()` method remains the sole evaluation path.

**When to use:** When multiple input formats must produce identical enforcement behavior.

**Example:**
```python
# Source: Architecture from D-02 decision + existing enforcement/policy.py
from __future__ import annotations

from typing import Protocol, runtime_checkable

from cloneguard.enforcement.policy import PolicyConfig


@runtime_checkable
class PolicyBackend(Protocol):
    """Protocol for policy backends that compile to PolicyConfig IR."""

    @property
    def name(self) -> str:
        """Backend name for logging and audit."""
        ...

    def compile(self, source: str) -> PolicyConfig:
        """Parse native policy language and compile to PolicyConfig.

        Raises ValueError on parse/validation failure.
        """
        ...

    def validate(self, source: str) -> list[str]:
        """Validate policy syntax without compiling.

        Returns list of error messages (empty = valid).
        """
        ...
```

### Pattern 2: OPA Backend -- Rego to PolicyConfig Compilation

**What:** Evaluates a Rego module that produces a structured output matching PolicyConfig semantics, then maps the output to PolicyConfig fields.

**Example:**
```python
# Source: regopy API docs (microsoft.github.io/rego-cpp/python/api.html)
from regopy import Interpreter

class OPAPolicyBackend:
    """Compile OPA/Rego policy to PolicyConfig IR."""

    @property
    def name(self) -> str:
        return "opa"

    def compile(self, source: str) -> PolicyConfig:
        rego = Interpreter()
        rego.add_module("policy.rego", source)
        # Query the structured output that maps to PolicyConfig
        output = rego.query("data.cloneguard.policy")
        if not output.ok():
            msg = "Rego policy compilation failed"
            raise ValueError(msg)
        # Parse the JSON output into PolicyConfig
        policy_json = output.binding("policy").json()
        return PolicyConfig.from_yaml(policy_json)  # JSON is valid YAML
```

### Pattern 3: SIEM Connector Protocol (Transformer Pattern)

**What:** Each SIEM connector reads NDJSON events and transforms them to the SIEM's native format.

**Example:**
```python
# Source: Architecture from D-03/D-04 decisions
from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

from cloneguard.audit.types import AuditEvent


@runtime_checkable
class SIEMConnector(Protocol):
    """Protocol for SIEM connectors that transform NDJSON to native format."""

    @property
    def name(self) -> str: ...

    def transform(self, event: AuditEvent) -> dict[str, Any]:
        """Transform AuditEvent to SIEM-native format."""
        ...

    def send(self, events: list[AuditEvent]) -> bool:
        """Batch-send events to SIEM. Returns True on success."""
        ...
```

### Pattern 4: Splunk HEC Connector

**What:** Wraps AuditEvent in Splunk HEC JSON envelope and POSTs to /services/collector endpoint.

**Example:**
```python
# Source: Splunk HEC docs (docs.splunk.com)
# HEC envelope format:
{
    "time": 1712438400,           # epoch timestamp
    "sourcetype": "cloneguard",
    "source": "cloneguard:hooks",
    "host": "workstation-01",
    "event": {                    # AuditEvent fields nested here
        "schema_version": "cloneguard/event/v1",
        "verdict": "detected",
        "confidence": 0.95,
        "enforcement_action": "BLOCK",
        "agent_identity": "spiffe://cluster/agent/claude-code-01",
        ...
    }
}
# Multiple events concatenated (NO array, NO separator):
# {"event": "first"}{"event": "second"}{"event": "third"}
```

### Pattern 5: SPIFFE Identity Injection

**What:** At hook startup, attempt to fetch SPIFFE identity from the Workload API. If available, inject into every AuditEvent. Graceful degradation if SPIFFE is unavailable.

**Example:**
```python
# Source: spiffe PyPI docs + SPIFFE spec (spiffe.io/docs/latest)
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentIdentity:
    """SPIFFE-based agent identity for audit attribution."""
    spiffe_id: str = ""       # e.g., "spiffe://example.org/agent/claude-code-01"
    trust_domain: str = ""    # e.g., "example.org"
    available: bool = False


def get_agent_identity() -> AgentIdentity:
    """Fetch SPIFFE identity from Workload API, or return empty identity."""
    socket = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not socket:
        return AgentIdentity()
    try:
        from spiffe import WorkloadApiClient
        with WorkloadApiClient() as client:
            svid = client.fetch_x509_svid()
            spiffe_id = str(svid.spiffe_id)
            trust_domain = svid.spiffe_id.trust_domain
            return AgentIdentity(
                spiffe_id=spiffe_id,
                trust_domain=trust_domain,
                available=True,
            )
    except Exception:
        return AgentIdentity()
```

### Anti-Patterns to Avoid

- **Dual evaluation paths:** Never evaluate Rego/Cedar policies in their native engines AND the YAML engine. D-02 says YAML is canonical. OPA/Cedar compile TO YAML, then YAML evaluates. One evaluation path.
- **SIEM connectors on the hot path:** Connectors must NEVER block hook responses. NDJSON goes to file/stderr first (existing emitter), connectors read asynchronously or are a separate process.
- **SPIFFE blocking hook startup:** Identity fetch must have hard timeout (e.g., 1 second). Missing SPIFFE = empty identity, never an error.
- **Policy from repo paths:** D-02 from Phase 2: Policy config is NEVER loaded from repo-resident paths. This applies to OPA/Cedar policy files too -- they must come from `~/.cloneguard/` or operator-controlled paths.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Rego evaluation | Custom Rego parser | regopy Interpreter | Rego grammar is complex; regopy uses the same test suite as OPA |
| Cedar evaluation | Custom Cedar parser | cedarpy is_authorized | Cedar has formal verification properties; hand-rolling loses them |
| SPIFFE certificate management | Manual gRPC to Workload API | spiffe WorkloadApiClient | Handles certificate rotation, reconnection, bundle refresh automatically |
| Splunk HEC batching | Custom HTTP client | requests.Session with retry | Connection pooling, keep-alive, exponential backoff are non-trivial |
| Azure auth for Sentinel | Manual OAuth2 token flow | azure-identity DefaultAzureCredential | Handles managed identity, CLI credential, service principal chains |
| UDM event serialization | Manual JSON construction | secops library or official API schema | UDM schema is large and versioned; manual construction is error-prone |
| MDM .mobileconfig format | XML templating | Apple Configurator 2 or ProfileCreator output | .mobileconfig has XML signature requirements and payload type constraints |

**Key insight:** This phase integrates with enterprise infrastructure (OPA, Cedar, Splunk, Sentinel, Chronicle, SPIFFE, MDM). Every one of these has established libraries with edge case handling. The value is in the integration, not in reimplementing the protocol.

## Common Pitfalls

### Pitfall 1: OPA/Cedar Policy Semantics Mismatch
**What goes wrong:** Rego and Cedar have fundamentally different policy models. Rego is data-driven (rules produce documents), Cedar is request-driven (permit/forbid on principal-action-resource). Mapping both to the same YAML IR can lose semantic fidelity.
**Why it happens:** Trying to make the IR too generic or too specific to one model.
**How to avoid:** Design the compilation as "extract threshold/constraint values from the policy output" rather than "translate policy logic." The Rego module/Cedar policy set is the source of truth for *what values* to use, not *how to evaluate* them.
**Warning signs:** If the OPA backend needs to call `rego.query()` at evaluation time (not compile time), the abstraction is leaking.

### Pitfall 2: SIEM Connector Blocking Hook Responses
**What goes wrong:** SIEM endpoint is slow or down, connector blocks, hook invocation exceeds <20ms budget, agent hangs.
**Why it happens:** Putting SIEM delivery in the hook's synchronous path.
**How to avoid:** The existing architecture already handles this correctly: `NDJSONEmitter` writes to file/stderr, and SIEM connectors are a separate consumption path (CLI command, background daemon, or log shipper). Connectors must NEVER be called from `hooks.py._emit_audit_event()`.
**Warning signs:** Any import of connector modules inside hooks.py.

### Pitfall 3: regopy Built-in Limitations
**What goes wrong:** Rego policies using unsupported built-ins (glob.*, http.send, net.*, some crypto functions) fail silently or raise RegoError.
**Why it happens:** regopy supports "v1.8.0 of Rego" but not all built-ins. [CITED: microsoft.github.io/rego-cpp/python/api.html]
**How to avoid:** Document supported built-in subset. CloneGuard policies should only need comparison, object manipulation, and string operations -- no network or crypto built-ins. Validate at compile time and surface clear errors.
**Warning signs:** Users writing Rego policies that call http.send to fetch remote data.

### Pitfall 4: SPIFFE Socket Unavailable in Most Developer Environments
**What goes wrong:** SPIFFE_ENDPOINT_SOCKET is not set, WorkloadApiClient raises exception, hook crashes.
**Why it happens:** SPIFFE requires a running SPIRE agent. Most developer workstations don't have one.
**How to avoid:** Make SPIFFE identity 100% optional. If `SPIFFE_ENDPOINT_SOCKET` is not set, `AgentIdentity.available = False` and `spiffe_id = ""`. Never error on missing SPIFFE.
**Warning signs:** Tests that require SPIFFE_ENDPOINT_SOCKET to pass.

### Pitfall 5: MDM Profile Signing Requirements
**What goes wrong:** Unsigned .mobileconfig profiles trigger security warnings on macOS or are rejected by MDM platforms.
**Why it happens:** Apple requires profiles to be signed for silent deployment; Jamf signs automatically but Intune has specific requirements.
**How to avoid:** Ship unsigned profiles as templates with clear documentation: "Sign with your organization's certificate before deploying." Include a signing script or reference Apple's `security cms -S` command.
**Warning signs:** CI tests that try to install unsigned profiles on macOS.

### Pitfall 6: Ansible Idempotency Violations
**What goes wrong:** Ansible playbook re-runs overwrite user customizations to policy.yaml or break running CloneGuard processes.
**Why it happens:** Using `copy:` instead of `template:` with merge logic, or not checking if the service is already configured.
**How to avoid:** Use `template:` with Jinja2, check for existing config before overwriting (or merge), and use handlers for restart-on-change.
**Warning signs:** `changed` on every playbook run even when nothing actually changed.

### Pitfall 7: Sentinel DCR Table Schema Mismatch
**What goes wrong:** Custom table in Log Analytics rejects events because field names or types don't match the DCR stream definition.
**Why it happens:** DCR requires explicit column definitions; dynamic JSON fields get dropped.
**How to avoid:** Define a fixed schema for the CloneGuard custom table (CloneGuard_CL) that maps to AuditEvent fields. Ship the DCR ARM template alongside the connector config.
**Warning signs:** 400/422 errors from the Logs Ingestion API with "stream declaration missing" messages.

## Code Examples

### OPA/Rego Policy for CloneGuard
```rego
# Source: Architecture design for GOVN-01
# File: ~/.cloneguard/policy.rego
package cloneguard

# Thresholds configurable via data
default suspicious_floor = 0.3
default malicious_floor = 0.7

# Per-tool overrides
tool_thresholds["Write"]["suspicious_floor"] = 0.2
tool_thresholds["Write"]["malicious_floor"] = 0.5

# Enforcement rules
enforcement["suspicious"]["Write"] = {
    "filesystem_writable": ["${PROJECT_DIR}"],
    "filesystem_readable": ["${PROJECT_DIR}", "${VENV_DIR}"],
    "network_allow": []
}

# Output structure matching PolicyConfig
policy = {
    "version": "1",
    "verdicts": {
        "thresholds": {
            "suspicious_floor": suspicious_floor,
            "malicious_floor": malicious_floor
        },
        "overrides": {
            "tool_name": {k: {"suspicious_floor": v.suspicious_floor, "malicious_floor": v.malicious_floor} | k, v := tool_thresholds[k]}
        }
    },
    "enforcement": enforcement,
    "dry_run": false
}
```

### Cedar Policy for CloneGuard
```cedar
// Source: Architecture design for GOVN-02
// File: ~/.cloneguard/policy.cedar

// Block high-confidence malicious detections
forbid(
    principal,
    action == Action::"tool_call",
    resource
)
when {
    resource.confidence >= 0.7 &&
    resource.verdict == "detected"
};

// Constrain suspicious Write tool calls
permit(
    principal,
    action == Action::"tool_call",
    resource
)
when {
    resource.tool_name == "Write" &&
    resource.confidence >= 0.2 &&
    resource.verdict == "suspicious"
}
advice {
    "filesystem_writable": ["${PROJECT_DIR}"],
    "network_allow": []
};
```

### Splunk HEC Connector Config
```yaml
# Source: Splunk HEC docs (docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector)
# File: examples/siem/splunk-hec.yaml
connector: splunk_hec
endpoint: "https://splunk.example.com:8088/services/collector"
token_env: "CLONEGUARD_SPLUNK_HEC_TOKEN"  # Read from env, never in config
sourcetype: "cloneguard"
source: "cloneguard:hooks"
index: "security"
verify_ssl: true
batch_size: 10
flush_interval_seconds: 5
```

### Sentinel DCR Connector Config
```yaml
# Source: Azure Monitor Logs Ingestion API docs (learn.microsoft.com)
# File: examples/siem/sentinel-dcr.yaml
connector: sentinel_dcr
endpoint_env: "CLONEGUARD_SENTINEL_ENDPOINT"
rule_id_env: "CLONEGUARD_SENTINEL_RULE_ID"
stream_name: "Custom-CloneGuard_CL"
# Auth via DefaultAzureCredential (managed identity, CLI, service principal)
batch_size: 50
flush_interval_seconds: 10
```

### Ansible Role Usage
```yaml
# Source: Ansible best practices (docs.ansible.com)
# File: fleet/ansible/site.yml
---
- hosts: developer_workstations
  roles:
    - role: cloneguard
      vars:
        cloneguard_version: "0.6.0"
        cloneguard_policy_source: "files/policy.yaml"
        cloneguard_install_method: "uv"  # or "pipx"
        cloneguard_extras: ["mini", "opa"]
        cloneguard_hook_scope: "global"  # global or project
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| OPA server-based evaluation | regopy in-process (C++ FFI) | regopy 1.0.0 (2024) | No sidecar container, <5ms evaluation [ASSUMED] |
| Cedar proprietary AWS service | cedarpy open-source local eval | cedarpy 4.1.0 (2024) | Local evaluation, no AWS dependency [VERIFIED: PyPI] |
| Custom log shippers to SIEM | Structured NDJSON with tested connectors | Industry trend 2024-2025 | Standardized event format reduces integration cost [ASSUMED] |
| Manual fleet deployment | MDM + Ansible automation | Standard practice | Reproducible, auditable deployments [ASSUMED] |
| IP-based attribution | SPIFFE workload identity | SPIFFE v1.0 CNCF graduated (2022) | Cryptographic identity instead of network location [CITED: spiffe.io] |

**Deprecated/outdated:**
- **OPA REST API for policy evaluation:** Requires running OPA server. regopy provides in-process alternative. [VERIFIED: regopy PyPI]
- **Azure Log Analytics Data Collector API (legacy):** Microsoft recommends migration to DCR-based Logs Ingestion API. [CITED: learn.microsoft.com/en-us/azure/azure-monitor/logs/custom-logs-migrate]

## Assumptions Log

> List all claims tagged `[ASSUMED]` in this research. The planner and discuss-phase use this
> section to identify decisions that need user confirmation before execution.

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | azure-identity >=1.15 required by azure-monitor-ingestion | Standard Stack | Wrong minimum version could cause import errors; verify at install time |
| A2 | requests >=2.31 preferred over urllib for Splunk HEC | Standard Stack | urllib could work but lacks retry/pooling; low risk either way |
| A3 | regopy in-process evaluation takes <5ms | State of the Art | If slower, may need caching of compiled PolicyConfig; measure during implementation |
| A4 | Splunk HEC, Sentinel DCR, and Chronicle UDM API formats are stable and backward-compatible | SIEM Connectors | API changes could break connectors; mitigated by CI mock tests |
| A5 | secops 0.40.0 is appropriate for Chronicle UDM ingestion | Standard Stack | May need direct HTTP to batchCreate endpoint instead; verify secops API coverage |

## Open Questions

1. **regopy Rego v1.8.0 vs. current OPA v1.x**
   - What we know: regopy supports Rego "v1.8.0" [CITED: microsoft.github.io/rego-cpp]
   - What's unclear: Whether enterprise users will need features from newer Rego versions (e.g., v1 module syntax changes in OPA 1.0+)
   - Recommendation: Document supported Rego version. Ship example policies using only v0.x-compatible syntax. Monitor regopy releases for v1.0+ support.

2. **Cedar `advice` blocks for constraint extraction**
   - What we know: cedarpy exposes `is_authorized()` with `AuthzResult.decision` and diagnostics
   - What's unclear: Whether Cedar's `advice` mechanism (or annotations) is the right way to attach constraint data to permit decisions. Standard Cedar only has permit/forbid.
   - Recommendation: Use Cedar entity attributes to encode constraints rather than trying to use non-standard syntax. The Cedar policy determines allow/block; constraints come from entity data mapped to the tool.

3. **secops SDK vs. direct Chronicle Ingestion API**
   - What we know: `secops` 0.40.0 exists on PyPI with active releases [VERIFIED: PyPI]
   - What's unclear: Whether its UDM ingestion API wraps the batchCreate endpoint cleanly enough for our needs
   - Recommendation: Test secops first. If insufficient, fall back to direct HTTP to `malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate` with google-auth.

4. **MDM profile content scope**
   - What we know: .mobileconfig can install software, set preferences, configure shell environments
   - What's unclear: Whether MDM profiles should install CloneGuard (via embedded script) or only configure an already-installed CloneGuard
   - Recommendation: Ship two profiles per MDM: (1) install profile (triggers `uv tool install cloneguard`) and (2) config profile (provisions policy.yaml and hook settings). This separates concerns and matches fleet deployment patterns.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.11+ | All code | Yes | 3.13+ (macOS) | -- |
| regopy | GOVN-01 | Not installed | 1.3.0 on PyPI | Install via pip/uv |
| cedarpy | GOVN-02 | Not installed | 4.8.0 on PyPI | Install via pip/uv |
| spiffe | GOVN-06 | Not installed | 0.2.6 on PyPI | Install via pip/uv |
| SPIRE agent | GOVN-06 runtime | Not running | -- | AgentIdentity.available=False (graceful degradation) |
| Ansible | GOVN-05 development | Not installed | -- | Develop playbooks statically, test in CI with ansible-lint |
| Jamf Pro | GOVN-05 MDM | Not available | -- | Create .mobileconfig templates, test XML validity only |
| Splunk instance | GOVN-04 testing | Not available | -- | Mock HEC endpoint in CI tests |
| Azure Log Analytics | GOVN-04 testing | Not available | -- | Mock DCR endpoint in CI tests |
| Chronicle instance | GOVN-04 testing | Not available | -- | Mock UDM endpoint in CI tests |

**Missing dependencies with no fallback:**
- None -- all external services (SIEM, MDM, SPIFFE) have graceful degradation paths.

**Missing dependencies with fallback:**
- Ansible: Develop playbooks statically, validate with `ansible-lint` in CI
- SIEM instances: Mock endpoints in pytest (httpretty or responses library)
- SPIRE: Tests use mock WorkloadApiClient or skip with `@pytest.mark.spiffe`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes (SIEM connectors) | Token-from-env (Splunk HEC), DefaultAzureCredential (Sentinel), google-auth service account (Chronicle) |
| V3 Session Management | No | -- |
| V4 Access Control | Yes (policy evaluation) | PolicyConfig enforces thresholds; operator-controlled paths only (~/.cloneguard/) |
| V5 Input Validation | Yes (Rego/Cedar parsing) | regopy/cedarpy handle parsing; PolicyConfig Pydantic validation on compiler output |
| V6 Cryptography | Yes (SPIFFE) | spiffe library handles X.509/JWT SVIDs; no custom crypto |

### Known Threat Patterns for Enterprise Governance

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Policy file injection from repo | Tampering | Policy loaded only from operator paths (~/.cloneguard/), never CWD. Existing security check in policy.py line 160-163 |
| SIEM token exfiltration | Information Disclosure | Tokens read from env vars only, never from config files. Config files reference env var names, not values |
| SPIFFE SVID leakage in logs | Information Disclosure | Log SPIFFE ID only (public identifier), never X.509 private key material |
| Malicious Rego policy DoS | Denial of Service | regopy Interpreter has built-in timeouts; add explicit query timeout. Validate policy at compile time, not per-request |
| MDM profile tampering | Tampering | Ship unsigned templates; document signing requirement. MDM platforms verify profile signatures |
| Ansible playbook privilege escalation | Elevation of Privilege | Playbook uses `become: yes` only for package install, not for policy writing. Policy files owned by user, not root |

## Project Constraints (from CLAUDE.md)

Directives extracted from CLAUDE.md that constrain this phase:

- **No custom crypto:** Use battle-tested, audited, well-maintained libraries. spiffe, regopy, cedarpy all qualify.
- **Python 3.11+ strict typing:** All new code must use `from __future__ import annotations`, modern union syntax (`str | None`), 100% type annotations.
- **Ruff + mypy strict:** All new modules must pass `ruff check` (E, F, I, N, W, UP) and `mypy --strict`.
- **Never commit secrets:** SIEM tokens read from env vars only. Config files reference env var names.
- **Parameterized queries only:** Not directly applicable (no SQL) but principle applies: SIEM connector configs never interpolate credentials into URLs.
- **Minimum 80% coverage for business logic:** Policy backends and SIEM connectors need thorough test coverage.
- **Conventional commits:** `feat(governance): ...`, `test(governance): ...`, `docs(governance): ...`.
- **Gitignored dirs are sacred:** Fleet deployment templates go in `src/cloneguard/fleet/` (tracked) NOT `docs/plans/` (gitignored).
- **Authoritative sources only:** SIEM connector configs reference official vendor docs, not blog posts.
- **Frame as raising attacker cost:** Any documentation about policy enforcement must use defensive language.

## Sources

### Primary (HIGH confidence)
- [regopy PyPI](https://pypi.org/project/regopy/) - Version 1.3.0 verified, Python bindings for rego-cpp
- [cedarpy PyPI](https://pypi.org/project/cedarpy/) - Version 4.8.0 verified, Cedar policy evaluation
- [spiffe PyPI](https://pypi.org/project/spiffe/) - Version 0.2.6 verified, SPIFFE Workload API client
- [azure-monitor-ingestion PyPI](https://pypi.org/project/azure-monitor-ingestion/) - Version 1.1.0 verified
- [secops PyPI](https://pypi.org/project/secops/) - Version 0.40.0 verified, Google SecOps wrapper
- [regopy API docs](https://microsoft.github.io/rego-cpp/python/api.html) - Interpreter class, methods, error handling
- [cedarpy GitHub](https://github.com/k9securityio/cedar-py) - is_authorized, is_authorized_batch, validate_policies API
- [SPIFFE Workload Endpoint spec](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_endpoint/) - SPIFFE_ENDPOINT_SOCKET URI format
- Existing codebase: `enforcement/policy.py`, `enforcement/types.py`, `enforcement/adapter.py`, `audit/ndjson.py`, `audit/types.py`

### Secondary (MEDIUM confidence)
- [Splunk HEC docs](https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector) - Event format, batching, endpoints
- [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) - DCR-based ingestion
- [Chronicle Ingestion API](https://cloud.google.com/chronicle/docs/reference/ingestion-api) - UDM event format
- [HPE py-spiffe README](https://github.com/HewlettPackard/py-spiffe) - WorkloadApiClient usage examples
- [Jamf configuration profiles](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Computer_Configuration_Profiles.html) - MDM profile deployment

### Tertiary (LOW confidence)
- secops SDK coverage of UDM batchCreate API -- needs validation at implementation time
- Cedar `advice` block availability for constraint attachment -- needs API testing

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All library versions verified on PyPI, APIs confirmed via official docs
- Architecture: MEDIUM-HIGH - Pattern follows existing codebase conventions (Protocol-based, lazy loading, graceful degradation). OPA/Cedar compilation pattern is novel and needs validation
- Pitfalls: MEDIUM - Based on library documentation and enterprise integration experience. SIEM-specific pitfalls need validation against real instances
- Fleet deployment: MEDIUM - MDM and Ansible patterns are standard but CloneGuard-specific details are untested

**Research date:** 2026-04-06
**Valid until:** 2026-05-06 (30 days -- libraries are stable; SIEM APIs evolve slowly)
