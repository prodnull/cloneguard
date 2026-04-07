# Phase 6: Agent Expansion - Research

**Researched:** 2026-04-07
**Domain:** Agent-type-specific pattern libraries + additional sandbox adapters
**Confidence:** HIGH

## Summary

This phase has two independent workstreams: (1) four domain-specific pattern libraries for browser, autonomous, financial, and CI/CD agent types, and (2) four additional sandbox adapters (gVisor, Firecracker, WASM/Wasmtime, Docker) with auto-selection by isolation strength.

The pattern library work is well-constrained: the existing YAML rule format, PatternEngine loader, and evidence standard (D-09) define exact deliverables. The primary research contribution is mapping real-world attack techniques to regex-detectable patterns per agent domain, grounded in OWASP Agentic Top 10 (ASI01-ASI10), MITRE ATLAS v5.4.0, and published CVEs/incidents. Each domain has distinct attack surfaces but the rule format is identical.

The sandbox adapter work extends a well-defined Protocol interface. Docker is the most portable (available on dev machine, macOS + Linux), gVisor and Firecracker are Linux-only (gVisor via Docker --runtime=runsc, Firecracker via REST API to microVM), and WASM via Wasmtime Python bindings offers process-level sandboxing with capability-based security. All four implement the same `SandboxAdapter` Protocol with `restrict_filesystem`, `restrict_network`, `apply_restrictions`, and the deferred methods.

**Primary recommendation:** Build pattern libraries first (parallel, independent YAML files), then sandbox adapters (Docker first since it is available on the dev machine, then gVisor/Firecracker/WASM with Linux CI testing).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Tiered approach -- ship a seed library (~8 patterns per agent type) as core. Additional patterns available as optional expansion packs that operators can enable via policy.yaml. Keeps FPR tight on the default set.
- **D-02:** Strictly additive -- new rules only cover attacks unique to each agent domain. Existing patterns (exfiltration, credential_harvesting, cicd_poisoning, memory_poisoning, etc.) already fire for all agent types via fusion weights. No domain-specialized variants of existing rules.
- **D-03:** All four agent types (browser, autonomous, financial, CI/CD) developed in parallel. Pattern libraries are independent YAML files with no technical dependency between them.
- **D-04:** Per-agent-type subdirectories: `rules/browser/`, `rules/autonomous/`, `rules/financial/`, `rules/cicd/`. Matches the agent-type concept from Phase 3 input adapters. PatternEngine loader extended to scan subdirectories.
- **D-05:** Existing 27 YAML rules stay at `rules/` root -- they are coding-agent patterns and serve their current purpose. No migration of existing patterns. This avoids breaking existing pattern IDs and test references.
- **D-06:** Implement all four additional sandbox adapters: gVisor, Firecracker, WASM (Wasmtime/Wasmer), and Docker. Each conforms to the existing SandboxAdapter Protocol from Phase 2.
- **D-07:** Full enforcement depth for all adapters: `restrict_filesystem` + `restrict_network` + `restrict_syscalls`. Consistent with Landlock/Seatbelt depth from Phase 2.
- **D-08:** Auto-selection ranking by strongest isolation: Firecracker (VM) > gVisor (kernel) > Docker (container) > WASM (process) > Landlock/Seatbelt (OS) > Noop. Operator can override via `~/.cloneguard/policy.yaml`. Probe order at startup determines availability.
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

### Deferred Ideas (OUT OF SCOPE)
- Browser agent CDP input adapter (XDET-01) -- v2 requirement, beyond pattern library scope
- Autonomous agent SDK middleware adapters for LangChain/AutoGen/ADK/CrewAI (XDET-03) -- v2 requirement
- Financial agent custom API middleware (XDET-02) -- v2 requirement
- Windows AppContainer sandbox adapter (XPLT-01) -- v2 requirement
- User-provided ONNX model support (XDET-04) -- v2 requirement
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| AGNT-01 | Browser agent pattern library (DOM injection, invisible text, URL redirect) | OWASP ASI01/ASI02/ASI05; Palo Alto Unit 42 browser injection research; Brave Comet vulnerability disclosures; CSS concealment techniques catalog |
| AGNT-02 | Autonomous agent pattern library (goal hijacking, delegation abuse, memory poisoning) | OWASP ASI01/ASI03/ASI06/ASI10; EchoLeak incident; MITRE ATLAS AML.T0096 |
| AGNT-03 | Financial agent pattern library (transaction manipulation, approval bypass) | OWASP ASI01/ASI02/ASI09; $2.3M wire transfer incident; CVE-2025-12420 ServiceNow; F5 financial agent threat research |
| AGNT-04 | CI/CD agent pattern library (workflow injection, secret exfil, release poisoning) | CVE-2025-30066 tj-actions; CVE-2025-53104 gluestack-ui; OWASP ASI04/ASI05; existing CI-001 through CI-006 as reference |
| AGNT-05 | Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) with auto-selection | Docker SDK 7.1.0; wasmtime 43.0.0; gVisor runsc OCI runtime; Firecracker REST API; existing SandboxAdapter Protocol |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| docker (Python SDK) | 7.1.0 | Docker sandbox adapter -- container creation, filesystem/network restriction | Official Docker SDK; 7.1.0 is current PyPI release [VERIFIED: PyPI] |
| wasmtime | 43.0.0 | WASM sandbox adapter -- capability-based process-level sandboxing | Bytecode Alliance official Python bindings; 43.0.0 current [VERIFIED: PyPI] |
| pyyaml | >=6.0 | Pattern rule loading (existing dependency) | Already in project dependencies [VERIFIED: pyproject.toml] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| subprocess (stdlib) | - | gVisor adapter -- invoke `docker run --runtime=runsc` | When gVisor/runsc is available on Linux host |
| urllib.request (stdlib) | - | Firecracker adapter -- REST API to Firecracker VMM socket | When Firecracker binary available on Linux host |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| wasmtime | wasmer | Wasmer has Python bindings too but wasmtime has broader community, Bytecode Alliance backing, and better WASI support |
| docker (Python SDK) | subprocess docker CLI | SDK provides typed API, container lifecycle management; CLI is simpler but less robust error handling |
| firecracker-python SDK | Direct REST API via urllib | SDK is v0.0.5 pre-release with limited features [VERIFIED: GitHub]; direct REST API via Unix socket is more reliable |

**Installation:**
```bash
uv pip install "docker>=7.1" "wasmtime>=43.0"
```

**pyproject.toml extras:**
```toml
[project.optional-dependencies]
docker = ["docker>=7.1"]
wasm = ["wasmtime>=43.0"]
sandbox = ["docker>=7.1", "wasmtime>=43.0"]
```

## Architecture Patterns

### Recommended Project Structure
```
src/cloneguard/
├── rules/                          # Existing 25 root-level YAML rules (UNTOUCHED per D-05)
│   ├── browser/                    # NEW: Browser agent patterns
│   │   ├── dom_injection.yaml
│   │   └── url_redirect.yaml
│   ├── autonomous/                 # NEW: Autonomous agent patterns
│   │   ├── goal_hijacking.yaml
│   │   └── delegation_abuse.yaml
│   ├── financial/                  # NEW: Financial agent patterns
│   │   ├── transaction_manipulation.yaml
│   │   └── approval_bypass.yaml
│   └── cicd/                       # NEW: CI/CD agent patterns (distinct from root cicd_poisoning.yaml)
│       ├── workflow_injection.yaml
│       └── release_poisoning.yaml
├── enforcement/
│   ├── adapter.py                  # MODIFY: Add new adapter entries to _ADAPTER_REGISTRY
│   ├── docker_adapter.py           # NEW: Docker sandbox adapter
│   ├── gvisor_adapter.py           # NEW: gVisor sandbox adapter
│   ├── firecracker_adapter.py      # NEW: Firecracker sandbox adapter
│   └── wasm_adapter.py             # NEW: WASM/Wasmtime sandbox adapter
└── patterns.py                     # MODIFY: PatternEngine to scan subdirectories
docs/
└── threats/                        # NEW: Threat catalog documents per D-11
    ├── browser.md
    ├── autonomous.md
    ├── financial.md
    └── cicd.md
```

### Pattern 1: PatternEngine Subdirectory Scanning
**What:** Extend `PatternEngine.__init__` to recursively scan `rules/` subdirectories for YAML files.
**When to use:** Always -- this is the core extension point for D-04.
**Example:**
```python
# Source: existing patterns.py line 116, extended for subdirectories
class PatternEngine:
    def __init__(self, rules_dir: Path | None = None) -> None:
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"
        self._compiled_rules: list[_CompiledRule] = []
        self._raw_rules: list[dict[str, Any]] = []
        if not rules_dir.is_dir():
            return
        # Load root-level rules (existing behavior)
        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            self._load_rule_file(yaml_file)
        # Load subdirectory rules (new behavior per D-04)
        for subdir in sorted(rules_dir.iterdir()):
            if subdir.is_dir() and not subdir.name.startswith((".", "_")):
                for yaml_file in sorted(subdir.glob("*.yaml")):
                    self._load_rule_file(yaml_file)
```
[VERIFIED: patterns.py source code in codebase]

### Pattern 2: Sandbox Adapter Implementation
**What:** Each new adapter follows the same Protocol pattern as LandlockAdapter/SeatbeltAdapter.
**When to use:** For all four new adapters.
**Example:**
```python
# Source: existing adapter.py Protocol + landlock.py reference implementation
class DockerAdapter:
    """Docker container sandbox adapter.
    
    Creates an ephemeral container with restricted filesystem mounts
    and network mode. apply_restrictions() is a no-op because Docker
    restrictions are applied at container creation time, not to the
    current process. Instead, the sandbox_exec wrapper uses
    docker run with the constraint spec.
    """
    def __init__(self) -> None:
        self._writable: list[str] = []
        self._readable: list[str] = []
        self._network_allow: list[str] = []

    @property
    def name(self) -> str:
        return "docker"

    def restrict_filesystem(self, writable, readable, executable_writable=None):
        self._writable = list(writable)
        self._readable = list(readable)

    def restrict_network(self, allow):
        self._network_allow = list(allow)

    def apply_restrictions(self) -> None:
        # Docker restrictions applied at container creation, not via
        # self-restriction. sandbox_exec builds docker run command
        # from serialized constraints.
        pass

    def serialize_constraints(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "writable": self._writable,
            "readable": self._readable,
            "network_allow": self._network_allow,
        }
```
[VERIFIED: Protocol shape from adapter.py in codebase]

### Pattern 3: Adapter Registry Extension
**What:** Insert new adapters into `_ADAPTER_REGISTRY` in strength order per D-08.
**When to use:** When adding new adapters to auto-selection.
**Example:**
```python
# Source: adapter.py line 190-193, extended per D-08
_ADAPTER_REGISTRY: list[tuple[str, Any, str]] = [
    ("firecracker", _probe_firecracker, "cloneguard.enforcement.firecracker_adapter"),
    ("gvisor", _probe_gvisor, "cloneguard.enforcement.gvisor_adapter"),
    ("docker", _probe_docker, "cloneguard.enforcement.docker_adapter"),
    ("wasm", _probe_wasm, "cloneguard.enforcement.wasm_adapter"),
    ("landlock", _probe_landlock, "cloneguard.enforcement.landlock"),
    ("seatbelt", _probe_seatbelt, "cloneguard.enforcement.seatbelt"),
]
```
[VERIFIED: _ADAPTER_REGISTRY structure from adapter.py]

### Pattern 4: Expansion Pack Loading via Policy
**What:** Optional pattern packs enabled via `~/.cloneguard/policy.yaml` configuration.
**When to use:** For patterns that meet quality bar but not evidence standard (D-10).
**Example:**
```yaml
# ~/.cloneguard/policy.yaml
expansion_packs:
  browser:
    enabled: true
  autonomous:
    enabled: false
  financial:
    enabled: true
  cicd:
    enabled: true
```
The PatternEngine checks policy config and conditionally loads `rules/{agent_type}/expansion/` subdirectories when enabled.
[ASSUMED]

### Anti-Patterns to Avoid
- **Duplicating existing rules in agent-type subdirectories:** D-02 is explicit -- new rules are strictly additive. Existing exfiltration, credential_harvesting, memory_poisoning patterns already fire for all agent types via fusion weights. Do not create browser-specific variants of EX-001 or MP-001.
- **Coupling pattern libraries to each other:** D-03 specifies no technical dependency between agent-type libraries. Each subdirectory is independently loadable.
- **Applying Docker restrictions to the current process:** Docker operates differently from Landlock/Seatbelt. Restrictions are applied at container creation time (`docker run` flags), not via self-restriction syscalls. The `apply_restrictions()` method for Docker must create/configure a container, not restrict the calling process.
- **Blocking on sandbox startup probes:** Auto-selection probes should be fast (check binary existence, not full capability test). Use `shutil.which()` for CLI probes. Fail fast, never block.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Docker container management | Custom Docker socket HTTP client | `docker` Python SDK 7.1.0 | Container lifecycle, volume mounts, network modes -- hundreds of edge cases |
| WASM capability sandboxing | Custom WASM runtime integration | `wasmtime` Python package 43.0.0 | WASI filesystem/network capability model is complex; Wasmtime handles it |
| Firecracker VM management | Full VM lifecycle from scratch | Firecracker REST API via Unix socket | Well-documented OpenAPI spec; no need for third-party SDK (v0.0.5 is immature) |
| gVisor integration | Custom OCI runtime shim | `docker run --runtime=runsc` | gVisor's runsc is an OCI runtime; Docker handles the integration |
| YAML rule schema validation | Custom validator | Existing `_load_rule_file()` pattern | Already validates id, regex, severity, description fields |

**Key insight:** All four sandbox adapters orchestrate existing isolation technologies. CloneGuard NEVER builds sandbox primitives -- it configures and invokes established sandboxes through their native APIs, exactly as designed (PROJECT.md: "Orchestrate existing sandboxes via adapters; don't maintain OS-level security primitives").

## Common Pitfalls

### Pitfall 1: Docker apply_restrictions() Architectural Mismatch
**What goes wrong:** Attempting to apply Docker restrictions to the current process (like Landlock/Seatbelt do) fails because Docker isolates via container creation, not process-level self-restriction.
**Why it happens:** Following Landlock/Seatbelt reference implementations too literally.
**How to avoid:** Docker adapter's `apply_restrictions()` must be a no-op (or raise if called directly). The real restriction happens in `sandbox_exec.py` which builds a `docker run` command from serialized constraints. The `sandbox_exec.py` must be extended to handle `adapter: "docker"` differently from `adapter: "landlock"/"seatbelt"`.
**Warning signs:** Tests pass locally but enforcement doesn't actually restrict the subprocess.

### Pitfall 2: Pattern ID Collisions Between Agent Types
**What goes wrong:** Two agent types using the same pattern ID prefix (e.g., both browser and financial use "FIN-001").
**Why it happens:** No enforced ID namespace convention.
**How to avoid:** Use clear prefixes: `BRW-` (browser), `AUT-` (autonomous), `FIN-` (financial), `CIC-` (CI/CD). Existing root patterns use `CI-`, `MP-`, `MCP-`, `EX-`, etc. -- new prefixes must not collide.
**Warning signs:** Test assertions fail with wrong pattern matching, or pattern counts are off.

### Pitfall 3: gVisor/Firecracker Linux-Only Probes on macOS
**What goes wrong:** Probe functions for Linux-only adapters crash or hang on macOS during testing.
**Why it happens:** Probing for `runsc` binary or Firecracker socket on a macOS machine.
**How to avoid:** Every probe function must check `sys.platform` first (as existing `_probe_landlock()` does). Return `False` immediately on unsupported platforms.
**Warning signs:** Test suite hangs or crashes on macOS CI.

### Pitfall 4: sandbox_exec.py Must Handle Docker/WASM Differently
**What goes wrong:** The existing `sandbox_exec.py` pattern of "apply restrictions to self, then exec" doesn't work for Docker (needs container creation) or WASM (needs module loading).
**Why it happens:** Current architecture assumes restrictions persist across exec. Docker and WASM have different execution models.
**How to avoid:** Extend `sandbox_exec.py` with adapter-specific execution paths. For Docker: build `docker run` command. For WASM: load module into Wasmtime engine. For gVisor: use `docker run --runtime=runsc`. For Firecracker: POST to VMM API.
**Warning signs:** `sandbox_exec.py` grows unwieldy with if/else chains. Consider adapter method `execute_sandboxed(target_cmd)` to push dispatch into adapter classes.

### Pitfall 5: Expansion Pack Loading Breaks Pattern Count Tests
**What goes wrong:** Enabling/disabling expansion packs changes the total pattern count, breaking existing tests that assert exact counts.
**Why it happens:** Tests assume a fixed number of patterns loaded.
**How to avoid:** Tests for agent-type patterns should test per-subdirectory counts, not total. Existing test_patterns.py and test_full_pattern_coverage.py likely assert total rule counts -- these need updating.
**Warning signs:** CI failures when new YAML files are added to subdirectories.

### Pitfall 6: Firecracker Requires KVM
**What goes wrong:** Firecracker adapter fails silently because KVM is not available in containers or on macOS.
**Why it happens:** Firecracker requires `/dev/kvm` for hardware virtualization.
**How to avoid:** Probe checks for `/dev/kvm` existence and Firecracker binary. Document that Firecracker sandbox is Linux-bare-metal only. CI tests for Firecracker need a KVM-enabled runner.
**Warning signs:** Adapter probe always returns False in CI/CD environments.

## Code Examples

### Browser Agent Pattern (DOM Injection Detection)
```yaml
# Source: Palo Alto Unit 42 research + Brave Comet vulnerability disclosures
# rules/browser/dom_injection.yaml
category: browserDomInjection
description: "Patterns detecting DOM-based prompt injection in browser agent contexts"
patterns:
  - id: BRW-001
    regex: '(?i)(?:font-size\s*:\s*0|opacity\s*:\s*0|visibility\s*:\s*hidden|display\s*:\s*none|position\s*:\s*absolute\s*;\s*(?:left|top)\s*:\s*-\d{3,})'
    severity: high
    description: "CSS-based text concealment -- invisible instructions in DOM"
    evidence: "Unit42: Web-based indirect prompt injection uses opacity:0, font-size:0, position:absolute with extreme negative coords"
    false_positive_hint: "Legitimate CSS may use display:none for responsive layouts -- flag for review in browser agent context"
```
[CITED: unit42.paloaltonetworks.com/ai-agent-prompt-injection/]

### Financial Agent Pattern (Transaction Manipulation)
```yaml
# Source: 2024 wire transfer incident, CVE-2025-12420 ServiceNow
# rules/financial/transaction_manipulation.yaml
category: financialTransactionManipulation
description: "Patterns detecting transaction manipulation in financial agent contexts"
patterns:
  - id: FIN-001
    regex: '(?i)(?:(?:approve|authorize|process|execute|confirm)\s+(?:all\s+)?(?:wire|transfer|payment|transaction)s?\b.{0,60}(?:override|bypass|skip|ignore)\s+(?:approval|verification|limit|threshold))'
    severity: critical
    description: "Instruction to process financial transaction while bypassing approval controls"
    evidence: "2024 financial institution incident: hidden instructions caused AI to approve $2.3M in fraudulent wire transfers"
    false_positive_hint: "Financial process documentation may discuss approval workflows"
```
[CITED: databahn.ai/blog/ai-agents-security-incidents]

### Docker Adapter Probe Function
```python
# Source: existing _probe_landlock() and _probe_seatbelt() patterns in adapter.py
def _probe_docker() -> bool:
    """Check if Docker daemon is available."""
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        client.ping()
        return True
    except Exception:
        return False
```
[VERIFIED: probe pattern from adapter.py in codebase]

### gVisor Adapter Probe Function
```python
# Source: gVisor docs (gvisor.dev/docs/user_guide/quick_start/docker/)
import shutil
import subprocess

def _probe_gvisor() -> bool:
    """Check if gVisor runsc runtime is available via Docker."""
    import sys
    if sys.platform != "linux":
        return False
    if not shutil.which("runsc"):
        return False
    # Verify runsc is registered as a Docker runtime
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.Runtimes}}"],
            capture_output=True, text=True, timeout=5
        )
        return "runsc" in result.stdout
    except Exception:
        return False
```
[CITED: gvisor.dev/docs/user_guide/quick_start/docker/]

### WASM Adapter Probe Function
```python
def _probe_wasm() -> bool:
    """Check if wasmtime Python bindings are available."""
    try:
        import wasmtime
        # Verify engine can be created
        engine = wasmtime.Engine()
        return engine is not None
    except ImportError:
        return False
    except Exception:
        return False
```
[ASSUMED -- based on wasmtime-py API docs pattern]

## Agent-Type Threat Catalog (Research Foundation for D-11)

### Browser Agent Attacks
| Attack Class | OWASP ASI | MITRE ATLAS | Evidence | Seed Pattern? |
|-------------|-----------|-------------|----------|---------------|
| Invisible text (opacity:0, font-size:0) | ASI01 | AML.T0051 | Unit42 in-wild detection, Brave Comet disclosure | YES |
| Off-screen positioning (left:-9999px) | ASI01 | AML.T0051 | Unit42 CSS concealment catalog | YES |
| Base64-encoded runtime assembly | ASI01, ASI05 | AML.T0051 | Unit42 obfuscation techniques | YES |
| SVG/XML CDATA payload embedding | ASI01 | AML.T0051 | Unit42 HTML attribute cloaking | YES |
| URL redirect to attacker-controlled page | ASI02 | AML.T0051 | Brave Comet, Fellou browser vuln | YES |
| Screenshot OCR poisoning | ASI01 | - | Brave unseeable injection research | YES |
| HTML attribute instruction cloaking | ASI01 | AML.T0051 | Unit42 documented technique | YES |
| JavaScript event handler injection | ASI05 | AML.T0051 | General web security, OWASP XSS | YES |

### Autonomous Agent Attacks
| Attack Class | OWASP ASI | MITRE ATLAS | Evidence | Seed Pattern? |
|-------------|-----------|-------------|----------|---------------|
| Goal hijacking via injected objectives | ASI01 | AML.T0051 | EchoLeak incident, OWASP ASI01 | YES |
| Delegation chain abuse | ASI03 | - | OWASP ASI03 confused deputy | YES |
| Cross-agent instruction injection | ASI07 | AML.T0096 | OWASP ASI07, SesameOp case study | YES |
| Reward/objective function manipulation | ASI10 | - | OWASP ASI10 rogue agents | YES |
| Agent identity spoofing | ASI03 | - | OWASP ASI03 impersonation | YES |
| Cascading failure trigger | ASI08 | - | OWASP ASI08 cascade patterns | YES |
| Persistent instruction via memory store | ASI06 | AML.T0051 | Existing MP-001/002, extended scope | YES (additive) |
| Tool chain abuse (unsafe composition) | ASI02 | - | OWASP ASI02 tool misuse | YES |

### Financial Agent Attacks
| Attack Class | OWASP ASI | MITRE ATLAS | Evidence | Seed Pattern? |
|-------------|-----------|-------------|----------|---------------|
| Transaction approval bypass | ASI01, ASI09 | - | $2.3M wire transfer incident | YES |
| Amount/recipient manipulation | ASI01 | - | F5 financial agent threat research | YES |
| Reconciliation data exfiltration | ASI02 | AML.T0051 | Reconciliation agent regex incident | YES |
| Approval threshold override | ASI01, ASI03 | - | CVE-2025-12420 ServiceNow bypass | YES |
| Fraudulent transaction authorization framing | ASI09 | - | OWASP ASI09 trust exploitation | YES |
| Audit trail suppression | ASI01 | - | General financial security, SOX/PCI | YES |
| Rate limit/velocity check bypass | ASI02 | - | F5 agentic AI banking threats | YES |
| Currency/account ID substitution | ASI01 | - | General financial fraud patterns | YES |

### CI/CD Agent Attacks
| Attack Class | OWASP ASI | MITRE ATLAS | Evidence | Seed Pattern? |
|-------------|-----------|-------------|----------|---------------|
| Workflow file injection | ASI04, ASI05 | AML.T0051 | CVE-2025-30066 tj-actions supply chain | YES |
| Secret exfiltration via log dump | ASI02 | - | CVE-2025-30066 memory dump technique | YES |
| Release artifact poisoning | ASI04 | - | reviewdog/action-setup cascade attack | YES |
| Runner escape to host | ASI05 | AML.T0096 | MITRE ATLAS "Escape to Host" technique | YES |
| Mutable tag pinning (non-SHA) | ASI04 | - | CVE-2025-30066 tag modification vector | YES |
| CI token in network request | ASI02, ASI03 | - | Existing CI-003, extended scope | YES (additive) |
| Dynamic action download | ASI04 | - | OWASP ASI04 supply chain | YES |
| Pipeline variable injection | ASI05 | - | CVE-2025-53104 gluestack-ui | YES |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Agent-agnostic pattern matching only | Domain-specific pattern libraries with agent-type context | OWASP Agentic Top 10, Dec 2025 | Agents have fundamentally different attack surfaces by domain |
| Binary allow/block sandbox | Multi-tier sandbox with auto-selection by strength | 2025-2026 agent sandbox trend | Different deployment contexts need different isolation levels |
| Docker container as strongest sandbox | Firecracker microVM as gold standard for agent isolation | Northflank/AWS 2025 | VM isolation is stronger than container namespace isolation |
| WASM for browser-only | WASM/WASI for server-side process sandboxing | Wasmtime 2025 maturity | Capability-based security model fits agent tool restriction |

**Deprecated/outdated:**
- firecracker-python SDK v0.0.5 is pre-release and limited -- prefer direct REST API via Unix socket [VERIFIED: GitHub]
- Apple sandbox-exec CLI is deprecated but sandbox_init_with_parameters (used by SeatbeltAdapter) remains functional [VERIFIED: codebase seatbelt.py]

## Assumptions Log

> List all claims tagged `[ASSUMED]` in this research.

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Expansion pack loading via `rules/{agent_type}/expansion/` subdirectory pattern | Architecture Patterns | Low -- alternative: separate `expansion/` top-level directory or policy-keyed loading. Implementation detail within Claude's discretion. |
| A2 | WASM adapter probe works by instantiating `wasmtime.Engine()` | Code Examples | Low -- verified pattern from wasmtime-py docs; actual API may differ in v43 |
| A3 | Docker adapter's `apply_restrictions()` is a no-op with execution handled by sandbox_exec | Architecture Patterns | Medium -- if sandbox_exec can't dispatch to Docker, the entire Docker adapter is non-functional. Design must be validated. |

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker | Docker adapter, gVisor adapter | YES | 29.3.0 | -- |
| docker (Python SDK) | Docker adapter | NO (not installed) | -- | `uv pip install docker` |
| wasmtime (Python) | WASM adapter | NO (not installed) | -- | `uv pip install wasmtime` |
| gVisor (runsc) | gVisor adapter | NO | -- | Linux-only; test in Docker/CI |
| Firecracker | Firecracker adapter | NO | -- | Linux-only + KVM; test in CI with KVM runner |
| Python | All | YES | 3.14.3 | -- |
| /dev/kvm | Firecracker | NO (macOS) | -- | Firecracker tests Linux-only |

**Missing dependencies with no fallback:**
- gVisor and Firecracker are Linux-only and require specific host capabilities. Cannot be tested locally on macOS. Must use Linux CI runners. This is expected and acceptable -- adapters gracefully degrade to NoopAdapter when unavailable.

**Missing dependencies with fallback:**
- `docker` and `wasmtime` Python packages: installable via `uv pip install docker wasmtime`. Not blocking.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest >=8.0 |
| Config file | `pyproject.toml` [tool.pytest.ini_options] |
| Quick run command | `python -m pytest tests/ -x -q --timeout=30` |
| Full suite command | `python -m pytest tests/ -v` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AGNT-01 | Browser patterns detect DOM injection, invisible text, URL redirect | unit | `pytest tests/test_browser_patterns.py -x` | No -- Wave 0 |
| AGNT-02 | Autonomous patterns detect goal hijacking, delegation abuse, memory poisoning | unit | `pytest tests/test_autonomous_patterns.py -x` | No -- Wave 0 |
| AGNT-03 | Financial patterns detect transaction manipulation, approval bypass | unit | `pytest tests/test_financial_patterns.py -x` | No -- Wave 0 |
| AGNT-04 | CI/CD patterns detect workflow injection, secret exfil, release poisoning | unit | `pytest tests/test_cicd_agent_patterns.py -x` | No -- Wave 0 |
| AGNT-05 | Docker/gVisor/Firecracker/WASM adapters conform to SandboxAdapter Protocol | unit + integration | `pytest tests/test_sandbox_adapters.py -x` | No -- Wave 0 |
| AGNT-05 | Auto-selection ranks adapters by strength | unit | `pytest tests/test_sandbox_adapters.py::test_auto_selection -x` | No -- Wave 0 |
| D-04 | PatternEngine loads subdirectory YAML files | unit | `pytest tests/test_patterns.py -x -k subdirectory` | No -- Wave 0 |
| D-09 | Every seed pattern has evidence citation | unit | `pytest tests/test_pattern_evidence.py -x` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `python -m pytest tests/ -x -q --timeout=30`
- **Per wave merge:** `python -m pytest tests/ -v`
- **Phase gate:** Full suite green + `ruff check` + `mypy` before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_browser_patterns.py` -- AGNT-01 pattern detection coverage
- [ ] `tests/test_autonomous_patterns.py` -- AGNT-02 pattern detection coverage
- [ ] `tests/test_financial_patterns.py` -- AGNT-03 pattern detection coverage
- [ ] `tests/test_cicd_agent_patterns.py` -- AGNT-04 pattern detection coverage
- [ ] `tests/test_sandbox_adapters.py` -- AGNT-05 adapter Protocol conformance + auto-selection
- [ ] `tests/test_pattern_evidence.py` -- D-09 evidence standard enforcement
- [ ] `tests/test_subdirectory_loading.py` -- D-04 PatternEngine subdirectory scanning

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | -- (adapters don't authenticate) |
| V3 Session Management | No | -- |
| V4 Access Control | Yes | Sandbox adapters enforce least-privilege filesystem/network |
| V5 Input Validation | Yes | YAML rule regex validation; adapter constraint input validation |
| V6 Cryptography | No | -- |

### Known Threat Patterns for Agent Expansion

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Regex ReDoS in new patterns | Denial of Service | Test all regex with ReDoS checker; avoid catastrophic backtracking |
| YAML rule injection via expansion packs | Tampering | Expansion packs loaded only from package-shipped paths, not user-writable |
| Docker container escape | Elevation of Privilege | Use `--read-only`, `--network none`, `--cap-drop ALL`, resource limits |
| Firecracker API socket access | Information Disclosure | Socket restricted to CloneGuard process; no exposure to sandboxed command |
| gVisor runsc bypass via OCI spec manipulation | Elevation of Privilege | Pin Docker runtime config; don't pass user-controlled OCI specs |
| WASM module loading from untrusted source | Tampering | Only load CloneGuard-shipped WASM modules; no user-provided modules |

## Open Questions

1. **sandbox_exec.py extension for Docker/WASM execution model**
   - What we know: Current sandbox_exec applies restrictions to self then exec's target. Docker and WASM don't work this way.
   - What's unclear: Should sandbox_exec.py grow adapter-specific branches, or should each adapter implement an `execute_sandboxed(cmd)` method?
   - Recommendation: Add `execute_sandboxed(target_cmd: list[str]) -> None` to SandboxAdapter Protocol. Default implementation does the existing apply+exec pattern. Docker/WASM/gVisor/Firecracker override with their specific execution model. This is cleaner than if/else chains in sandbox_exec.py.

2. **Expansion pack delivery mechanism**
   - What we know: D-10 says expansion patterns enabled via policy.yaml. D-04 says subdirectories under rules/.
   - What's unclear: Are expansion patterns shipped in the package but disabled by default, or distributed separately?
   - Recommendation: Ship in-package under `rules/{agent_type}/expansion/*.yaml`. Loaded only when policy.yaml enables them. Simpler distribution than separate packages.

3. **CI/CD agent patterns vs existing cicd_poisoning.yaml**
   - What we know: D-02 says strictly additive, D-05 says existing rules stay at root.
   - What's unclear: How to avoid semantic overlap between root `cicd_poisoning.yaml` (CI-001 through CI-006) and new `rules/cicd/` patterns.
   - Recommendation: New CI/CD agent patterns (CIC-xxx) focus on CI/CD-specific agent autonomy attacks (e.g., agent self-modifying workflows, release signing bypass, ephemeral runner escape) distinct from the existing CI-001..006 which cover workflow file injection patterns. Cross-reference in threat catalog.

## Sources

### Primary (HIGH confidence)
- Codebase: `src/cloneguard/enforcement/adapter.py` -- SandboxAdapter Protocol, _ADAPTER_REGISTRY, probe functions
- Codebase: `src/cloneguard/enforcement/landlock.py` -- Reference adapter implementation
- Codebase: `src/cloneguard/enforcement/seatbelt.py` -- Reference adapter implementation
- Codebase: `src/cloneguard/enforcement/sandbox_exec.py` -- Sandbox execution wrapper architecture
- Codebase: `src/cloneguard/patterns.py` -- PatternEngine loader, _CompiledRule, subdirectory extension point
- Codebase: `src/cloneguard/rules/cicd_poisoning.yaml` -- Existing CI/CD patterns (avoid overlap)
- Codebase: `src/cloneguard/rules/memory_poisoning.yaml` -- Existing memory poisoning (avoid overlap)
- Codebase: `src/cloneguard/enforcement/policy.py` -- PolicyConfig, policy.yaml loading
- PyPI: docker 7.1.0 (verified via PyPI JSON API)
- PyPI: wasmtime 43.0.0 (verified via PyPI JSON API)

### Secondary (MEDIUM confidence)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) -- ASI01-ASI10 attack taxonomy
- [Palo Alto Unit 42: Web-based Indirect Prompt Injection](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) -- Browser agent CSS concealment techniques
- [Brave: Unseeable prompt injections in screenshots](https://brave.com/blog/unseeable-prompt-injections/) -- Browser agent screenshot/OCR attacks
- [Brave: Agentic Browser Security](https://brave.com/blog/comet-prompt-injection/) -- Perplexity Comet vulnerability
- [CVE-2025-30066: tj-actions/changed-files supply chain attack](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3) -- CI/CD secret exfiltration via GitHub Actions
- [CVE-2025-53104: gluestack-ui workflow injection](https://webflow.sysdig.com/blog/cve-2025-53104-command-injection-via-github-actions-workflow-in-gluestack-ui) -- CI/CD command injection
- [CVE-2025-12420: ServiceNow BodySnatcher](https://appomni.com/ao-labs/bodysnatcher-agentic-ai-security-vulnerability-in-servicenow/) -- Agentic hijacking with approval bypass
- [DataBahn: AI Agents Security Incidents and CVEs](https://www.databahn.ai/blog/ai-agents-security-incidents-and-related-cves-for-enterprise-security-teams) -- Financial agent $2.3M incident
- [F5: Agentic AI Security Vulnerabilities in Banking](https://www.f5.com/resources/articles/top-agentic-ai-security-vulnerabilities-in-banking) -- Financial agent threat research
- [MITRE ATLAS v5.4.0](https://atlas.mitre.org/) -- Adversarial ML technique framework including AML.T0096
- [gVisor documentation](https://gvisor.dev/docs/) -- runsc OCI runtime integration
- [Firecracker getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md) -- REST API architecture
- [Wasmtime Python API docs](https://bytecodealliance.github.io/wasmtime-py/) -- Python bindings reference
- [Docker SDK for Python 7.1.0 docs](https://docker-py.readthedocs.io/) -- Container management API

### Tertiary (LOW confidence)
- [firecracker-python v0.0.5](https://github.com/myugan/firecracker-python) -- Community Python SDK, pre-release (prefer direct REST API)
- [Northflank: How to sandbox AI agents in 2026](https://northflank.com/blog/how-to-sandbox-ai-agents) -- Industry sandbox comparison

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- Docker SDK and wasmtime verified on PyPI; gVisor/Firecracker use stdlib (subprocess/urllib)
- Architecture: HIGH -- Extends well-defined Protocol interface and PatternEngine loader; reference implementations in codebase
- Pattern libraries: HIGH -- Attack taxonomy grounded in OWASP Agentic Top 10, MITRE ATLAS, published CVEs
- Pitfalls: HIGH -- Derived from codebase analysis of existing adapter pattern and sandbox_exec architecture

**Research date:** 2026-04-07
**Valid until:** 2026-05-07 (stable domain -- OWASP/MITRE taxonomies update quarterly)
