# Stack Research

**Domain:** Universal agentic defense layer -- sandbox orchestration, policy evaluation, multi-format compliance output, multi-agent-type input adapters
**Researched:** 2026-04-05
**Confidence:** MEDIUM-HIGH (versions verified via PyPI; some libraries are young or alpha-quality)

## Competitive Context

Microsoft released the Agent Governance Toolkit (AGT) on 2026-04-02 -- three days before this research. AGT is a seven-package MIT-licensed toolkit covering all 10 OWASP Agentic Top 10 risks with sub-millisecond policy enforcement. AWS Bedrock AgentCore Policy (Cedar-based) went GA on 2026-03-03 across 13 regions. These are the two 800-pound gorillas. CloneGuard's differentiation is: (a) on-device / no-cloud, (b) pre-agent position (L0), (c) pattern+semantic+behavioral fusion, (d) honest published bypass rates. AGT operates in-process middleware; CloneGuard operates as an external trust boundary the agent cannot compromise.

## Recommended Stack

### Core Technologies (Retained from v0.5.0)

| Technology | Version | Purpose | Why Recommended | Confidence |
|------------|---------|---------|-----------------|------------|
| Python | 3.11+ (3.11, 3.12, 3.13, 3.14) | Runtime | Existing codebase, ecosystem coverage, async support. No reason to change. | HIGH |
| PyYAML | >=6.0.2 | YAML rule + policy parsing | Already in use. Fast, C-backed, battle-tested. | HIGH |
| ONNX Runtime | >=1.17 | MiniLM inference | Already in use. CPU inference, no GPU dependency. Keep. | HIGH |
| Pydantic | >=2.12.5 | Schema validation, event models | Already a transitive dep (via MCP SDK). Promote to direct dependency for all internal event/policy schemas. v2's Rust core gives sub-ms validation. | HIGH |
| hatchling | (build) | Build backend | Already in use. Keep. | HIGH |

### Sandbox Adapters

CloneGuard orchestrates existing sandboxes via adapters -- it does NOT build a sandbox. Each adapter wraps a platform-native mechanism via `subprocess` or `ctypes`. The adapter interface is a Python ABC with `restrict()`, `is_available()`, and `describe_constraints()` methods.

| Technology | Version / Kernel | Purpose | Why Recommended | Confidence |
|------------|-----------------|---------|-----------------|------------|
| Landlock (via ctypes) | Linux kernel >=5.13 (ABI v5) | Linux filesystem+network restriction | Unprivileged, per-process, kernel-enforced. Claude Code's Codex sandbox uses Landlock+seccomp. Write thin ctypes wrapper (~200 LOC) against `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` syscalls. Do NOT use `py-landlock` (0.1.1) or `landlock` (1.0.0.dev5) -- both are alpha-quality with no maintainer track record. Direct syscall via ctypes is safer and removes a supply-chain dep. | MEDIUM-HIGH |
| Bubblewrap (bwrap) | >=0.8.0 | Linux namespace isolation | Claude Code's Linux sandbox. Subprocess wrapper around `/usr/bin/bwrap`. Stronger than Landlock for full filesystem/network/PID isolation. Use for high-isolation mode. No Python library needed -- invoke via `subprocess.run()`. | HIGH |
| Seatbelt (sandbox-exec) | macOS (deprecated but functional) | macOS filesystem+network restriction | Apple's kernel-level sandboxing. Invoked via `subprocess.run(['sandbox-exec', '-f', profile, ...])`. Profile files use Scheme-like syntax. Apple deprecated the CLI but still uses the underlying mechanism for App Store apps. Functional on all current macOS versions. | MEDIUM |
| gVisor (runsc) | >=release-20250310 | Container-level syscall interception | Google-maintained, Go-based application kernel. Intercepts all syscalls in userspace. 10-20% overhead for I/O-heavy workloads, negligible for CPU-bound. Invoked via Docker/containerd with `--runtime=runsc`. For enterprise/CI deployments. | MEDIUM |
| Firecracker | >=1.10 | MicroVM hardware isolation | AWS-maintained, KVM-based. 125ms boot, <5 MiB overhead. REST API on Unix socket. Use `firecracker-python` SDK or direct HTTP via `httpx`. For maximum isolation in cloud/CI deployments. | LOW (enterprise-only) |
| Wasmtime | >=43.0.0 (PyPI: `wasmtime`) | WASM sandbox for tool execution | Bytecode Alliance, standards-track. No ambient authority by default. Sub-10ms cold start. Useful for sandboxing individual tool outputs or UDF execution. AI tooling ecosystem is still maturing. | LOW (future/experimental) |
| NoopAdapter | -- | Passthrough | Preserves current v0.5.0 exit-code behavior. Default adapter. | HIGH |

**Decision: Direct ctypes/subprocess, not wrapper libraries.** The Python Landlock/Bubblewrap wrapper libraries are immature. The syscall interfaces are stable (kernel ABI). Writing 100-300 LOC of ctypes/subprocess code is lower risk than depending on alpha-quality PyPI packages with unknown maintainers.

### Policy Engine

| Technology | Version | Purpose | Why Recommended | Confidence |
|------------|---------|---------|-----------------|------------|
| YAML policy (built-in) | -- | Default policy format | Already used for pattern rules. Extend to policy definitions. No additional dependency. Evaluated by Python dict matching. | HIGH |
| regopy | >=1.3.0 | OPA Rego evaluation (in-process) | Microsoft-maintained C++ Rego runtime with Python bindings via C FFI. In-process -- no OPA server needed. Supports Rego v1 syntax. Enterprise customers using OPA can bring their existing policies. | MEDIUM-HIGH |
| cedarpy | >=4.8.0 | Cedar policy evaluation | Rust-backed Python bindings for Cedar Policy v4. AWS AgentCore Policy uses Cedar -- customers on AWS will have Cedar policies. Supports `is_authorized()` and batch authorization. Third-party maintained (k9security) but version-tracks Cedar engine. | MEDIUM |

**Decision: YAML as default, OPA/Cedar as optional extras.** The `[policy-opa]` and `[policy-cedar]` extras pattern keeps core lightweight while meeting enterprises where they are. YAML covers 80%+ of use cases. OPA and Cedar are for enterprises with existing policy infrastructure.

**What NOT to use:**
- `opa-python-client`: Requires a running OPA server. CloneGuard is on-device with no external service dependencies.
- `regorus` (Rust-based Rego): Less mature Python bindings than regopy. regopy has Microsoft backing.
- Custom DSL: Do not invent a policy language. The world has OPA and Cedar; use them.

### Structured Output (Audit / Compliance)

| Technology | Version | Purpose | Why Recommended | Confidence |
|------------|---------|---------|-----------------|------------|
| Pydantic v2 models | >=2.12.5 | Internal event schema | All audit events are Pydantic models. Serialize to any format. Type-safe, validated, documented via JSON Schema export. | HIGH |
| NDJSON (stdlib `json`) | -- | Streaming audit log | One JSON object per line. Use stdlib `json.dumps()` -- no library needed. jsonlines (4.0.0) adds convenience but is an unnecessary dependency for write-only use. | HIGH |
| sarif-pydantic | >=0.6.2 | SARIF 2.1.0 output | Pydantic v2 models for SARIF 2.1.0. Better than sarif-om (1.0.4, unmaintained, pbr dependency). sarif-pydantic is type-safe and integrates with our Pydantic-first approach. | MEDIUM-HIGH |
| opentelemetry-api | >=1.40.0 | OTel trace/span API | Stable, CNCF-graduated project. API package is zero-dependency. Allows consumers to wire up their own exporters. | HIGH |
| opentelemetry-sdk | >=1.40.0 | OTel SDK (optional) | Full SDK with span processors and exporters. Make this an optional extra `[otel]` -- not everyone needs full OTel. The API alone lets us emit spans that consumers collect. | HIGH |

**Decision: Pydantic models as the canonical internal representation.** NDJSON, SARIF, and OTel are serialization targets, not internal formats. A single Pydantic event model serializes to all three. This avoids maintaining three parallel schemas.

**What NOT to use:**
- `sarif-om` (1.0.4): Unmaintained, uses pbr build system, no type hints. Use sarif-pydantic instead.
- `jsonlines` (4.0.0): Unnecessary for write-only NDJSON. stdlib `json` + `\n` is sufficient.
- Custom logging framework: Use structlog or stdlib logging for operational logs. Audit events are structured data, not log lines.

### Input Adapters (Agent Framework Integration)

Each adapter translates a specific agent framework's hook/callback/middleware protocol into CloneGuard's internal event schema.

| Framework | Integration Point | Adapter Strategy | Confidence |
|-----------|-------------------|------------------|------------|
| Claude Code | JSON stdin/stdout hooks (3 events) | **Existing.** Already implemented in v0.5.0. | HIGH |
| Gemini CLI | JSON hooks (11 events, compatible) | `gemini hooks migrate --from-claude` works. Thin translation layer. | HIGH |
| Cursor | JSON hooks (19+ events) | Similar protocol to Claude Code. `failClosed`, `prompt` type hooks. | MEDIUM-HIGH |
| VS Code Copilot | JSON hooks (8 events, preview) | Preview in v1.109+. Track for GA. | LOW |
| LangChain | `AgentMiddleware.awrap_tool_call` callback | Implement as LangChain middleware. Uses handler callback pattern for pre/post tool call interception. | MEDIUM |
| CrewAI | `BaseInterceptor` + before/after LLM call hooks | Implement as CrewAI interceptor plugin. Pydantic-validated. | MEDIUM |
| Microsoft Agent Framework | `ToolCallInterceptor` plugin interface | Implement as AGT plugin. AGT's `agent-governance-toolkit` (3.0.1) exposes this interface. Consider compatibility/coopetition. | MEDIUM |
| Google ADK | Plugin callback hooks (lifecycle stages) | Implement as ADK Plugin subclass. Hooks at every agent lifecycle stage. | MEDIUM |
| OpenAI Agents SDK | Guardrails (input/output validation) | Implement as guardrail. Runs in parallel with agent execution. | MEDIUM |
| MCP Protocol | Interceptor middleware on MCP server | Use `mcp` SDK (1.26.0). MCP interceptors modify requests, implement retries, short-circuit. CloneGuard as MCP middleware/proxy. | MEDIUM-HIGH |

**Decision: Adapter per framework, not universal shim.** Each framework has its own interception semantics. A universal shim would be lowest-common-denominator. Per-framework adapters let us use the full power of each framework's interception capabilities.

**Priority order:** Claude Code (done) > Gemini CLI (near-free) > MCP (protocol-level) > Cursor > LangChain > Google ADK > CrewAI > MS Agent Framework > OpenAI Agents > VS Code Copilot (wait for GA).

### MELON Integration

| Technology | Version | Purpose | Why Recommended | Confidence |
|------------|---------|---------|-----------------|------------|
| MELON (custom impl) | Based on arXiv:2502.05174 | Provable IPI detection via masked re-execution | ICML 2025 paper. >99% attack prevention on AgentDojo. Training-free. The reference implementation (github.com/kaijiezhu11/MELON) is research code, not production-ready. Implement the core algorithm (masked prompt re-execution + tool call comparison) as a CloneGuard module using existing ONNX/Ollama infrastructure. Selective triggering in 0.4-0.6 confidence zone limits overhead to ~5-10% of calls. | MEDIUM |

**Decision: Reimplement MELON core, don't depend on research code.** The algorithm is well-defined in the paper. The reference repo is research-quality Python. CloneGuard needs a production implementation that integrates with our existing confidence scoring and three-verdict model.

### Testing & Quality (Retained + Added)

| Technology | Version | Purpose | Why Recommended | Confidence |
|------------|---------|---------|-----------------|------------|
| pytest | >=8.0 | Test runner | Already in use. | HIGH |
| pytest-cov | >=6.0 | Coverage | Already in use. | HIGH |
| ruff | >=0.8 | Lint + format | Already in use. | HIGH |
| mypy | >=1.13 | Type checking (strict) | Already in use. | HIGH |
| hypothesis | >=6.100 | Property-based testing for policy engine | Fuzz policy evaluation with random inputs. Critical for catching edge cases in YAML/Rego/Cedar policy parsing. | HIGH |

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| ctypes Landlock wrapper | `py-landlock` (0.1.1) | Never. Alpha-quality, unknown maintainer, supply-chain risk for a security tool. |
| ctypes Landlock wrapper | `landlock` (1.0.0.dev5) | Never. Dev release, pre-release only. |
| regopy (in-process Rego) | `opa-python-client` (REST) | If org already runs OPA server and wants centralized policy management. CloneGuard's on-device constraint rules this out for core. |
| cedarpy (Rust bindings) | AWS AVP API | If org uses AWS Verified Permissions service. Cloud-dependent, violates on-device constraint. |
| sarif-pydantic | sarif-om (1.0.4) | Never. Unmaintained, no type hints, pbr dependency. |
| Pydantic v2 event models | dataclasses | If removing Pydantic dependency. But Pydantic is already transitive via MCP SDK -- pay zero marginal cost. |
| subprocess bwrap | Docker SDK | When target environment already has Docker. Heavier, but more portable. |
| MELON reimplementation | MELON reference repo | Never for production. Research code without error handling, tests, or production patterns. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `py-landlock` / `landlock` (PyPI) | Alpha-quality packages for a security-critical syscall interface. Supply-chain risk. | Direct ctypes syscall wrapper (~200 LOC) |
| `sarif-om` | Unmaintained since 2022, pbr build dep, no Pydantic/type support | sarif-pydantic (0.6.2) |
| `opa-python-client` | Requires running OPA server; violates on-device constraint | regopy (1.3.0, in-process) |
| `jsonlines` | Unnecessary dep for write-only NDJSON; stdlib json suffices | `json.dumps()` + `"\n"` |
| Custom policy DSL | NIH syndrome; OPA and Cedar are industry standards with tooling | YAML (default) + regopy + cedarpy |
| `agent-governance-toolkit` as dep | CloneGuard IS the defense layer. Do not depend on a competitor. Build adapters FOR their ToolCallInterceptor interface instead. | Implement CloneGuard as an AGT plugin |
| Firejail | Deprecated upstream, SUID-root attack surface, replaced by bwrap+Landlock | Bubblewrap or Landlock |
| seccomp-bpf (direct) | Complex BPF programs, high risk of DoS or escape if filters are wrong | Landlock (simpler API, designed for unprivileged use) |
| AppArmor / SELinux (direct) | Requires root, system-wide configuration, not per-process by unprivileged user | Landlock (unprivileged) or Bubblewrap (user namespaces) |

## Stack Patterns by Deployment Target

**If on-device CLI (default, open-source):**
- NoopAdapter (backward compat) or LandlockAdapter/SeatbeltAdapter
- YAML policy (built-in)
- NDJSON audit output
- No external dependencies beyond PyYAML + Pydantic

**If CI/CD pipeline (GitHub Actions, containers):**
- BubblewrapAdapter or gVisorAdapter
- YAML policy
- SARIF output (GitHub Code Scanning integration)
- NDJSON for pipeline logs

**If enterprise deployment (proprietary tier):**
- Full adapter suite including Firecracker
- OPA/Cedar policy backends
- SARIF + OTel + NDJSON simultaneous output
- LangChain/CrewAI/ADK/AGT framework adapters
- Fleet management, SIEM integration

**If MCP ecosystem:**
- MCP interceptor middleware
- CloneGuard as MCP proxy between client and server
- NDJSON audit to MCP-aware consumers

## Version Compatibility Matrix

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| Python 3.11+ | All packages listed | 3.14 verified in current venv |
| Pydantic >=2.12.5 | sarif-pydantic >=0.6.2 | Both use Pydantic v2 |
| Pydantic >=2.12.5 | mcp >=1.26.0 | MCP SDK depends on Pydantic v2 |
| opentelemetry-sdk 1.40.0 | opentelemetry-api 1.40.0 | Must match versions |
| regopy 1.3.0 | Python 3.6+ (claimed), tested 3.11+ | C FFI, platform-specific wheels |
| cedarpy 4.8.0 | Cedar engine 4.8.x | Version tracks Cedar engine major.minor |
| wasmtime 43.0.0 | Python 3.8+ | Bytecode Alliance maintained |

## Installation

```bash
# Core (open-source, detection + basic adapters)
uv pip install pyyaml pydantic

# Semantic detection (existing)
uv pip install onnxruntime transformers numpy

# Policy backends (optional extras)
uv pip install regopy    # [policy-opa]
uv pip install cedarpy   # [policy-cedar]

# Structured output (optional extras)
uv pip install sarif-pydantic                   # [sarif]
uv pip install opentelemetry-api opentelemetry-sdk  # [otel]

# All optional
uv pip install cloneguard[all]

# Dev dependencies
uv pip install pytest pytest-cov ruff mypy hypothesis types-PyYAML
```

## Dependency Budget

CloneGuard's security credibility depends on a minimal dependency surface. Every dependency is an attack surface.

| Category | Direct Deps (new) | Rationale |
|----------|-------------------|-----------|
| Core | +1 (pydantic, promoted from transitive) | Already in dependency tree via MCP |
| Policy | +0 to +2 (regopy, cedarpy) | Optional extras only |
| Output | +0 to +2 (sarif-pydantic, opentelemetry) | Optional extras only |
| Sandbox | +0 | All via ctypes/subprocess -- no PyPI deps |
| Adapters | +0 | Adapters use framework's own SDK (user's dep, not ours) |

**Total new required dependencies: 1 (Pydantic promotion)**
**Total new optional dependencies: up to 4**

This is an extremely conservative dependency budget for a security tool.

## Sources

- [PyPI cedarpy](https://pypi.org/project/cedarpy/) -- v4.8.0 verified via `uv pip install --dry-run` (HIGH)
- [PyPI regopy](https://pypi.org/project/regopy/) -- v1.3.0 verified via `uv pip install --dry-run` (HIGH)
- [PyPI sarif-pydantic](https://pypi.org/project/sarif-pydantic/) -- v0.6.2 verified via `uv pip install --dry-run` (HIGH)
- [PyPI opentelemetry-sdk](https://pypi.org/project/opentelemetry-sdk/) -- v1.40.0 verified via `uv pip install --dry-run` (HIGH)
- [PyPI wasmtime](https://pypi.org/project/wasmtime/) -- v43.0.0 verified via `uv pip install --dry-run` (HIGH)
- [PyPI agent-governance-toolkit](https://pypi.org/project/agent-governance-toolkit/) -- v3.0.1 verified via `uv pip install --dry-run` (HIGH)
- [PyPI mcp](https://pypi.org/project/mcp/) -- v1.26.0 verified via `uv pip show` (HIGH)
- [Microsoft AGT announcement](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) -- Released 2026-04-02 (MEDIUM)
- [AWS Bedrock AgentCore Policy GA](https://aws.amazon.com/blogs/aws/amazon-bedrock-agentcore-adds-quality-evaluations-and-policy-controls-for-deploying-trusted-ai-agents/) -- GA 2026-03-03 (MEDIUM)
- [MELON paper](https://arxiv.org/abs/2502.05174) -- ICML 2025, arXiv:2502.05174v4 (HIGH)
- [MELON reference implementation](https://github.com/kaijiezhu11/MELON) -- Research code (MEDIUM)
- [Landlock kernel docs](https://docs.kernel.org/userspace-api/landlock.html) -- Stable kernel ABI (HIGH)
- [Bubblewrap GitHub](https://github.com/containers/bubblewrap) -- Used by Flatpak, Claude Code (HIGH)
- [gVisor docs](https://gvisor.dev/docs/) -- Google-maintained (HIGH)
- [Firecracker GitHub](https://github.com/firecracker-microvm/firecracker) -- AWS-maintained (HIGH)
- [LangChain AgentMiddleware](https://reference.langchain.com/python/langchain/agents/middleware/types/AgentMiddleware/awrap_tool_call) -- Official docs (MEDIUM)
- [CrewAI changelog](https://docs.crewai.com/en/changelog) -- Interceptor hooks confirmed (MEDIUM)
- [Google ADK plugins](https://google.github.io/adk-docs/plugins/) -- Lifecycle callback hooks (MEDIUM)
- [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-python/guardrails/) -- Parallel validation (MEDIUM)
- [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) -- Released 2025-12 (HIGH)
- [Agent sandbox comparison](https://pierce.dev/notes/a-deep-dive-on-agent-sandboxes) -- Community analysis (LOW)
- [Sandbox comparison - Northflank](https://northflank.com/blog/best-code-execution-sandbox-for-ai-agents) -- Commercial analysis (LOW)

---
*Stack research for: CloneGuard v2 Universal Agentic Defense Layer*
*Researched: 2026-04-05*
