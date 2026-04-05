# Feature Research: Universal Agentic Defense Layer

**Domain:** Agentic AI security (detection, enforcement, audit of AI agent tool calls)
**Researched:** 2026-04-05
**Confidence:** HIGH (commercial landscape well-documented, standards published, architecture validated)

## Feature Landscape

### Table Stakes (Users Expect These)

Features buyers assume exist. Missing these means the product is disqualified before evaluation begins.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Prompt injection detection (direct + indirect)** | Every competitor has this. Lakera, Cisco AI Defense, LlamaFirewall, NeMo Guardrails all ship it. OWASP ASI-01/ASI-02 require it. | MEDIUM | CloneGuard already has 204 regex + MiniLM ONNX + Ollama. Existing. |
| **Structured audit logging** | EU AI Act Article 12 enforceable 2026-08-02. SOC 2 Type II audits require evidence of operating controls. 38% of orgs can't monitor agent traffic end-to-end. | MEDIUM | NDJSON event schema with session_id, verdict, confidence, signals, enforcement_action. Foundation for everything downstream. |
| **SARIF 2.1.0 output** | GitHub Advanced Security, VS Code, SonarQube, Harness STO all consume SARIF. Security teams expect findings in their existing tooling. Snyk, Semgrep, and every SAST tool emit SARIF. | LOW | Well-specified format. Straightforward mapping from detection events to SARIF result objects. |
| **Policy-configurable verdicts** | Binary allow/block is insufficient for production. MS AGT, AWS AgentCore Policy, and every governance framework support configurable policy. Cedar in AgentCore uses default-deny. | HIGH | YAML as default, but the policy engine abstraction (compile to IR) is the hard part. Must support threshold tuning, per-tool overrides, per-agent-type defaults. |
| **Multi-agent-platform support** | Claude Code, Cursor, Gemini CLI, Windsurf, VS Code Copilot. Enterprises run heterogeneous agent fleets. Single-agent lock-in is a deal-breaker for procurement. | MEDIUM | Input adapter abstraction. Claude Code hook protocol is the reference; others are variations on the same JSON stdin/stdout or event API pattern. |
| **MCP server/tool scanning** | MCP has 30+ CVEs in 60 days (2026). Invariant/Snyk mcp-scan, MITRE ATLAS added "Publish Poisoned AI Agent Tool" technique (Feb 2026). OWASP ASI-04 covers supply chain. | MEDIUM | Tool description fingerprinting, metadata analysis, cross-reference against known-good registries. Distinct from runtime interception. |
| **Sensitive data leak prevention** | PII redaction and data exfiltration detection are baseline in Lakera Guard, Cisco AI Defense, and Prompt Security. OWASP ASI-06 covers memory/context poisoning. | LOW | CloneGuard already has SEQ-001/002 (read-then-exfil sequence detection). Extend with PII pattern matching (regex for SSN, credit card, API keys). |
| **CLI + library installation** | Developer tools must be installable via `pip install`, `uv tool install`, `pipx`, or equivalent. No SaaS signup, no cloud dependency for core functionality. | LOW | Already partially done. Packaging fix needed for standalone binary. |
| **Sub-50ms detection latency** | Lakera advertises <50ms. Arcjet advertises inline at the request boundary. Developers won't tolerate perceptible slowdown in their agent loop. | LOW | CloneGuard already <20ms for Tier 0+1.5. Maintain this. |
| **Configuration-as-code** | Security policies in version control, reviewable in PRs, deployable via CI/CD. This is how every DevSecOps tool works. | LOW | YAML policy files checked into repo. Already the planned approach. |

### Differentiators (Competitive Advantage)

Features that set CloneGuard apart. Not expected, but deliver outsized value.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Three-signal fusion with trajectory calibration** | No competitor fuses pattern + semantic + behavioral signals calibrated against 208K real trajectories. LlamaFirewall runs sequential (PromptGuard then AlignmentCheck). Cisco/Lakera use single-signal classifiers. Fusion with real-world FPR calibration is a 2+ year moat. | HIGH | Requires calibration pipeline on trajectory dataset. Context-weighted scoring (not max(scores)). The dataset is the defensible asset. |
| **Allow-But-Constrain (three-verdict model)** | Binary allow/block forces a false choice. AWS AgentCore Policy supports forbid/permit but not adaptive sandboxing per verdict. MS AGT supports DENY but not "allow with tightened sandbox." The constraint generation (which domains, which paths, whether to snapshot) given a specific verdict and tool context is novel. | HIGH | Requires sandbox adapter interface + policy engine + constraint generation logic. The combination is what no one else ships. |
| **Sandbox-agnostic enforcement** | Orchestrate any containment technology (Landlock, Seatbelt, Bubblewrap, gVisor, Firecracker, WASM, Docker) through a single adapter interface. Claude Code uses Bubblewrap/Seatbelt opt-in; OpenAI Codex uses Landlock+seccomp default. CloneGuard wraps any of these and selects the strongest available automatically. | HIGH | Auto-detection of available sandbox capabilities at startup. Each adapter implementation is moderate complexity; the interface design and auto-selection are the hard parts. |
| **MELON provable detection (selective)** | ICML 2025 algorithm (arXiv:2502.05174). No production tool has shipped masked re-execution for indirect prompt injection with provable guarantees. Selective triggering (only in ambiguous confidence zone) limits overhead to ~5-10% of calls. | VERY HIGH | Requires implementing the MELON algorithm, integrating with fusion confidence zone, managing re-execution overhead. Research-grade complexity. |
| **Package hallucination detection (slopsquatting)** | 20% of AI-generated code includes hallucinated package names. 43% of hallucinated names recur across runs. react-codeshift spread across 237 GitHub repos via agent skills. No hook-based tool catches this at `npm install` / `pip install` time. Snyk does it as SAST; we do it at the tool-call boundary before installation. | MEDIUM | Cross-reference package name against npm/PyPI registry API before allowing install command. Cache registry responses. Low false-positive potential. |
| **Honest adversarial evaluation methodology** | CloneGuard reported 16.7% bypass rate (Opus iterative) while competitors report cherry-picked headlines. Evaluation against "The Attacker Moves Second" methodology (Nasr, Carlini, Tramer). Reproducible benchmark harness. This is a trust differentiator with security buyers. | MEDIUM | Already partially built (eval harness, adaptive red team methodology). Needs continuous maintenance as attack patterns evolve. |
| **OTel span emission** | OpenTelemetry GenAI semantic conventions are stabilizing (2025-2026). AG2, Microsoft Agent Framework, and Datadog LLM Observability natively support OTel. Correlating security events with existing observability (Splunk, Datadog, Grafana) is high-value for SOC teams. | MEDIUM | Emit spans conforming to GenAI semantic conventions. Each detection event becomes a span with verdict, confidence, tool_name, enforcement_action attributes. |
| **Governance framework plugin (AGT, OPA, Cedar)** | MS AGT has ToolCallInterceptor interface. AWS AgentCore Policy uses Cedar with default-deny. OPA is the enterprise policy lingua franca. Being a first-class sensor that feeds these governance engines means CloneGuard becomes a dependency of the governance layer, not a replacement. | HIGH | Three distinct integration surfaces. AGT ToolCallInterceptor plugin, OPA external data source (REST), Cedar context attributes for AgentCore. |
| **Behavioral sequence detection (CaMeL-lite)** | Session-wide typed markers that persist across arbitrary intervening tool calls. Detects multi-step attack patterns (read-then-exfil, config hijacking) that single-event classifiers miss. SEQ rules are configurable, allowlistable. | MEDIUM | Already built (6 SEQ rules, 3 enforce, 3 advisory). Extend with new patterns for browser, CI/CD, MCP, autonomous agent contexts. |
| **Cross-agent pattern libraries** | Agent-type-specific YAML pattern sets (coding/, browser/, cicd/, mcp/, autonomous/, financial/) with a common engine. Security teams maintain domain-specific rules without touching the engine. | MEDIUM | Pattern file format and engine already exist. New pattern sets require domain expertise per agent type. Browser/financial patterns are highest value. |
| **CI/CD runner deployment** | GitHub Actions, GitLab CI, Jenkins. Scan PRs and agent-generated code before merge. SARIF upload to GitHub Security tab. | MEDIUM | Lightweight: wrap existing CLI in action YAML. SARIF output makes this mostly packaging. |

### Anti-Features (Commonly Requested, Often Problematic)

Features to deliberately NOT build. These seem attractive but would weaken the product.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **SaaS/cloud-hosted detection** | Enterprise procurement teams default to SaaS. Lakera and Prompt Security offer SaaS. | Sending tool-call content to a cloud service defeats the trust model. CloneGuard's core value is running on-device, in the trust boundary the agent can't compromise. Phone-home means the agent (or attacker) can intercept/block the call. SaaS adds latency. SaaS creates a data sovereignty problem for EU AI Act compliance. | On-device execution only. Enterprise "fleet management" is a separate concern (policy distribution, not detection-as-a-service). |
| **Custom ML model training platform** | Enterprises want to train on their own data. Fine-tuning sounds differentiating. | MiniLM is commodity. Custom training is an operations burden CloneGuard shouldn't own. IPI Arena model retraining showed unacceptable FPR regression (9% to 20-42%). The value is in fusion and calibration, not in a marginally better classifier. | Expose calibration tuning (threshold adjustment, weight adjustment in fusion layer). Let users bring their own ONNX model if needed. Don't build a training platform. |
| **Full governance framework** | CISOs ask "does this replace my governance tool?" | CloneGuard is a sensor that feeds governance (AGT, OPA, Cedar). Building governance means competing with Microsoft, AWS, HashiCorp. Wrong fight. Governance = identity, RBAC, audit retention, compliance reporting. CloneGuard = semantic intelligence about what the tool call contains. | Plugin into governance frameworks. Be the best sensor, not a mediocre governance platform. |
| **Building a sandbox** | Users expect "if you detect, you should also isolate." | Landlock, Seatbelt, gVisor, Firecracker, Docker all exist. Building a sandbox means maintaining OS-level security primitives across Linux/macOS/Windows. Wrong competency. | Adapter interface that orchestrates any existing sandbox. Auto-select strongest available. Value is in the intelligence (which constraints to apply), not the containment mechanism. |
| **LLM-as-judge for every tool call** | Tier 2 (Ollama) is powerful. Why not use LLM classification on everything? | LLM inference adds 200-2000ms per call. Unacceptable for tool-call-level interception where every agent action waits. Also non-deterministic: same input can produce different verdicts. | LLM as optional Tier 2 for ambiguous cases only. MELON selective re-execution in the confidence gap. Pattern + semantic + sequence handle 90%+ at <20ms. |
| **Real-time dashboard / web UI** | Every enterprise security product has a dashboard. | A dashboard is a full-stack web application: auth, session management, data persistence, frontend framework, hosting. This is months of engineering that doesn't improve detection quality. CLI + structured logs + SIEM integration covers the same use cases without the maintenance burden. | SARIF in GitHub Security tab, OTel in Datadog/Grafana, NDJSON in Splunk/Sentinel. Use existing dashboards. |
| **Blocking all unsafe agent behavior** | Marketing temptation to claim "stops all attacks." | Dishonest. 16.7% bypass rate against adaptive Opus attacker. No defense stops all attacks. Claiming otherwise destroys credibility with security buyers who know better. | Frame as raising attacker cost. Report honest evaluation numbers. "Makes attacks harder, more expensive, and more likely to be caught." |
| **Windows sandbox adapter** | Windows is a large developer market. | Windows sandboxing (AppContainers, Windows Sandbox) is fundamentally different from Linux/macOS and poorly documented for programmatic use. Linux (Landlock) and macOS (Seatbelt) cover the vast majority of developer workstations and all CI/CD runners. | NoopAdapter (detection-only) on Windows. Prioritize Linux + macOS enforcement. Windows adapter is a community contribution opportunity, not a core deliverable. |
| **Agent-internal prompt hardening** | Spotlighting, instruction hierarchy, defensive system prompts. | CloneGuard operates at Layer 0 (before the agent). It cannot modify the agent's system prompt. Spotlighting was assessed and rejected: Nasr, Carlini et al. (2025 preprint) showed ASR >95% under adaptive attack. Wrong architectural layer. | Detect and constrain from the outside. Don't try to make the agent itself more robust; that's the agent vendor's job. |

## Feature Dependencies

```
Structured Audit Logging (NDJSON events)
    +-- SARIF 2.1.0 Emitter (transforms events to SARIF)
    +-- OTel Span Emission (transforms events to OTel spans)
    +-- SIEM Integration Guides (consumes NDJSON directly)
    +-- EU AI Act Article 12 Compliance (requires structured events)

Detection Engine Extraction (standalone module from hooks.py)
    +-- Input Adapter Abstraction (decouples from Claude Code protocol)
    |       +-- Multi-Agent-Platform Support
    |       +-- MCP Protocol Middleware Adapter
    |       +-- CI/CD Runner Deployment
    |       +-- AGT ToolCallInterceptor Plugin
    +-- Three-Signal Fusion Layer
    |       +-- MELON Selective Re-Execution
    +-- Package Hallucination Detection

Policy Engine (YAML configuration)
    +-- Three-Verdict Model (SAFE/SUSPICIOUS/MALICIOUS)
    |       +-- Allow-But-Constrain Enforcement
    |       +-- Sandbox Adapter Interface
    |       |       +-- LandlockAdapter (Linux)
    |       |       +-- SeatbeltAdapter (macOS)
    |       |       +-- BubblewrapAdapter (Linux)
    |       |       +-- Advanced Adapters (gVisor, Firecracker, WASM, Docker)
    +-- OPA/Rego Policy Backend
    +-- Cedar Policy Backend

Cross-Agent Pattern Libraries
    +-- Browser Agent Patterns (requires input adapter for CDP)
    +-- CI/CD Agent Patterns (requires input adapter for GH Actions events)
    +-- MCP Server Patterns (requires MCP middleware adapter)
    +-- Autonomous Agent Patterns (requires AGT/SDK middleware adapter)
    +-- Financial Agent Patterns (requires custom API middleware)
```

### Dependency Notes

- **Structured Audit Logging is the foundation for all compliance features:** SARIF, OTel, and SIEM integration all consume the same event schema. Build the schema first, then the emitters.
- **Detection Engine Extraction enables all non-hook integrations:** The current engine is coupled to Claude Code's hook protocol in `hooks.py`. Extracting it into a standalone module is prerequisite for AGT, MCP, CI/CD, and framework adapter integrations.
- **Policy Engine enables the three-verdict model:** Without configurable policy, there's no way to express "SUSPICIOUS means constrain" vs "MALICIOUS means block." Policy must exist before enforcement.
- **Three-Verdict Model enables sandbox enforcement:** Allow-But-Constrain requires knowing the verdict (SUSPICIOUS) and looking up constraints. The sandbox adapter interface is useless without a policy decision that produces constraints.
- **Input Adapter Abstraction enables all agent-type expansion:** Browser agents, CI/CD agents, MCP middleware, and AGT plugins all feed through the input adapter layer. This is the gateway to the multi-agent market.
- **Pattern libraries are independent of each other but depend on input adapters:** Browser patterns need CDP input; CI/CD patterns need GitHub Actions events. The pattern engine itself is already agent-agnostic.

## MVP Definition

### Launch With (v1.0 -- "Detection + Audit")

Minimum viable product for the v2 architecture. Everything here extends the existing v0.5.0 without rewriting it.

- [x] **204 regex patterns + MiniLM ONNX classifier + SEQ rules** -- Existing detection. Already works.
- [ ] **Structured event schema (NDJSON)** -- Foundation for all audit/compliance features.
- [ ] **SARIF 2.1.0 emitter** -- Puts findings in GitHub Security tab alongside SAST results.
- [ ] **Detection engine extracted from hooks.py** -- Prerequisite for everything non-Claude-Code.
- [ ] **`uv tool install` / `pipx` packaging** -- Professional installation experience.
- [ ] **Hook config integrity self-check** -- Prevents CVE-2025-59536-class config tampering.

### Add After Validation (v1.x -- "Enforcement + Integration")

Features to add once core detection + audit is proven in production.

- [ ] **Policy engine (YAML)** -- Trigger: customers need threshold tuning, per-tool overrides.
- [ ] **Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS)** -- Trigger: binary allow/block insufficient for production deployments.
- [ ] **Sandbox adapter interface + NoopAdapter + LandlockAdapter + SeatbeltAdapter** -- Trigger: customers want enforcement, not just detection.
- [ ] **Input adapter abstraction** -- Trigger: demand from non-Claude-Code agent users.
- [ ] **Package hallucination detection** -- Trigger: slopsquatting incidents in the wild.
- [ ] **OTel span emission** -- Trigger: SOC teams need correlation with existing observability.
- [ ] **AGT ToolCallInterceptor plugin** -- Trigger: Microsoft Agent Framework adoption.
- [ ] **MCP protocol middleware** -- Trigger: MCP ecosystem maturity.
- [ ] **CI/CD runner deployment** -- Trigger: PR scanning demand.

### Future Consideration (v2+ -- "Governance + Expansion")

Features to defer until product-market fit is established.

- [ ] **OPA/Rego + Cedar policy backends** -- Why defer: Only needed when enterprises already use OPA/Cedar. YAML covers 80%.
- [ ] **Three-signal fusion layer (calibrated)** -- Why defer: Requires calibration pipeline maturity. High value but high effort.
- [ ] **MELON selective re-execution** -- Why defer: Research-grade complexity. Must prove three-signal fusion first.
- [ ] **Browser agent pattern library + CDP adapter** -- Why defer: Browser agent market not mature enough.
- [ ] **Autonomous agent patterns + SDK middleware** -- Why defer: AutoGen/CrewAI/ADK ecosystem still fragmenting.
- [ ] **Financial agent patterns + transaction policy** -- Why defer: Specialized domain, requires domain experts.
- [ ] **Advanced sandbox adapters (gVisor, Firecracker, WASM)** -- Why defer: Landlock + Seatbelt cover 90% of workstations.
- [ ] **Fleet deployment tooling (MDM/Ansible)** -- Why defer: Enterprise feature, needs customer pull.
- [ ] **SPIFFE agent identity** -- Why defer: Enterprise zero-trust integration, needs AGT maturity.
- [ ] **SIEM integration guides** -- Why defer: NDJSON output is already SIEM-consumable. Guides are documentation, not engineering.

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Structured event schema (NDJSON) | HIGH | LOW | P1 |
| SARIF 2.1.0 emitter | HIGH | LOW | P1 |
| Detection engine extraction | HIGH | MEDIUM | P1 |
| Packaging fix (uv/pipx) | HIGH | LOW | P1 |
| Hook config integrity self-check | HIGH | LOW | P1 |
| Policy engine (YAML) | HIGH | HIGH | P1 |
| Three-verdict model | HIGH | MEDIUM | P1 |
| Sandbox adapter interface + Noop | MEDIUM | MEDIUM | P2 |
| LandlockAdapter | MEDIUM | MEDIUM | P2 |
| SeatbeltAdapter | MEDIUM | MEDIUM | P2 |
| Input adapter abstraction | HIGH | MEDIUM | P2 |
| Package hallucination detection | MEDIUM | LOW | P2 |
| OTel span emission | MEDIUM | MEDIUM | P2 |
| AGT ToolCallInterceptor plugin | HIGH | MEDIUM | P2 |
| MCP protocol middleware | MEDIUM | MEDIUM | P2 |
| CI/CD runner deployment | MEDIUM | LOW | P2 |
| Three-signal fusion (calibrated) | HIGH | HIGH | P2 |
| OPA/Rego backend | MEDIUM | HIGH | P3 |
| Cedar backend | MEDIUM | HIGH | P3 |
| MELON selective re-execution | HIGH | VERY HIGH | P3 |
| Browser agent patterns + CDP | LOW | HIGH | P3 |
| Autonomous agent patterns | LOW | MEDIUM | P3 |
| Financial agent patterns | LOW | MEDIUM | P3 |
| Advanced sandbox adapters | LOW | HIGH | P3 |
| Fleet deployment tooling | LOW | MEDIUM | P3 |
| SPIFFE agent identity | LOW | MEDIUM | P3 |

**Priority key:**
- P1: Must have for v1.0 launch (detection + audit + policy)
- P2: Must have for v1.x (enforcement + integration + wider coverage)
- P3: Future consideration for v2+ (governance + agent-type expansion)

## Competitor Feature Analysis

| Feature | Cisco AI Defense | Lakera Guard | LlamaFirewall | MS AGT | Snyk/Invariant | CloneGuard (planned) |
|---------|-----------------|--------------|---------------|--------|----------------|---------------------|
| **Prompt injection detection** | ML + regex + threat intel | ML classifier (50K patterns) | PromptGuard 2 (86M BERT) + AlignmentCheck | Defers to plugins | MCP-scan + TFA | 204 regex + MiniLM ONNX + SEQ |
| **Deployment model** | Cloud / SASE | SaaS + self-hosted | Open source library | Open source framework | SaaS + CLI scanner | On-device CLI/library |
| **Policy engine** | Proprietary | Proprietary | None (detection only) | OPA/Rego/Cedar/YAML | None | YAML/OPA/Cedar (all to IR) |
| **Sandbox enforcement** | Network-level (SASE) | None | None | Execution rings | None | Landlock/Seatbelt/gVisor/etc |
| **SARIF output** | No | No | No | Audit log format | Yes (mcp-scan) | Yes |
| **OTel spans** | Via SASE telemetry | No | No | Yes (first-class) | No | Yes |
| **Multi-agent support** | Cloud agents | API-level (any) | Meta models | AutoGen/LangChain/CrewAI | Agent skills/MCP | Hook/AGT/MCP/CI-CD adapters |
| **Behavioral sequence detection** | Unknown | No | AlignmentCheck (CoT) | Saga orchestration | Trace analysis | CaMeL-lite SEQ rules |
| **Package hallucination** | No | No | No | No | Dependency scanning | Registry cross-reference |
| **Honest eval published** | No (algorithmic red team) | No | Yes (ASR numbers) | OWASP certification | No | Yes (16.7% bypass reported) |
| **Latency** | Network hop | <50ms | Model inference | <0.1ms policy | Offline scan | <20ms detection |
| **Pricing** | Enterprise bundle | $99/mo+ | Free (OSS) | Free (OSS) | Enterprise bundle | Free (OSS) + enterprise tier |
| **Hook-level interception** | No (network/API) | No (API) | No (library) | No (framework) | No (scanner) | **Yes (Layer 0, pre-agent)** |

### Key Competitive Insight

No competitor operates at the hook/tool-call boundary. Cisco and Lakera operate at the network/API level. LlamaFirewall and NeMo Guardrails operate as libraries within the agent. MS AGT operates as a framework wrapper. Snyk/Invariant operate as offline scanners. CloneGuard is uniquely positioned to intercept every tool call from outside the agent's trust boundary, before execution, at the OS level where the agent cannot disable or bypass the defense.

## Regulatory and Standards Feature Mapping

| Standard/Regulation | Relevant Feature | Status |
|---------------------|-----------------|--------|
| EU AI Act Article 12 (2026-08-02) | Structured event logs, 6-month retention, risk situation identification | Planned (NDJSON schema) |
| EU AI Act Article 19 | Automatically generated logs for deployer access | Planned (NDJSON + SARIF) |
| OWASP ASI-01 (Agent Goal Hijack) | Prompt injection detection, behavioral sequence analysis | Existing (patterns + SEQ) |
| OWASP ASI-02 (Tool Misuse) | Tool-call interception, policy enforcement | Planned (policy engine) |
| OWASP ASI-04 (Supply Chain) | MCP scanning, package hallucination detection | Planned |
| OWASP ASI-05 (Unexpected Code Execution) | Sandbox enforcement, code execution gating | Planned (sandbox adapters) |
| OWASP ASI-06 (Memory/Context Poisoning) | Config file write protection (SEQ-005), memory poison patterns | Partially existing |
| MITRE ATLAS AML.T0051 (Prompt Injection) | Pattern IDs mapped to ATLAS sub-techniques | Existing |
| MITRE ATLAS "Publish Poisoned AI Agent Tool" | MCP tool description fingerprinting | Planned |
| SOC 2 Type II | Aggregated quarterly reports from structured events | Planned (via NDJSON) |
| ISO 42001 A.6.2.8 | Inference-phase decision logging with policy version | Planned |
| NIST CAISI | Agent security controls (standard still developing) | Monitoring |

## Sources

### Official Documentation and Standards
- [EU AI Act Article 12: Record-Keeping](https://artificialintelligenceact.eu/article/12/) -- logging requirements for high-risk AI systems
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) -- peer-reviewed risk framework
- [MITRE ATLAS](https://atlas.mitre.org/) -- 16 tactics, 84 techniques, including agentic AI techniques added Oct 2025-Feb 2026
- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/) -- agent span standards

### Commercial Products
- [Cisco AI Defense](https://www.cisco.com/c/en/us/products/collateral/security/ai-defense/ai-defense-ds.html) -- Robust Intelligence acquisition, agentic expansion
- [Lakera Guard](https://www.lakera.ai/lakera-guard) -- API-level AI firewall, $99/mo+
- [AWS Bedrock AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html) -- Cedar-based agent policy, GA March 2026

### Open Source Frameworks
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) -- MIT license, OPA/Rego/Cedar, 10/10 OWASP coverage claim
- [LlamaFirewall](https://ai.meta.com/research/publications/llamafirewall-an-open-source-guardrail-system-for-building-secure-ai-agents/) -- PromptGuard 2 + AlignmentCheck + CodeShield
- [Snyk/Invariant Labs acquisition](https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/) -- Toxic Flow Analysis, MCP-scan

### Market Analysis
- [Bessemer: Securing AI Agents -- Defining Challenge of 2026](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026) -- 48% cite agentic AI as top attack vector, $4.63M avg shadow AI breach
- [Microsoft: Secure Agentic AI End-to-End](https://www.microsoft.com/en-us/security/blog/2026/03/20/secure-agentic-ai-end-to-end/) -- Agent Runtime SDK, Defender for AI
- [NVIDIA: Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/) -- kernel-level isolation guidance

### Attack Research
- [Slopsquatting: AI Package Hallucination Attacks](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks) -- 20% of generated code includes hallucinated packages
- [MCP Security 2026: 30 CVEs in 60 Days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/) -- MCP attack surface
- [VentureBeat: Agent Behavioral Baseline Gap](https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap) -- CrowdStrike, Cisco, Palo Alto all shipped agentic SOC tools but left telemetry gap

---
*Feature research for: Universal Agentic Defense Layer (CloneGuard v2)*
*Researched: 2026-04-05*
