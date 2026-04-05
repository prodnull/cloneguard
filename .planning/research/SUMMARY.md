# Project Research Summary

**Project:** CloneGuard v2 — Universal Agentic Defense Layer
**Domain:** Agentic AI security (detection, enforcement, audit of AI agent tool calls)
**Researched:** 2026-04-05
**Confidence:** HIGH

## Executive Summary

CloneGuard v2 is a universal agentic defense layer that operates at Layer 0 — before any agent reads repo content, from a position the agent cannot compromise. The research confirms a clear competitive gap: no existing product (Cisco AI Defense, Lakera Guard, LlamaFirewall, Microsoft AGT, Snyk/Invariant) intercepts tool calls at the hook/OS boundary. All competitors operate at the network, API, library, framework, or offline-scan level. CloneGuard's architectural position — external to the agent's trust boundary, executed before tool call proceeds — is the primary differentiation and must not be compromised by design decisions that move logic inside the agent or into a cloud service.

The recommended approach is a five-phase modular decomposition of the current monolithic `hooks.py` + `scanner.py`. The pipeline runs strictly linear: Input Adapter → Detection Engine → Policy Engine → Enforcement Layer → Audit Layer, connected by immutable typed dataclasses. The adapter-first architecture is critical: normalizing all agent events to a `ToolCallEvent` at the boundary makes everything downstream agent-agnostic. The competitive threat from Microsoft AGT (released 2026-04-02, 10/10 OWASP coverage claim) and AWS AgentCore Policy (Cedar-based, GA 2026-03-03) makes the differentiation story urgent: CloneGuard must ship its unique capabilities (hook-level interception, three-signal fusion, allow-but-constrain, honest adversarial evaluation) before the window closes.

The key risks are FPR explosion from naive signal fusion (Pitfall 1 — documented at 22.2% combined vs 9.2% standalone), enforcement becoming a DoS vector if deployed without dry-run gating (Pitfall 2), and detection engine extraction breaking the 20ms latency budget (Pitfall 3). All three are mitigable with the build order and calibration approach described in ARCHITECTURE.md. The EU AI Act Article 12 deadline (2026-08-02) creates a hard external forcing function for structured audit logging — NDJSON output is not optional, it is a compliance deliverable.

## Key Findings

### Recommended Stack

The existing v0.5.0 stack (Python 3.11+, PyYAML, ONNX Runtime, hatchling) is retained unchanged. The only promoted dependency is Pydantic v2 (already transitive via MCP SDK — zero marginal cost), which becomes the canonical internal event schema. All sandbox integration is via direct ctypes/subprocess — no PyPI wrapper libraries — because the two available options (`py-landlock` 0.1.1, `landlock` 1.0.0.dev5) are alpha-quality with no maintainer track record; the syscall ABI is stable and 100-300 LOC of ctypes code is lower risk than an unmaintained security-critical dependency.

Policy backends follow an optional extras pattern: YAML is built-in and covers 80%+ of users; `regopy` (1.3.0, in-process OPA Rego) and `cedarpy` (4.8.0, Rust bindings) are `[policy-opa]` and `[policy-cedar]` extras for enterprises already using those systems. Total new required dependencies: 1 (Pydantic promotion). Total new optional: up to 4. This is an extremely conservative dependency budget for a security tool.

**Core technologies:**
- Python 3.11+: Runtime — existing codebase, no reason to change
- Pydantic v2 (>=2.12.5): Internal event schema — already transitive, zero marginal cost, Rust core gives sub-ms validation
- PyYAML (>=6.0.2): Policy + rule parsing — existing, fast, C-backed
- ONNX Runtime (>=1.17): MiniLM inference — existing, CPU, no GPU dependency
- Landlock via ctypes: Linux enforcement — kernel ABI stable, no PyPI wrapper
- macOS sandbox-exec (subprocess): macOS enforcement — deprecated CLI but functional; adapter interface abstracts the replacement risk
- regopy (>=1.3.0) [optional]: In-process OPA Rego — Microsoft-backed, no OPA server required
- cedarpy (>=4.8.0) [optional]: Cedar policy — Rust-backed, AWS AgentCore-compatible
- sarif-pydantic (>=0.6.2) [optional]: SARIF 2.1.0 output — Pydantic v2-native, replaces unmaintained sarif-om
- opentelemetry-sdk (>=1.40.0) [optional]: OTel spans — CNCF-graduated, GenAI semantic conventions

### Expected Features

**Must have (table stakes — v1.0):**
- Prompt injection detection (direct + indirect) — 204 regex + MiniLM ONNX + SEQ already ships
- Structured audit logging (NDJSON) — EU AI Act Article 12 deadline 2026-08-02
- SARIF 2.1.0 output — GitHub Advanced Security integration; every SAST tool emits it
- Policy-configurable verdicts (YAML minimum) — binary allow/block is disqualifying in enterprise procurement
- Multi-agent-platform support — single-agent lock-in is a deal-breaker; Claude Code done, Gemini CLI is near-free
- Sub-50ms detection latency — already <20ms; must be preserved through refactoring
- CLI + library installation via uv/pipx — packaging fix needed for standalone binary
- Hook config integrity self-check — prevents CVE-2025-59536-class config tampering

**Should have (competitive differentiators — v1.x):**
- Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) with Allow-But-Constrain — no competitor does this
- Sandbox adapter interface (Landlock/Seatbelt/Noop) — hook-level enforcement is unique
- Input adapter abstraction (AGT, MCP, Cursor) — gateway to multi-agent market
- Package hallucination detection (slopsquatting) — 20% of AI-generated code includes hallucinated packages; no hook-based tool catches this at install time
- OTel span emission — SOC team observability correlation
- Three-signal fusion with trajectory calibration — 208K trajectory dataset is a 2+ year moat
- CaMeL-lite SEQ rule expansion (browser, CI/CD, MCP patterns)

**Defer to v2+:**
- OPA/Rego + Cedar policy backends — only needed when enterprises already have OPA/Cedar
- MELON selective re-execution (arXiv:2502.05174, ICML 2025) — research-grade complexity; prove fusion first
- Browser agent patterns + CDP adapter — market not mature enough
- Advanced sandboxes (gVisor, Firecracker, WASM) — Landlock + Seatbelt cover 90% of workstations
- Fleet deployment tooling — enterprise feature, needs customer pull

**Explicit anti-features (do not build):**
- SaaS/cloud-hosted detection — violates the trust model; agent or attacker can intercept/block
- Custom ML model training platform — IPI Arena retraining showed unacceptable FPR regression (9% → 20-42%)
- Full governance framework — CloneGuard is a sensor that feeds governance, not a governance platform
- Real-time dashboard/web UI — months of engineering that does not improve detection quality
- Claims of "blocking all attacks" — 16.7% bypass rate against adaptive Opus is documented; honesty is a trust differentiator

### Architecture Approach

The architecture decomposes the current ~2,000-line monolith across five bounded subsystems connected by immutable dataclasses. Every boundary uses `typing.Protocol` (PEP 544 structural subtyping) so third-party adapters can satisfy the interface without inheriting from CloneGuard base classes — critical for the AGT ToolCallInterceptor integration where CloneGuard must conform to Microsoft's interface. The existing `hooks.py` and `scanner.py` become thin shims (~10 lines each) that construct a `RuntimeOrchestrator` and delegate; backward compatibility with v0.5.0 is non-negotiable. The three module-level singletons in the current codebase (`_engine`, `_mini_classifier`, `_mini_attempted`) must be replaced with constructor injection in `RuntimeOrchestrator` to support testing, parallel execution, and library import.

**Major components:**
1. Input Adapters (`adapters/`) — normalize agent-specific protocol JSON into `ToolCallEvent` dataclass; all agent-specific parsing lives here, never in the detection engine
2. Detection Engine (`detection/`) — three signals (PatternEngine, SemanticClassifier, SequenceAnalyzer) fused by FusionLayer into calibrated `DetectionResult`; extract from `hooks.py` without architectural changes first, add fusion layer after
3. Policy Engine (`policy/`) — maps `DetectionResult` + `ToolCallEvent` + operator config to `PolicyDecision` (ALLOW/CONSTRAIN/BLOCK); strictly a decision function, never a detection function
4. Enforcement Layer (`enforcement/`) — `SandboxAdapter` Protocol with `NoopAdapter` (default), `LandlockAdapter`, `SeatbeltAdapter`; auto-detects available capability at startup via `probe.py`
5. Audit Layer (`audit/`) — `EventBuilder` assembles `AuditEvent` from all pipeline stages; emitters for NDJSON, SARIF, OTel run in parallel on the same event; audit emitter failures must not block other emitters

**Build order:** Types → Detection extraction → Audit (NDJSON+SARIF) → Policy (YAML) → Enforcement (Noop) → Orchestrator + shims → Real sandboxes + adapters → Enterprise policy backends

### Critical Pitfalls

1. **FPR explosion from signal fusion** — Naive `max(scores)` or `any(fires)` fusion pushes combined FPR to 22.2% (measured). Calibrate the FusionLayer on the 208K trajectory dataset before shipping. Set SUSPICIOUS floor at 0.5+ at launch. Track FPR by content type, not only aggregate.

2. **Enforcement as DoS vector** — Sandbox constraints that miscapture benign developer workflows silently break tools with opaque OS errors. Ship NoopAdapter as default; require explicit opt-in; run dry-run mode for ≥2 weeks of real usage before enabling enforcement; every constraint denial must surface a CloneGuard-attributed error, not a raw "Permission denied."

3. **Detection engine extraction breaks 20ms budget** — Abstraction layers (Protocol dispatch, dataclass allocation, event normalization) compound in Python. Establish a benchmark regression gate in CI before extraction begins. Keep the hot path zero-copy for the Claude Code common case. Extraction should be mechanical (move functions, update imports), not architectural.

4. **Exit code backward compatibility** — The three-verdict model must not introduce a third exit code. SUSPICIOUS + NoopAdapter = exit 0 (warning on stdout). SUSPICIOUS + real sandbox = apply constraints out-of-band, return exit 0. MALICIOUS = exit 2. Reserve exit 1 for CloneGuard internal errors. Test against all four hook protocols (Claude Code, Gemini CLI, Cursor, Windsurf).

5. **Layer 0 trust invariant** — Any code path where sandbox adapter or policy engine reads a file from the repo root violates the Layer 0 security property (repo content must not influence enforcement posture). Enforcement config lives exclusively in `~/.cloneguard/`. Add a CI check that greps for `Path.cwd()` reads in sandbox/policy initialization code.

6. **Input adapter abstraction leaks protocol semantics** — Too-tight normalization discards protocol-specific signals needed for detection (e.g., MCP tool descriptions for tool poisoning). Design: core required fields + `extra` dict for protocol-specific context. Test the same attack payload through every adapter; detection must not regress as adapters are added.

7. **Seatbelt deprecation (macOS platform risk)** — Apple deprecated `sandbox-exec` in macOS 10.15. No replacement programmatic sandboxing API exists for unprivileged CLI tools. Implement SeatbeltAdapter behind the adapter interface so it can be swapped. Monitor WWDC annually. Do not make macOS enforcement load-bearing for the value proposition.

## Implications for Roadmap

Based on the combined research, the architecture's Phase A-G build order maps directly to the following product phases. The ordering is constrained by type dependencies (types before components), the 20ms latency non-negotiable (benchmark gate before extraction), and the EU AI Act deadline (NDJSON by August 2026).

### Phase 1: Foundation — Core Types, Detection Extraction, and Audit

**Rationale:** Detection engine extraction is the highest-risk refactor in the entire project (touching 2,000+ LOC of production code). Do it first, while the codebase is otherwise stable, with a benchmark regression gate. NDJSON audit follows immediately because it is the EU AI Act Article 12 compliance deliverable and the simplest subsystem to build. SARIF adds GitHub Advanced Security integration at low marginal cost. The result: existing v0.5.0 users see identical behavior via thin shims, while the architecture is now ready for all subsequent phases.

**Delivers:** Modular detection engine with typed contracts; backward-compatible thin shims; NDJSON structured audit (EU AI Act ready); SARIF 2.1.0 output (GitHub Security tab); packaging fix (uv/pipx); hook config integrity self-check; benchmark regression CI gate

**Addresses (FEATURES.md):** Structured audit logging, SARIF output, sub-50ms latency preservation, CLI installation, hook config integrity

**Avoids (PITFALLS.md):** Detection extraction latency regression (benchmark gate), triple emission maintenance burden (NDJSON + SARIF only in Phase 1), audit event raw content leak (hash tool_input in schema from day one)

### Phase 2: Adaptive Enforcement — Policy Engine and Sandbox Adapters

**Rationale:** Policy engine must exist before enforcement — the `PolicyDecision.constraints` type defines what enforcement implements. The three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) requires policy before it can produce differentiated outcomes. NoopAdapter ships alongside policy to prove the interface before introducing OS-level complexity. Landlock and Seatbelt adapters ship after NoopAdapter is proven. Dry-run mode with structured logging is the default; explicit opt-in is required for active enforcement.

**Delivers:** YAML policy engine; three-verdict model (SAFE/SUSPICIOUS/MALICIOUS); Allow-But-Constrain enforcement; NoopAdapter (default); LandlockAdapter (Linux); SeatbeltAdapter (macOS); sandbox capability auto-detection; dry-run mode; exit code compatibility matrix; Layer 0 trust boundary enforcement

**Uses (STACK.md):** Pydantic v2 for `PolicyDecision`/`ConstraintSet` models; ctypes/subprocess for Landlock/Seatbelt; Pydantic config schema for `~/.cloneguard/`

**Avoids (PITFALLS.md):** Enforcement as DoS (dry-run default, explicit opt-in), exit code backward compatibility (SUSPICIOUS = exit 0), Layer 0 trust invariant (enforcement reads only `~/.cloneguard/`), policy engine becoming second detection engine (IR excludes content fields)

### Phase 3: Framework Integration — Input Adapter Abstraction and Multi-Agent Support

**Rationale:** Input adapter abstraction is the gateway to the multi-agent market. It cannot be built correctly in Phase 1 without existing enforcement and audit infrastructure to test end-to-end. MCP middleware is the highest-value non-hook adapter (30+ CVEs in 60 days, OWASP ASI-04, MITRE ATLAS "Publish Poisoned AI Agent Tool" technique). AGT ToolCallInterceptor plugin positions CloneGuard as a sensor within Microsoft's governance pipeline. OTel spans ship here (after NDJSON/SARIF are proven) as an enterprise observability integration.

**Delivers:** `InputAdapter` Protocol with `ToolCallEvent` normalization; Gemini CLI adapter (near-free via `gemini hooks migrate --from-claude`); Cursor adapter; MCP protocol middleware (request + response scanning); AGT ToolCallInterceptor plugin; OTel span emission; CI/CD runner deployment (GitHub Actions); package hallucination detection (slopsquatting via registry cross-reference)

**Uses (STACK.md):** `mcp` SDK (1.26.0) for MCP middleware; `agent-governance-toolkit` (3.0.1) interface for AGT plugin; `opentelemetry-sdk` (1.40.0) for OTel; `opentelemetry-api` (separate from SDK for consumers)

**Avoids (PITFALLS.md):** Input adapter detection leakage (core fields + `extra` dict; same-attack cross-adapter test suite), OTel cardinality explosion (semantic conventions, no dynamic span names), MCP response blind spot (intercept both request and response)

### Phase 4: Detection Excellence — Three-Signal Fusion and Calibration

**Rationale:** Three-signal fusion is deferred until Phase 4 deliberately. Phases 1-3 give production usage data: real confidence distributions across real agent types with real benign baselines. Calibrating FusionLayer on production data rather than only the 208K coding-trajectory dataset produces significantly better weights for MCP, CI/CD, and browser agent contexts. MELON selective re-execution (arXiv:2502.05174, ICML 2025) follows as an additive layer on top of proven fusion, not as a replacement for it.

**Delivers:** Calibrated FusionLayer with per-agent-type weights; per-signal weight functions keyed to scan mode (STRICT/STANDARD/LENIENT); per-content-type FPR tracking (CI configs, security docs, test fixtures separately); cross-agent pattern libraries (browser/, cicd/, mcp/, common/); MELON selective re-execution (opt-in, circuit breaker, per-agent-type zone configuration)

**Uses (STACK.md):** Existing ONNX Runtime + 208K trajectory dataset + production data; MELON algorithm reimplemented from arXiv:2502.05174 (not the reference repo — research code, not production-ready)

**Avoids (PITFALLS.md):** FPR explosion (calibrated FusionLayer, not max/any), MELON cost explosion (circuit breaker at >15% trigger rate, per-agent-type zones, opt-in), fusion calibration without auth-paradox test (run Campbell et al. auth-marker FPR test on the fused pipeline)

### Phase 5: Enterprise Governance — OPA, Cedar, and Fleet

**Rationale:** OPA/Rego and Cedar policy backends are deferred until enterprises actually use them and demand integration. Phase 4 must demonstrate stable detection before adding policy complexity. Fleet deployment tooling (MDM/Ansible) requires customer pull to justify the engineering investment. SPIFFE agent identity belongs here as a zero-trust enterprise feature.

**Delivers:** OPA/Rego policy backend (`regopy` in-process); Cedar policy backend (`cedarpy` Rust bindings); OPA WASM compilation for single-binary deployment; policy composition and inheritance for multi-site enterprises; fleet deployment tooling; SIEM integration guides (NDJSON to Splunk HEC, Sentinel, Elasticsearch); SPIFFE identity on audit events; ISO 42001 A.6.2.8 compliance documentation

**Uses (STACK.md):** `regopy` (1.3.0), `cedarpy` (4.8.0)

**Avoids (PITFALLS.md):** Policy engine becoming detection engine (IR schema validation rejects content-accessing fields), OPA IPC cost (in-process `regopy` or WASM, not subprocess OPA binary), OPA bundle MITM (cryptographic signature verification, local-only default)

### Phase Ordering Rationale

- **Types and extraction before everything** (Phase 1): The detection engine extraction is a 2,000-LOC refactor with a 20ms latency non-negotiable. It must happen with nothing else in flight and with a benchmark gate established in CI first. The build order is strictly bottom-up: types → extraction → audit → policy → enforcement → orchestrator → adapters → enterprise.
- **Audit before policy** (Phase 1 before Phase 2): NDJSON audit provides immediate EU AI Act Article 12 compliance value and validates the `AuditEvent` schema that every subsequent phase serializes.
- **Policy before enforcement** (Phase 2 ordering): `PolicyDecision.constraints` type must be defined before any sandbox adapter can implement it. Building enforcement without policy produces an untestable sandbox.
- **Enforcement with dry-run default** (Phase 2): The enforcement-as-DoS risk is the highest user-facing risk in the project. Dry-run mode for ≥2 weeks is required before active enforcement is default-on.
- **Adapters after core is proven** (Phase 3): Input adapter abstraction built on top of production detection + policy + enforcement gives a real end-to-end system to test against, not a stub pipeline.
- **Fusion calibration after production data** (Phase 4): The 208K coding-trajectory dataset is a good calibration baseline but covers only one agent type. MCP, CI/CD, and browser agent confidence distributions are unknown until Phase 3 ships adapters that collect real data.
- **Enterprise backends last** (Phase 5): OPA and Cedar add external dependencies and integration complexity. They should follow, not lead, the product's proven detection and enforcement capabilities.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 2 (Sandbox Adapters):** Landlock ABI v5 unprivileged operation; Seatbelt profile syntax for common developer tool constraints; subprocess vs. ctypes performance for per-call application. The "apply constraints to subprocess, not self" requirement (Pitfall 10 + Integration Gotchas) has non-obvious implementation implications.
- **Phase 3 (MCP Middleware):** MCP SDK response interception API surface; how MCP servers handle CloneGuard as a proxy. MCP protocol evolves rapidly (30+ CVEs in 60 days); API research needed at planning time, not now.
- **Phase 4 (MELON):** The ICML 2025 paper describes the algorithm clearly, but the production integration (masked re-execution in a constrained execution context with no network access) requires design work. MELON's known failure modes in response-based attacks (72.73%) need mitigation strategy for non-coding agent types.

Phases with standard patterns (skip research):
- **Phase 1 (Detection Extraction + NDJSON/SARIF):** Well-documented refactoring patterns. NDJSON is stdlib `json` + `\n`. SARIF 2.1.0 is a published OASIS specification with `sarif-pydantic` providing Pydantic v2 models. No research needed beyond validating output against OASIS schema.
- **Phase 5 (OPA/Cedar backends):** `regopy` and `cedarpy` are documented PyPI packages with Python examples. The integration is additive behind the existing `PolicyBackend` Protocol.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM-HIGH | Versions verified via PyPI dry-run. Sandbox libraries (Landlock ctypes, Seatbelt subprocess) are technically straightforward but the "apply to subprocess, not self" architecture has not been prototyped. Seatbelt deprecation is a known unknown. |
| Features | HIGH | Competitive landscape well-documented via primary sources. OWASP/MITRE/EU AI Act deadlines are fixed. Feature dependencies mapped end-to-end in FEATURES.md. |
| Architecture | HIGH | Build order is constrained by dependency graph, not preference. Typed contract pattern is proven in Python production systems. Anti-patterns are grounded in the existing codebase's failure modes. |
| Pitfalls | HIGH | Grounded in CloneGuard's own empirical FPR measurements, documented production failures in adjacent tools, and peer-reviewed research (Campbell et al. arXiv:2603.01246). Not theoretical. |

**Overall confidence:** HIGH

### Gaps to Address

- **Fusion calibration for non-coding agent types:** The 208K trajectory dataset covers SWE-bench coding workflows only. MCP, browser, CI/CD, and financial agent workflows have different benign baselines. Plan to collect trajectory data from each new adapter type as Phase 3 ships. Do not set SUSPICIOUS floor below 0.5 until per-agent-type calibration data exists.
- **Landlock "apply to subprocess" prototype:** The integration gotcha (Landlock restrictions are inherited by child processes and cannot be removed; apply only to the subprocess executing the tool call, not to the CloneGuard process itself) is architecturally important but not yet prototyped. This needs a ≤1-day spike at the start of Phase 2 to confirm feasibility before the full adapter implementation.
- **macOS Seatbelt deprecation replacement:** No confirmed replacement API exists for unprivileged programmatic sandboxing on macOS without `.app` bundle entitlements. WASM-based sandboxing (Wasmtime) is a cross-platform alternative but with different isolation semantics. This is a known long-term risk that must be re-evaluated at each macOS major release.
- **Trust cache concurrency:** Current JSON-file trust cache is not safe for concurrent agent sessions. This is documented as technical debt (SQLite or similar needed). Acceptable for Phase 1 (single-session), must be resolved before multi-session enterprise deployment.
- **Gemini CLI hook protocol version stability:** `gemini hooks migrate --from-claude` is confirmed, but the protocol is not formally versioned. Pin to verified version and test in CI against both Claude Code and Gemini CLI.

## Sources

### Primary (HIGH confidence)
- [EU AI Act Article 12: Record-Keeping](https://artificialintelligenceact.eu/article/12/) — logging requirements for high-risk AI systems, 2026-08-02 enforcement deadline
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — ASI-01 through ASI-06 risk framework
- [MITRE ATLAS](https://atlas.mitre.org/) — AML.T0051, "Publish Poisoned AI Agent Tool" technique
- [MELON paper](https://arxiv.org/abs/2502.05174) — arXiv:2502.05174v4, ICML 2025
- [Landlock kernel docs](https://docs.kernel.org/userspace-api/landlock.html) — stable kernel ABI
- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/) — agent span standards
- [PEP 544 — Protocols: Structural Subtyping](https://peps.python.org/pep-0544/) — Python Protocol class specification
- PyPI packages verified via `uv pip install --dry-run`: cedarpy 4.8.0, regopy 1.3.0, sarif-pydantic 0.6.2, opentelemetry-sdk 1.40.0, agent-governance-toolkit 3.0.1, mcp 1.26.0

### Secondary (MEDIUM confidence)
- [Microsoft AGT release](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) — 2026-04-02, 10/10 OWASP coverage claim
- [AWS Bedrock AgentCore Policy GA](https://aws.amazon.com/blogs/aws/amazon-bedrock-agentcore-adds-quality-evaluations-and-policy-controls-for-deploying-trusted-ai-agents/) — Cedar-based, GA 2026-03-03
- [LlamaFirewall](https://ai.meta.com/research/publications/llamafirewall-an-open-source-guardrail-system-for-building-secure-ai-agents/) — PromptGuard 2 + AlignmentCheck + CodeShield architecture
- [Slopsquatting research](https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks) — 20% hallucination rate, 43% recurrence
- [Bessemer 2026 agentic security analysis](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026) — market sizing, 48% cite agentic AI as top attack vector
- CloneGuard empirical data: 208K trajectory dataset, SEQ-004 FPR 15.80%, combined pipeline FPR 22.2% vs 9.2% standalone, 16.7% adaptive bypass rate (Opus iterative)
- Campbell et al. arXiv:2603.01246 (ICLR 2026 Workshop) — authorization preamble FPR amplification

### Tertiary (LOW confidence)
- [Agent sandbox comparison](https://pierce.dev/notes/a-deep-dive-on-agent-sandboxes) — community analysis, Seatbelt deprecation notes
- [MCP Security 2026: 30 CVEs in 60 Days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/) — attack surface characterization

---
*Research completed: 2026-04-05*
*Ready for roadmap: yes*
