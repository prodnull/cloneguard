# Pitfalls Research

**Domain:** Universal agentic defense layer (detection + enforcement + audit)
**Researched:** 2026-04-05
**Confidence:** HIGH (grounded in CloneGuard's own empirical data, published research, and documented production failures in adjacent tools)

## Critical Pitfalls

### Pitfall 1: FPR Explosion from Signal Fusion

**What goes wrong:**
Combining three detection signals (regex + semantic + sequence) with independent false positive rates does not produce a lower combined FPR. Naive fusion (any-signal-fires = alert) multiplies the effective FPR. CloneGuard already measures this: combined pipeline FPR is 22.2% versus Tier 1.5 standalone at 9.2%. Adding a third signal (SEQ rules, especially SEQ-004 at 15.80% FPR) without calibrated weighting will push the combined FPR to intolerable levels, particularly in SUSPICIOUS verdict territory where the system must decide between constrain-and-continue versus block.

**Why it happens:**
Teams treat fusion as `max(scores)` or `any(fires)` because it is simple. The actual problem is that the three signals have correlated failure modes on defensive security content (Campbell et al., ICLR 2026 Workshop, arXiv:2603.01246 -- authorization preambles increase Tier 1.5 FPR from 9.25% to 21.93%). When signals correlate on false positives, fusion amplifies rather than cancels noise.

**How to avoid:**
- Calibrate the fusion layer on the 208K trajectory dataset before shipping. The dataset exists; use it.
- Define per-signal weight functions that account for scan mode (STRICT/STANDARD/LENIENT), not flat weights.
- Set the SUSPICIOUS floor conservatively high (0.5+) at launch. Lower it only after production FPR data confirms safety.
- Track FPR by content type (CI configs, security docs, test fixtures) separately -- aggregate FPR hides category-specific regression.
- The trajectory dataset covers SWE-bench coding workflows only. MCP, browser, CI/CD, and financial agent workflows have different benign baselines. Fusion weights calibrated on coding data will misfire on other agent types until new trajectory data is collected.

**Warning signs:**
- Combined FPR exceeds 5% on held-out benign corpus during integration testing.
- SUSPICIOUS verdicts dominate over SAFE in normal coding sessions (indicates floor is too low).
- Users disable the system or set all rules to advisory within the first week of deployment.

**Phase to address:**
Phase 4 (Detection Excellence) -- fusion calibration is the primary deliverable. But Phase 2 (Adaptive Enforcement) must ship with conservative thresholds that Phase 4 can later tighten, not the reverse.

---

### Pitfall 2: Enforcement Layer Becomes a Denial-of-Service Vector

**What goes wrong:**
Moving from detection-only (exit 0 / exit 2) to enforcement (sandbox constraints) means that a false positive in the enforcement path now silently breaks the user's workflow rather than merely warning. A SUSPICIOUS verdict that restricts network access will break `npm install`. A filesystem restriction that scopes writes to `${PROJECT_DIR}` will break tools that write to `/tmp` or `~/.cache`. Users cannot diagnose why their agent "stopped working" because the constraint is invisible -- the sandbox silently denies the syscall and the tool fails with a cryptic error.

**Why it happens:**
Enforcement is designed around the threat model (what an attacker would do) rather than the benign baseline (what a developer's tools actually need). The constraint policy is written by security engineers who test against attack scenarios, not against the full diversity of legitimate developer workflows. Landlock's irreversible restrictions compound this -- once a restriction is applied for a SUSPICIOUS call, it cannot be relaxed for the next call in the same process.

**How to avoid:**
- Ship NoopAdapter as default for the first release of enforcement. Require explicit opt-in to Landlock/Seatbelt.
- Log every constraint that would have been applied in "dry-run" mode for at least 2 weeks of real usage before enabling enforcement.
- Define a minimum set of always-allowed paths (`/tmp`, `~/.cache`, `${PROJECT_DIR}`) that no constraint policy can restrict.
- Make constraints per-call, not per-session. Each tool invocation should get fresh constraint evaluation. Do not accumulate restrictions across calls (Landlock's design fights this -- see Technical Debt Patterns below).
- Ensure sandbox failures surface as CloneGuard-attributed errors, not opaque OS errors. If Seatbelt denies a write, the user must see "CloneGuard: write to /path blocked by SUSPICIOUS verdict" not "Permission denied."

**Warning signs:**
- Users report "npm install fails sometimes" or "git push hangs" with no pattern they can identify.
- Support tickets spike after enforcement is enabled with no corresponding increase in actual attacks detected.
- `NoopAdapter` usage remains at 100% after enforcement ships, indicating nobody trusts the sandbox.

**Phase to address:**
Phase 2 (Adaptive Enforcement). The sandbox adapter interface and NoopAdapter fallback are designed to mitigate this, but dry-run mode with structured logging must be the Phase 2 default, not an afterthought.

---

### Pitfall 3: Detection Engine Extraction Breaks the 20ms Budget

**What goes wrong:**
The current detection engine is co-located with hooks.py -- 499 lines that import patterns.py (313 lines), mini_semantic.py (429 lines), and monitor.py (1,092 lines). Extracting the detection engine into a standalone module to support multiple input adapters introduces abstraction layers (adapter interfaces, event normalization, verdict objects) that add overhead. Each additional function call, dict copy, or Protocol dispatch in the hot path adds microseconds that compound across the 204 regex patterns and 16-chunk sliding window. The 20ms budget is already tight: Tier 0+1.5 measures <50ms for regex + ~16ms for ONNX classification.

**Why it happens:**
Abstraction layers are designed for correctness and extensibility, not for latency. The natural refactoring pattern is to create a `DetectionEngine` class that accepts normalized events and returns verdicts through a clean interface. But normalization means copying/transforming the input dict, the clean interface means virtual dispatch through Protocol methods, and the verdict object means allocating dataclasses on every call. In Python, these costs are non-trivial at hook-invocation frequency.

**How to avoid:**
- Profile before and after extraction. Establish a regression benchmark that runs in CI: `bench/benchmark.py` already exists; extend it to cover the refactored path.
- Keep the hot path zero-copy where possible. The input adapter should pass the raw dict through to the pattern engine without intermediate normalization in the common case (Claude Code hook protocol). Only non-Claude adapters pay the normalization cost.
- Avoid ABC/Protocol dispatch in the per-invocation path. Use concrete classes with `if isinstance()` checks (ugly but measurably faster in CPython) for the 2-3 input adapter types that will exist initially.
- The extraction should be mechanical (move functions, update imports) not architectural (new abstractions). Add the adapter interface as a thin layer on top of the extracted module, not as the extraction's organizing principle.

**Warning signs:**
- p95 latency exceeds 25ms in CI benchmark after refactoring.
- New `__init__` or `__call__` methods that allocate dicts or lists on every invocation.
- The refactored module has more lines than the sum of the files it replaced.

**Phase to address:**
Phase 1 (Foundation) -- detection engine extraction is explicitly listed. The benchmark regression gate must be established before the extraction begins, not after.

---

### Pitfall 4: Backward Compatibility Regression in Exit Code Semantics

**What goes wrong:**
v0.5.0 defines a clear contract: exit 0 = allow, exit 2 = block. The three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) introduces CONSTRAIN as a third behavior. If the exit code for SUSPICIOUS differs from 0 (allow), existing Claude Code hook configurations that only expect 0 or 2 will treat any non-zero exit as a failure and either crash or ignore the hook entirely. If SUSPICIOUS maps to exit 0 (same as SAFE), the constraint information has no channel to reach the caller -- stdout is the only communication path in the Claude Code hook protocol.

**Why it happens:**
The Claude Code hook protocol was designed for binary decisions. It has no concept of "allow with constraints." The protocol documentation (verified in hooks API reference) specifies JSON on stdout for messaging, but exit codes drive the allow/block decision. Introducing a third verdict requires either: (a) overloading exit 0 with additional stdout JSON (CONSTRAIN metadata), which existing hooks won't understand; or (b) using a new exit code (e.g., exit 1 for CONSTRAIN), which may break agents that interpret exit 1 as an error.

**How to avoid:**
- SUSPICIOUS with NoopAdapter must produce exit 0 with a warning on stdout. This is functionally identical to the current WARNING behavior and breaks nothing.
- SUSPICIOUS with a real sandbox adapter applies constraints outside the hook protocol (the sandbox is a separate mechanism) and still returns exit 0 to the hook. The constraint is enforced by the sandbox, not by the exit code.
- MALICIOUS always produces exit 2. No change.
- Document the exit code contract explicitly in a compatibility matrix. Test it against Claude Code, Gemini CLI (11 events), Cursor (19+ events), and Windsurf (12 events) hook protocols.
- Never introduce exit 1 as a verdict. Reserve it for CloneGuard internal errors (as it implicitly is now).

**Warning signs:**
- Any test that checks `exit_code == 2` for a SUSPICIOUS verdict.
- Hook configuration documentation that mentions three exit codes.
- Agent-side error logs showing "hook returned unexpected exit code."

**Phase to address:**
Phase 2 (Adaptive Enforcement) -- three-verdict model introduction. The exit code compatibility matrix must be part of the Phase 2 design review, not a post-implementation discovery.

---

### Pitfall 5: Seatbelt Deprecation Creates a macOS Platform Risk

**What goes wrong:**
The SeatbeltAdapter depends on macOS's `sandbox-exec`, which Apple has marked as DEPRECATED since macOS 10.15. Apple provides no replacement API for programmatic unprivileged sandboxing. The App Sandbox alternative requires `.app` bundles with entitlements, which is incompatible with CLI tools installed via `uv tool install` or `pipx`. If Apple removes `sandbox-exec` in a future macOS release, CloneGuard loses its macOS enforcement capability entirely.

**Why it happens:**
Apple's internal sandboxing infrastructure (Seatbelt profiles) powers the App Sandbox, Safari, and system daemons. The `sandbox-exec` CLI is an unofficial public interface to this infrastructure. Apple has deprecated the CLI without deprecating the underlying infrastructure, creating uncertainty. Anthropic's Claude Code itself uses `sandbox-exec` for its own sandboxing, so there is alignment risk -- if Apple removes it, both CloneGuard and its primary integration target break simultaneously.

**How to avoid:**
- Implement SeatbeltAdapter, but do not make it load-bearing for the macOS value proposition. Detection (NoopAdapter + all tiers) provides value without enforcement.
- Monitor Apple's WWDC announcements and macOS release notes each June. If a replacement API is announced, begin migration immediately.
- Design the adapter interface so that SeatbeltAdapter can be swapped for a future macOS sandbox mechanism without changing any code above the adapter layer.
- Consider WASM-based sandboxing (Extism, Wasmtime) as a cross-platform alternative that works on macOS without Seatbelt. This is not a 1:1 replacement (different isolation model) but provides filesystem/network restriction capabilities.

**Warning signs:**
- Apple removes `sandbox-exec` from macOS beta releases.
- Claude Code switches away from `sandbox-exec` to a different sandboxing mechanism.
- New macOS versions break specific Seatbelt profile directives that CloneGuard depends on.

**Phase to address:**
Phase 2 (Adaptive Enforcement) for initial SeatbeltAdapter. Phase 6 (Agent Type Expansion) for WASM fallback. The adapter interface design in Phase 2 must accommodate this swap.

---

### Pitfall 6: Policy Engine IR Becomes a Second Detection Engine

**What goes wrong:**
The policy engine is designed to evaluate verdicts + context and produce enforcement decisions. Over time, teams add detection logic to policy rules: "if tool_name == 'Bash' and input contains 'curl' and verdict == SAFE, override to SUSPICIOUS." The policy engine gradually accumulates detection heuristics that duplicate, conflict with, or shadow the actual detection engine. Two separate codepaths now produce verdicts, with different update cycles, different testing, and different FPR characteristics.

**Why it happens:**
Enterprise customers demand custom rules that express domain-specific security concerns ("block all writes to /prod/" or "any tool call to S3 is MALICIOUS"). These are legitimate policy requirements, but they blend detection logic (analyzing content) with enforcement logic (deciding what to do about a verdict). The YAML/OPA/Cedar policy backends all have the expressiveness to implement arbitrary detection logic, and operators will use that expressiveness.

**How to avoid:**
- Define and enforce a strict separation: the detection engine produces verdicts (SAFE/SUSPICIOUS/MALICIOUS with confidence and matched rules). The policy engine maps verdicts to actions (ALLOW/CONSTRAIN/BLOCK with specific constraints). The policy engine never inspects tool content directly -- it only sees verdict, confidence, tool_name, tool_input_hash (not content), agent_type, and session context.
- The policy IR should have no string matching or regex operators. If a customer needs content-aware rules, those belong in the pattern engine as YAML rule files, not in the policy layer.
- Document this boundary in the architecture. Name it. ("The policy engine is a decision function, not a detection function. If you need to detect, add a pattern.")

**Warning signs:**
- Policy rules that reference `tool_input` content (not just metadata).
- Policy rules that produce SUSPICIOUS or MALICIOUS verdicts (the policy engine should only produce actions, not verdicts).
- Enterprise customers maintaining parallel "detection policies" and "enforcement policies" in the same OPA/Rego namespace.

**Phase to address:**
Phase 2 (Adaptive Enforcement) -- policy engine design. The IR schema must exclude content inspection fields. Phase 5 (Enterprise Governance) must enforce this boundary when adding OPA/Rego and Cedar backends.

---

### Pitfall 7: MELON Selective Triggering Misjudges the Ambiguity Zone

**What goes wrong:**
MELON's masked re-execution doubles API costs. Selective triggering (only fire MELON when fusion confidence is 0.4-0.6) is designed to limit this overhead to ~5-10% of calls. But the confidence distribution is not uniform -- it clusters. If the cluster falls inside the ambiguity zone (because the classifier is systematically uncertain about a common content type), MELON fires on 30-50% of calls instead of 5-10%, creating unacceptable latency and cost. Conversely, if the ambiguity zone is set too narrow, MELON never fires and provides no value.

**Why it happens:**
The confidence zone is set based on calibration data (208K trajectories). But that data contains zero MCP interactions, zero browser agent sessions, and zero financial agent workflows. The confidence distribution for these new agent types is unknown. What looks like a narrow ambiguity zone on coding-agent data may be the dominant confidence range for browser-agent data.

Additionally, MELON's known failure modes are concentrated in response-based attacks (72.73% of MELON failures per the ICML paper) and tool call redundancy (15.15%). These categories are precisely the ones that matter for non-coding agent types (browser agents produce many response-based actions, autonomous agents have complex tool call graphs with redundancy).

**How to avoid:**
- Do not hardcode the ambiguity zone boundaries. Make them per-agent-type configurable.
- Ship MELON as opt-in with monitoring for the first release. Collect confidence distributions from real usage before setting default zone boundaries.
- Implement a circuit breaker: if MELON fires on >15% of calls in a rolling 100-call window, automatically widen the zone (raise the floor, lower the ceiling) until the rate drops below 10%.
- Accept that MELON may provide marginal value for non-coding agent types where response-based attacks dominate. Do not force it into agent types where its failure modes align with the primary threat.

**Warning signs:**
- MELON triggering rate exceeds 15% during integration testing with non-coding agent workflows.
- Confidence distributions show bimodal clustering with the valley inside the ambiguity zone.
- Users complain about doubled latency on "every other tool call."

**Phase to address:**
Phase 4 (Detection Excellence) -- MELON implementation. The circuit breaker and per-agent-type configuration must be part of the Phase 4 deliverable.

---

### Pitfall 8: Input Adapter Abstraction Leaks Protocol Semantics

**What goes wrong:**
The input adapter layer decouples CloneGuard from the Claude Code hook protocol. But each agent protocol has different semantics: Claude Code sends JSON on stdin with tool_name/tool_input/tool_result. Gemini CLI uses the same protocol (confirmed: `gemini hooks migrate --from-claude`). Cursor has 19+ events with different field names. MCP middleware sees requests/responses with different structure. The AGT ToolCallInterceptor receives a `ToolCallContext` object. The "normalized event" that the adapter produces must preserve enough information for the detection engine to work, but different protocols provide different information.

When the abstraction is too tight (common denominator), adapters discard protocol-specific information that the detection engine needs (e.g., MCP tool descriptions that are essential for tool poisoning detection). When the abstraction is too loose (union type of all fields), every adapter must handle fields it does not understand, and the detection engine must handle missing fields gracefully.

**Why it happens:**
This is the classic leaky abstraction problem, amplified by the security context. In a normal application, a leaky abstraction causes a feature to degrade. In a security tool, a leaky abstraction causes a detection gap -- an attack that would be caught under one adapter but not another because the normalization discarded the relevant signal.

**How to avoid:**
- Define the normalized event as a core set of required fields (event_type, tool_name, tool_input as string, source_path if applicable) plus an `extra` dict for protocol-specific fields. The detection engine can inspect `extra` when it knows the adapter type.
- The pattern engine must work on the core fields alone. Protocol-specific detection (MCP tool description scanning, Cursor-specific events) goes in protocol-specific pattern libraries, not the core engine.
- Test the same attack payload through every adapter and verify identical detection results for the core fields. Protocol-specific detection is additive (catches more), never subtractive (catches less).
- Start with Claude Code and MCP adapters only. Add others one at a time with per-adapter detection regression tests.

**Warning signs:**
- Detection tests that pass under one adapter but fail under another for the same payload content.
- The normalized event type has >15 fields (indicates the abstraction is too loose).
- Adapters that do string manipulation on tool_input before passing it to the detection engine (indicates the abstraction is too tight and the adapter is compensating).

**Phase to address:**
Phase 3 (Framework Integration) -- input adapter abstraction is the primary deliverable. The "same attack, every adapter" test suite must be built alongside the abstraction, not after.

---

### Pitfall 9: OTel + SARIF + NDJSON Triple Emission Creates Maintenance Burden Without Users

**What goes wrong:**
Emitting every event in three formats simultaneously sounds like maximum coverage. In practice, nobody consumes all three from the same deployment. SARIF goes to GitHub Advanced Security (if the user has it). OTel goes to their observability stack (if they have one). NDJSON goes to SIEM (if they have one). Building and maintaining three emitters from day one means: three serialization code paths to keep in sync, three integration test suites, three sets of consumer-specific quirks to handle (SARIF's severity levels are restricted to error/warning/note/none; OTel requires semantic conventions for span names to avoid cardinality explosion; NDJSON schemas vary by SIEM vendor).

**Why it happens:**
The design doc envisions CloneGuard as an enterprise tool. Enterprise tools must integrate with existing infrastructure. The instinct is to build all integrations upfront so that "we support your stack" is a day-one claim. But each format has significant integration complexity (SARIF 2.1.0 is a 225-page OASIS specification), and the priority should be getting one format right rather than three formats half-right.

**How to avoid:**
- Phase 1 ships NDJSON only. It is the simplest format, the most flexible (any consumer can parse it), and the one needed for EU AI Act Article 12 compliance logging (the first regulatory deadline: August 2, 2026).
- Phase 1 adds SARIF as the second format, because GitHub Advanced Security integration is the highest-value developer-facing integration.
- OTel spans are Phase 3 or later. They require understanding the deployment's collector configuration, trace context propagation, and span naming conventions. These are enterprise integration concerns, not core product concerns.
- Define the internal event schema first (the common model all three formats serialize from). All emitters are projections of this single schema. Never let a format-specific field leak into the internal schema.

**Warning signs:**
- SARIF output fails validation against the OASIS schema (indicates the implementation diverged from the spec).
- OTel spans have high-cardinality span names (e.g., including file paths or tool inputs) that explode metrics backends.
- Three separate test files for three formats that test different event payloads (indicates the formats are diverging from the common model).

**Phase to address:**
Phase 1 (Foundation) for NDJSON + SARIF. Phase 3 (Framework Integration) for OTel. The internal event schema must be designed in Phase 1 with all three formats in mind, even though only two are implemented.

---

### Pitfall 10: Layer 0 Trust Invariant Violated by Sandbox Adapter Initialization

**What goes wrong:**
Layer 0's security property is that it runs before the agent reads any files, from a position the agent cannot compromise. The sandbox adapter needs to be initialized before tool calls are constrained. If sandbox initialization reads configuration from the repository (e.g., a `cloneguard-policy.yaml` in the project root), an attacker can poison the policy file to weaken or disable sandbox constraints. This violates the Layer 0 invariant: repo content influencing the defense posture.

**Why it happens:**
Project-level policy customization is a legitimate feature request. Developers want to tune thresholds per-project ("this project legitimately uses curl in builds, don't constrain network for npm scripts"). The natural place for this configuration is a file in the repository. But any file in the repository is attacker-controlled by the threat model.

**How to avoid:**
- Project-level policy files can only relax advisory rules, never enforcement rules. Enforcement configuration lives exclusively in `~/.cloneguard/` (outside the repo, protected by the threat model).
- Project-level policy files are themselves scanned by Layer 0 before being loaded. If the policy file contains suspicious content, it is ignored and the default policy applies.
- The sandbox adapter reads only from `~/.cloneguard/config.yaml` (operator-controlled) and environment variables. Never from repo-resident files.
- Document this trust boundary explicitly: "Repo-resident configuration can tune detection sensitivity. It cannot weaken enforcement constraints."

**Warning signs:**
- Any code path where sandbox adapter reads a file from `Path.cwd()` or the repo root.
- Policy loading code that does not distinguish between operator-controlled and repo-controlled configuration sources.
- Tests that place policy files in the test repo fixture and expect them to affect enforcement behavior.

**Phase to address:**
Phase 2 (Adaptive Enforcement) -- policy engine design. This trust boundary must be defined in the Phase 2 architecture review and enforced with a CI check that greps for repo-path reads in the sandbox/policy initialization code.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Hardcoded Claude Code protocol parsing in detection engine | Faster Phase 1 delivery | Every new adapter requires modifying the engine, not just adding an adapter | Phase 1 only -- must be extracted before Phase 3 begins |
| `isinstance()` checks instead of Protocol dispatch | ~5-15% faster per-call in CPython | Violates open-closed principle; each new adapter type requires modifying dispatch code | Acceptable permanently for the 3-4 known adapter types; switch to Protocol if >5 adapters |
| Single-process sandbox (Landlock applied to CloneGuard's own process) | Simple, no IPC overhead | Cannot constrain the agent's process, only CloneGuard's own subprocess calls | Never -- this is a fundamental design error. The sandbox must constrain the tool execution, not the defense tool |
| Flat YAML policy without inheritance | Easy to understand, no precedence surprises | Enterprise customers with 50+ agent deployments need policy inheritance/overrides | MVP only -- Phase 5 must add policy composition |
| Inline regex compilation on first use | No startup cost for unused patterns | First invocation of each pattern is slower; unpredictable latency in hot path | Acceptable if patterns are pre-compiled at module load (current behavior in `PatternEngine.__init__`) |
| Trust cache in JSON file | Simple persistence, human-readable | JSON file locking under concurrent agent sessions; corruption on crash | Phase 1 only -- must move to SQLite or similar for multi-session safety |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Claude Code hooks | Assuming `tool_input` is always a dict. For Bash tool, `tool_input` is `{"command": "..."}` but for Write tool it's `{"file_path": "...", "content": "..."}`. | Pattern-match on tool_name first, then extract the relevant field. Never assume a universal schema. |
| Gemini CLI hooks | Assuming exact Claude Code protocol compatibility. `gemini hooks migrate --from-claude` exists but event names and field formats may drift between versions. | Pin to a verified Gemini CLI version. Test hook compatibility in CI against both Claude Code and Gemini CLI. |
| OPA/Rego integration | Embedding OPA as a Go binary subprocess and paying IPC + process startup cost on every hook invocation. | Use OPA's WASM compilation target (`opa build -t wasm`) and evaluate in-process via a Python WASM runtime. Or use py-opa (pure Python Rego evaluator) for simple policies. |
| SARIF to GitHub Advanced Security | Emitting findings without `ruleId` or with non-standard severity levels. GitHub silently drops malformed SARIF results. | Validate output against the OASIS SARIF schema before shipping. Use `sarif-tools` to round-trip test. Severity must be one of: error, warning, note, none. |
| MCP middleware | Intercepting MCP requests but not responses. Tool poisoning attacks often manifest in the response (the tool returns poisoned content), not the request. | Intercept both request and response. Scan the response body with the same detection pipeline used for PostToolUse hook content. |
| Landlock adapter | Applying restrictions before the agent forks. Landlock restrictions are inherited by child processes and cannot be removed. | Apply restrictions only to the subprocess executing the tool call, not to the CloneGuard process itself. Use subprocess sandboxing, not self-sandboxing. |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| ONNX model loaded per-call instead of per-session | Latency spikes to 200ms+ on first Tier 1.5 classification | Lazy-load once (current behavior in `_get_mini_classifier()`); verify this persists through refactoring | Any refactoring that creates a new `DetectionEngine` instance per hook invocation |
| Sliding window on every PostToolUse call | p95 latency of 256ms on long tool outputs | Apply sliding window only when content exceeds 256 tokens (current behavior); ensure threshold check is preserved in extracted module | Tools that return large outputs (e.g., `cat` on a large file, `git diff` output) |
| SEQ rule evaluation scans full event history | O(n) per rule * O(n) events = O(n^2) per session | Ring buffer with lookback window of 10 events (current `_LOOKBACK_WINDOW = 10`); bounded by design | If lookback window is increased to accommodate longer attack sequences (>50 events) |
| Policy engine evaluates all rules on every call | Latency grows linearly with policy size | Index rules by tool_name and verdict for O(1) lookup; short-circuit on first matching rule | Enterprise deployments with 100+ custom policy rules |
| NDJSON + SARIF + OTel serialization on every event | Triple serialization cost on every hook invocation | Emit to async queue; serialize in background thread; never block the hook response path | High-frequency tool calls (autocomplete, file watchers) that trigger 10+ events/second |
| Trust cache JSON file I/O on every cache check | Disk I/O on hot path defeats the purpose of caching | Load cache into memory at session start; write-back on session end or periodic flush (verify current behavior) | Concurrent agent sessions reading/writing the same JSON file |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Sandbox adapter configured from repo-resident policy file | Attacker weakens sandbox constraints via poisoned policy | Enforcement policy lives only in `~/.cloneguard/`; repo-resident policy can only tune detection sensitivity (see Pitfall 10) |
| MELON re-execution uses the same credentials/tokens as original execution | If the original execution is an exfiltration attempt, MELON's masked re-execution may also exfiltrate (with different content) | MELON re-execution must use a constrained execution context with no network access. The masked run is a simulation, not a live execution. |
| OPA/Rego policy loaded from network (bundle polling) | Network-sourced policy can be MITM'd to inject permissive rules | Policy bundles must be cryptographically signed. Verify signature before loading. Default to local-only policy with no network fetching. |
| MCP middleware trusts tool descriptions from the MCP server | Tool descriptions can be poisoned (RADE attack vector); if CloneGuard's pattern library uses tool descriptions as detection context, a poisoned description could cause the pattern to not match | Scan tool descriptions themselves as potential injection vectors. Never use tool descriptions as allowlist criteria. |
| Sequence allowlist entries created from repo-resident configuration | Attacker adds SEQ rule exemptions to bypass behavioral detection | Sequence allowlist entries can only be created from `~/.cloneguard/` or via interactive CLI (same protection as file allowlist). Repo-resident config cannot suppress SEQ rules. |
| Audit events include raw tool_input content | Sensitive data (API keys, passwords) in tool_input leaks to SIEM/OTel/SARIF | Hash tool_input for audit events (`tool_input_hash` in the event schema). Full content only in local debug logs with explicit opt-in. |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| SUSPICIOUS verdict blocks without explanation | User does not know why their tool call was constrained, cannot diagnose or fix | Always emit a human-readable reason: "CloneGuard: restricted network access for this tool call because [pattern RH-009 matched + classifier score 0.54]. Run `cloneguard explain <event-id>` for details." |
| Policy configuration requires OPA/Rego knowledge | 95% of users cannot write Rego | YAML is the default and only policy format for individual users. OPA/Rego and Cedar are enterprise-only features with documentation that includes worked examples, not just the language spec. |
| Sandbox constraints applied silently | User's workflow breaks with no indication that CloneGuard is the cause | Every constraint application must produce a visible log entry on stderr (not stdout, which is the hook protocol channel). The log entry must include the constraint type, the triggering verdict, and the `cloneguard explain` command. |
| Multiple agent types require per-type configuration | User with Claude Code + Cursor must configure CloneGuard twice | Single configuration file with agent-type-specific overrides. Defaults work for all agents. Per-agent-type sections are optional. |
| Upgrade from v0.5.0 to v1.0.0 changes behavior | Users who upgrade see new SUSPICIOUS verdicts for content that was previously CLEAN | Provide a `cloneguard migrate` command that explains what changed. First run after upgrade operates in report-only mode for 24 hours, showing what would have changed without affecting behavior. |

## "Looks Done But Isn't" Checklist

- [ ] **Detection engine extraction:** Module compiles and tests pass, but p95 latency regression not measured -- verify with `bench/benchmark.py` extended to cover the new code path.
- [ ] **SARIF emitter:** JSON output looks correct, but GitHub Advanced Security silently drops it because `ruleId` is missing or severity is "CRITICAL" instead of "error" -- validate against OASIS SARIF 2.1.0 schema and test upload to a real GitHub repo.
- [ ] **Landlock adapter:** Filesystem restrictions work in tests, but fail in production because the test runs as root (CAP_SYS_ADMIN) and production runs as unprivileged user requiring "No New Privileges" -- test in unprivileged container.
- [ ] **Three-verdict model:** SAFE/SUSPICIOUS/MALICIOUS verdicts are emitted, but the `ScanReport.exit_code` property still maps to the old binary (0/2) -- verify the exit code path end-to-end through every adapter.
- [ ] **Policy engine YAML config:** Policies load and evaluate, but error messages for malformed policies are internal Python exceptions, not user-friendly errors -- test with deliberately malformed YAML and verify error messages.
- [ ] **OTel span emission:** Spans are emitted, but span names include dynamic content (file paths, tool inputs) creating cardinality explosion -- verify span names follow OTel semantic conventions with no dynamic segments.
- [ ] **Package hallucination detection:** npm/pip cross-reference works online, but fails silently when the registry is unreachable -- verify graceful degradation with network disabled, and ensure the detection falls back to advisory (not block).
- [ ] **MCP middleware adapter:** Intercepts requests, but does not intercept responses -- verify response-side scanning is implemented and tested.
- [ ] **Fusion layer calibration:** Weights are set based on trajectory data, but the calibration did not include the authorization paradox (Campbell et al.) test -- run the auth-marker FPR test on the fused pipeline, not just Tier 1.5 standalone.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| FPR explosion from fusion | MEDIUM | Raise SUSPICIOUS floor to 0.7; revert to per-signal thresholds; collect new calibration data from production |
| Enforcement as DoS | LOW | Flip all users to NoopAdapter via config push; ship patch with dry-run default |
| Detection engine latency regression | MEDIUM | Revert extraction; keep monolith for v1.0; re-attempt extraction with profiling data |
| Exit code backward incompatibility | HIGH | Emergency patch to restore exit 0 for SUSPICIOUS; apologize to users whose CI broke |
| Seatbelt deprecation removal | HIGH | Remove SeatbeltAdapter; recommend WASM adapter; no macOS enforcement until replacement ships |
| Policy engine becomes detection engine | HIGH | Audit and remove all content-inspection policy rules; add schema validation that rejects content-accessing fields; break enterprise customer workflows |
| MELON cost explosion | LOW | Widen ambiguity zone or disable MELON; no user-facing impact since MELON is additive |
| Input adapter detection gap | HIGH | Emergency per-adapter regression test suite; manual audit of every adapter's normalization for information loss |
| Triple emission maintenance burden | LOW | Defer OTel to next release; focus on NDJSON + SARIF only |
| Layer 0 trust violation | CRITICAL | Emergency patch to remove repo-resident policy loading from enforcement path; security advisory to users |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| FPR explosion from fusion | Phase 4 (Detection Excellence), but conservative thresholds set in Phase 2 | Combined FPR <5% on held-out benign corpus; per-content-type FPR tracked in CI |
| Enforcement as DoS | Phase 2 (Adaptive Enforcement) | 2-week dry-run period with structured logging before enforcement enabled; zero user-reported workflow breakage in dry-run period |
| Detection engine latency regression | Phase 1 (Foundation) | p95 latency <25ms in CI benchmark; benchmark runs on every PR |
| Exit code backward compatibility | Phase 2 (Adaptive Enforcement) | Compatibility matrix tested against Claude Code, Gemini CLI, Cursor, Windsurf hook protocols |
| Seatbelt deprecation | Phase 2 + Phase 6 | Adapter interface allows drop-in replacement; SeatbeltAdapter wrapped in runtime availability check |
| Policy engine scope creep | Phase 2 + Phase 5 | Policy IR schema validated to exclude content-inspection fields; CI lint check on policy rules |
| MELON cost explosion | Phase 4 (Detection Excellence) | Circuit breaker implemented; triggering rate <15% in integration tests |
| Input adapter abstraction | Phase 3 (Framework Integration) | Same-attack-every-adapter test suite passes; no adapter-specific detection gaps |
| Triple emission burden | Phase 1 (NDJSON + SARIF) + Phase 3 (OTel) | Internal event schema defined in Phase 1; all emitters are projections of single schema |
| Layer 0 trust violation | Phase 2 (Adaptive Enforcement) | CI check: no repo-path reads in sandbox/policy initialization code; enforcement config only from `~/.cloneguard/` |

## Sources

- Campbell et al., "Security Authorization Paradox in Safety-Aligned LLMs" (ICLR 2026 Workshop, arXiv:2603.01246) -- structural FPR limits from embedding-space proximity
- Nasr, Carlini, Tramer, "The Attacker Moves Second" (arXiv:2510.09023) -- adaptive attacks achieve 96-100% bypass against filtering-based detectors
- Zhu et al., "MELON: Provable Defense Against Indirect Prompt Injection" (ICML 2025, arXiv:2502.05174) -- 2x API cost, response-based attack failure mode (72.73% of missed attacks)
- CloneGuard v0.5.0 empirical data: combined pipeline FPR 22.2%, Tier 1.5 FPR 9.2%, SEQ-004 FPR 15.80%, authorization paradox +12.7pp FPR increase
- CloneGuard trajectory mining: 208,127 trajectories, 8.3M actions -- SEQ-001 FPR 0.0024%, SEQ-005 FPR 0.0005%
- Landlock kernel documentation (docs.kernel.org/userspace-api/landlock.html) -- irreversible restrictions, CAP_SYS_ADMIN requirement, file descriptor timing semantics
- macOS sandbox-exec deprecation: confirmed deprecated since macOS 10.15, no replacement API; still functional as of macOS 15.4 (Apple Developer documentation, Hacker News discussion threads, openai/codex#215)
- OPA performance documentation (openpolicyagent.org/docs/policy-performance) -- p99 target 10-20ms with prepared queries; memory 200x bundle size; sequential HTTP calls in Rego
- OPA maintainers hired by Apple (August 2025) -- Styra enterprise products sunsetted; CNCF maintains OPA; long-term stewardship uncertain
- Microsoft Agent Governance Toolkit (April 2026, github.com/microsoft/agent-governance-toolkit) -- same-process trust boundary, application-level not kernel-level isolation, ToolCallInterceptor interface
- SARIF 2.1.0 OASIS specification -- severity restricted to error/warning/note/none; tool compliance variations documented by sarif-tools project
- OTel cardinality explosion (github.com/vercel/otel/issues/120, opentelemetry.io semantic conventions) -- dynamic span names create metrics spikes
- MCP security vulnerabilities: tool description poisoning, RADE attacks, CVE-2025-6514 (mcp-remote command injection), Supabase Cursor incident (mid-2025), Invariant Labs WhatsApp exfiltration demo

---
*Pitfalls research for: CloneGuard v2 Universal Agentic Defense Layer*
*Researched: 2026-04-05*
