# Phase 2: Adaptive Enforcement - Context

**Gathered:** 2026-04-05 (auto mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

Operators can configure three-verdict outcomes (SAFE / SUSPICIOUS / MALICIOUS) with YAML policy and optionally constrain tool calls via OS-level sandbox adapters (Noop / Landlock / Seatbelt), with dry-run as the safe default. Package hallucination detection cross-references npm/PyPI registries at install time. Enforcement config lives exclusively in operator-controlled paths.

</domain>

<decisions>
## Implementation Decisions

### Verdict Model Transition
- **D-01:** Extend existing `Verdict` enum in `detection/patterns.py` from `CLEAN/SUSPICIOUS/DETECTED` to `SAFE/SUSPICIOUS/MALICIOUS`. Map current binary logic: `CLEAN→SAFE`, `SUSPICIOUS→SUSPICIOUS`, `DETECTED→MALICIOUS`. The `DetectionResult.verdict` field (currently a string) transitions to use the new enum values.
- **D-02:** Confidence thresholds are operator-configurable per ScanMode in the YAML policy file. Default thresholds: `suspicious_floor: 0.3`, `malicious_floor: 0.7` (matching v2 design doc). Thresholds can be overridden per tool name and per agent type.
- **D-03:** The three-verdict model feeds into the policy engine, which maps verdict → enforcement action: SAFE → allow (no constraints), SUSPICIOUS → allow-but-constrain (sandbox tightened), MALICIOUS → block (no execution).

### Sandbox Adapter Interface
- **D-04:** `SandboxAdapter` Protocol (PEP 544) with two core methods for Phase 2: `restrict_filesystem(writable: list[str], readable: list[str]) -> None` and `restrict_network(allow: list[str]) -> None`. These are the minimum required for meaningful enforcement.
- **D-05:** Defer `snapshot()`, `rollback()`, `restrict_syscalls()`, and `get_audit_log()` to later phases. The Protocol includes them as optional (default no-op implementations) so adapters can grow without breaking the interface.
- **D-06:** Auto-selection at startup: probe available capabilities, select strongest adapter. Operator can override via `sandbox.preferred` in YAML config. Fallback is always NoopAdapter. CloneGuard never fails to start due to missing sandbox support.

### Concrete Adapters
- **D-07:** `NoopAdapter` — all methods are no-ops. Preserves current v0.5.0 detection-only behavior exactly. This is the default adapter and the fallback when no OS-level sandbox is available or configured.
- **D-08:** `LandlockAdapter` — uses Landlock LSM (Linux 5.13+) for filesystem restriction. Applies Landlock rules to the tool call subprocess only, not to the CloneGuard process itself. Network restriction via Landlock v4 (kernel 6.7+) if available, otherwise logged as unsupported.
- **D-09:** `SeatbeltAdapter` — uses `sandbox-exec` with generated Seatbelt profiles for macOS. Applies filesystem and network restrictions to the tool call subprocess. Note: `sandbox-exec` is technically deprecated by Apple but remains functional and is the only unprivileged sandbox mechanism on macOS.

### Policy Engine
- **D-10:** YAML-only policy engine for Phase 2. Config file at `~/.cloneguard/policy.yaml`. No IR compilation layer — direct YAML → `PolicyDecision` dataclass mapping. OPA/Cedar backends deferred to Phase 5.
- **D-11:** Policy schema follows v2 design doc format: `verdicts.thresholds` (global), `enforcement.suspicious` (per-tool-name constraints), `enforcement.malicious` (action: block), `sandbox.preferred` (adapter selection). Variable expansion for `${PROJECT_DIR}` and `${VENV_DIR}`.
- **D-12:** `PolicyDecision` is a frozen dataclass: `action` (allow/constrain/block), `constraints` (filesystem/network restrictions), `dry_run` (bool), `matched_rule` (which policy section triggered). Feeds into the enforcement loop.

### Dry-Run Default
- **D-13:** `dry_run: true` is the default in the YAML policy schema. When dry-run is active, the enforcement layer logs what constraints would be applied (adapter name, filesystem restrictions, network restrictions) but does not invoke the sandbox adapter. This is the safe default for all new installations.
- **D-14:** Dry-run output goes to NDJSON audit events (Phase 1 infrastructure) with `enforcement_action: "DRY_RUN"` and a `would_apply` field containing the constraints that would have been enforced.

### Package Hallucination Detection
- **D-15:** Implemented as a PreToolUse detection signal in the detection engine. When `tool_name` is "Bash" and content matches `npm install`, `pip install`, or similar patterns, extract package names and cross-reference against registry APIs (registry.npmjs.org, pypi.org).
- **D-16:** Returns a `SignalResult` with `signal_type: "package_hallucination"`. A package not found in the registry produces `verdict: "detected"` with high confidence. The signal feeds into the standard three-signal fusion (alongside pattern + semantic + sequence).
- **D-17:** Registry API calls are cached per session (package name → exists/missing). Network failures degrade gracefully — if the registry is unreachable, log a warning and skip the check (never block on network failure).

### Config Path Security
- **D-18:** Enforcement config lives exclusively at `~/.cloneguard/policy.yaml`. Never read from repo-resident files. This prevents agents from modifying their own constraints.
- **D-19:** Config path follows the existing pattern: `~/.cloneguard/allowlist.json` (Phase 1) → `~/.cloneguard/policy.yaml` (Phase 2). All operator-controlled state in `~/.cloneguard/`.

### Claude's Discretion
- Internal module organization for enforcement layer (e.g., `cloneguard/enforcement/` package structure)
- Exact Landlock ruleset composition for filesystem restrictions
- Seatbelt profile generation strategy (template vs. programmatic)
- Registry API client implementation details (urllib3 vs. httpx vs. stdlib)
- Error handling for malformed policy YAML
- Test strategy for OS-specific sandbox adapters (mock vs. integration)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v2 Architecture Design
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` — Full v2 architecture with SandboxAdapter Protocol (section 5), Policy Engine YAML format (section 6.2), three-verdict model (section 2)
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` §5 — SandboxAdapter Protocol definition, concrete adapter table, auto-selection strategy
- `docs/plans/2026-04-05-cloneguard-v2-architecture-design.md` §6.2 — YAML policy schema (verdicts, enforcement, sandbox sections)

### Detection Engine (Phase 1 output — build on this)
- `src/cloneguard/detection/types.py` — ToolCallEvent, SignalResult, DetectionResult, DetectionEngineProtocol (Phase 2 extends these)
- `src/cloneguard/detection/engine.py` — DetectionEngine with scan methods (Phase 2 adds enforcement after scan)
- `src/cloneguard/detection/patterns.py` — Current Verdict enum (CLEAN/SUSPICIOUS/DETECTED → evolve to SAFE/SUSPICIOUS/MALICIOUS)

### Existing Config Patterns
- `src/cloneguard/allowlist.py` — Allowlist storage pattern at `~/.cloneguard/` (follow this pattern for policy.yaml)
- `src/cloneguard/sequence_allowlist.py` — Sequence allowlist pattern (operator-controlled paths)

### Research (from Phase 1)
- `.planning/research/ARCHITECTURE.md` — Component boundaries, data flow, build order
- `.planning/research/PITFALLS.md` — FPR explosion risk, backward compat contract, latency benchmark gate

### Standards (external)
- Landlock LSM documentation (kernel.org) — Landlock v1-v4 API, `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`
- macOS `sandbox-exec` man page — Seatbelt profile format, SBPL syntax
- npm registry API (registry.npmjs.org) — Package existence endpoint
- PyPI JSON API (pypi.org/pypi/{package}/json) — Package metadata endpoint

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DetectionEngine` (detection/engine.py): Phase 2 enforcement layer sits AFTER scan() returns DetectionResult. The pipeline becomes: scan() → PolicyEngine.evaluate() → SandboxAdapter.apply() → AuditEmitter.emit().
- `Verdict` enum (detection/patterns.py): Currently `CLEAN/SUSPICIOUS/DETECTED`. Rename to `SAFE/SUSPICIOUS/MALICIOUS` with backward-compatible string values.
- `NDJSONEmitter` (audit/ndjson.py): Phase 1 audit infrastructure. Phase 2 adds `enforcement_action` and `constraints_applied` fields to audit events.
- `BUILD_COMMANDS` list (detection/engine.py): Already identifies `npm install`, `pip install`, etc. Reusable for package hallucination detection triggering.
- Allowlist storage pattern (`~/.cloneguard/allowlist.json`): Follow this pattern for policy.yaml location and loading.

### Established Patterns
- **Protocol-based interfaces** (D-04 from Phase 1): SandboxAdapter must be a `typing.Protocol`, not ABC.
- **Frozen dataclasses on hot path**: PolicyDecision, enforcement types should be frozen dataclasses.
- **Graceful degradation**: Sandbox adapters that can't load (wrong OS, missing kernel version) must return None/NoopAdapter, never crash.
- **TOCTOU-safe**: Policy evaluation must use the same content that was scanned, not re-read from disk.
- **Session-scoped caching**: Registry API results cached within session, similar to trust cache pattern.

### Integration Points
- `hooks.py` thin shims → call DetectionEngine.scan() → **NEW: pass DetectionResult to PolicyEngine** → **NEW: pass PolicyDecision to enforcement** → emit audit event
- `cli.py` → `cloneguard init` needs to generate default `~/.cloneguard/policy.yaml` with dry-run enabled
- `pyproject.toml` → may need new optional dependency group for registry API client

</code_context>

<specifics>
## Specific Ideas

- The v2 design doc pipeline is strictly linear: ToolCallEvent → DetectionResult → PolicyDecision → EnforcementOutcome → AuditEvent. Phase 2 implements the middle three stages (PolicyDecision, EnforcementOutcome additions to AuditEvent).
- STATE.md flags "Phase 2 needs Landlock apply-to-subprocess spike before full adapter implementation" — this should be a research spike in the first plan.
- macOS Seatbelt deprecation is acknowledged (STATE.md concern). SeatbeltAdapter should document the deprecation risk and be designed for easy replacement when Apple provides an alternative.
- Package hallucination detection should NOT block on network I/O. If registry is unreachable, skip check and log. The check is an additional signal, not a gate.

</specifics>

<deferred>
## Deferred Ideas

- OPA/Rego policy backend — Phase 5 (GOVN-01)
- Cedar policy backend — Phase 5 (GOVN-02)
- Policy IR compilation layer — Phase 5 (GOVN-03), needed when multiple policy formats exist
- `snapshot()` / `rollback()` adapter methods — Later phase, useful for MELON re-execution (Phase 4)
- `restrict_syscalls()` adapter method — Phase 5, for advanced sandboxing (gVisor, Firecracker)
- Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) — Phase 5 (AGNT-05)
- MCP tool description fingerprinting — Phase 4 (DETC-05)
- SPIFFE agent identity — Phase 5 (GOVN-06)

None — analysis stayed within phase scope.

</deferred>

---

*Phase: 02-adaptive-enforcement*
*Context gathered: 2026-04-05*
