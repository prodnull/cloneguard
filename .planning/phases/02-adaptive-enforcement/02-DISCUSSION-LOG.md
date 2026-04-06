# Phase 2: Adaptive Enforcement - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-05
**Phase:** 02-adaptive-enforcement
**Mode:** auto
**Areas discussed:** Verdict model transition, Sandbox adapter scope, Policy engine architecture, Package hallucination integration, Dry-run default strategy, Config path security

---

## Verdict Model Transition

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing Verdict enum to SAFE/SUSPICIOUS/MALICIOUS | Map current values, configurable thresholds in YAML policy | ✓ |
| New enum alongside old (parallel verdicts) | Keep old for backward compat, new for enforcement | |
| String-based verdicts without enum | Maximum flexibility, less type safety | |

**User's choice:** [auto] Extend existing Verdict enum (recommended default)
**Notes:** Current enum has CLEAN/SUSPICIOUS/DETECTED. Natural mapping: CLEAN→SAFE, SUSPICIOUS→SUSPICIOUS, DETECTED→MALICIOUS. Thresholds from v2 design doc: suspicious_floor 0.3, malicious_floor 0.7.

---

## Sandbox Adapter Scope

| Option | Description | Selected |
|--------|-------------|----------|
| restrict_filesystem + restrict_network only | Minimum viable enforcement for Phase 2, defer advanced methods | ✓ |
| Full Protocol (all 6 methods) | Complete interface now, no-op defaults for unimplemented | |
| filesystem-only (no network) | Simplest, but misses exfil protection | |

**User's choice:** [auto] restrict_filesystem + restrict_network only (recommended default)
**Notes:** snapshot/rollback needed for MELON (Phase 4), syscalls for advanced adapters (Phase 5). Two core methods provide meaningful enforcement. Protocol includes deferred methods as optional with default no-op implementations.

---

## Policy Engine Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| YAML → PolicyDecision direct mapping | Simple, no IR layer. OPA/Cedar deferred to Phase 5 | ✓ |
| YAML + IR compilation (future-proof) | Build IR now so OPA/Cedar plug in cleanly later | |
| Inline policy (no external config file) | Hardcoded thresholds, no user configuration | |

**User's choice:** [auto] YAML → PolicyDecision direct mapping (recommended default)
**Notes:** YAGNI — IR compilation layer only needed when multiple policy formats exist. Phase 5 will add OPA/Cedar and the compilation step then.

---

## Package Hallucination Integration

| Option | Description | Selected |
|--------|-------------|----------|
| PreToolUse detection signal in engine | Match install commands, cross-reference registry, return SignalResult | ✓ |
| Separate standalone module | Independent from detection pipeline, own CLI command | |
| Policy engine rule (not detection) | Policy decides whether to check, not detection | |

**User's choice:** [auto] PreToolUse detection signal in engine (recommended default)
**Notes:** Fits naturally into existing PreToolUse flow — BUILD_COMMANDS list already identifies install commands. Registry results cached per session. Network failures degrade gracefully (never block).

---

## Dry-Run Default Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Boolean dry_run flag in YAML policy | Default true, logs constraints without enforcing | ✓ |
| Separate DryRunAdapter wrapping real adapter | Intercepts all calls, logs, passes through | |
| CLI flag --dry-run (not config) | Per-invocation, not persistent | |

**User's choice:** [auto] Boolean dry_run flag in YAML policy (recommended default)
**Notes:** Config-based is better than CLI flag for persistent default. Logs to NDJSON with enforcement_action: "DRY_RUN" and would_apply field.

---

## Config Path Security

| Option | Description | Selected |
|--------|-------------|----------|
| ~/.cloneguard/policy.yaml exclusively | Matches allowlist pattern, never repo-resident | ✓ |
| XDG_CONFIG_HOME/cloneguard/ | Standards-compliant but different from existing allowlist path | |
| Both ~/.cloneguard/ and project-level | Flexible but agents could modify project-level config | |

**User's choice:** [auto] ~/.cloneguard/policy.yaml exclusively (recommended default)
**Notes:** Consistent with existing ~/.cloneguard/allowlist.json. Repo-resident policy would let agents modify their own constraints — security violation.

---

## Claude's Discretion

- Internal enforcement module organization
- Landlock ruleset composition details
- Seatbelt profile generation strategy
- Registry API client library choice
- Error handling for malformed policy YAML
- Test strategy for OS-specific adapters

## Deferred Ideas

- OPA/Rego and Cedar policy backends — Phase 5
- Policy IR compilation — Phase 5
- snapshot/rollback adapter methods — Phase 4 (MELON)
- restrict_syscalls — Phase 5
- Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) — Phase 5
