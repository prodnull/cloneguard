# Phase 02: Adaptive Enforcement - Research

**Researched:** 2026-04-06
**Domain:** OS-level sandbox enforcement, YAML policy engine, package hallucination detection
**Confidence:** HIGH (Landlock/Seatbelt well-documented; registry APIs verified live; codebase patterns confirmed by reading source)

## Summary

Phase 2 transforms CloneGuard from detection-only (exit 0/2) to adaptive enforcement: SAFE/SUSPICIOUS/MALICIOUS verdicts drive a YAML policy engine that maps verdicts to sandbox constraints applied via OS-level adapters (Landlock on Linux, Seatbelt on macOS, Noop everywhere else). The critical design constraint is that sandbox restrictions must apply ONLY to the tool call subprocess, never to the CloneGuard process itself. Both Landlock and Seatbelt support this via the fork+restrict+exec pattern -- apply restrictions in the child process between fork and exec, before the target command runs.

The second major component is package hallucination detection: when a build command (`npm install`, `pip install`) is detected, extract package names and check them against registry APIs (registry.npmjs.org for npm, pypi.org for PyPI). A 404 response indicates a hallucinated package. This is implemented as an additional SignalResult feeding into the existing detection pipeline, not a separate gate.

**Primary recommendation:** Implement the sandbox adapters using a lightweight Python wrapper that applies Landlock/Seatbelt restrictions via ctypes syscalls in `preexec_fn`, with a compiled helper binary as the fallback/safe option for production. Ship with dry-run default and NoopAdapter as the detection-only fallback. YAML policy validation uses Pydantic models (already a dependency) to parse `~/.cloneguard/policy.yaml`.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Extend existing `Verdict` enum from `CLEAN/SUSPICIOUS/DETECTED` to `SAFE/SUSPICIOUS/MALICIOUS`. Map: `CLEAN->SAFE`, `SUSPICIOUS->SUSPICIOUS`, `DETECTED->MALICIOUS`. DetectionResult.verdict transitions to new enum values.
- **D-02:** Confidence thresholds operator-configurable per ScanMode in YAML. Defaults: `suspicious_floor: 0.3`, `malicious_floor: 0.7`. Overridable per tool name and per agent type.
- **D-03:** Three-verdict model feeds policy engine: SAFE->allow, SUSPICIOUS->allow-but-constrain, MALICIOUS->block.
- **D-04:** `SandboxAdapter` Protocol (PEP 544) with `restrict_filesystem(writable, readable)` and `restrict_network(allow)`. Minimum required for Phase 2.
- **D-05:** Defer `snapshot()`, `rollback()`, `restrict_syscalls()`, `get_audit_log()` to later phases. Protocol includes them as optional with default no-op.
- **D-06:** Auto-selection at startup: probe capabilities, select strongest. Operator override via `sandbox.preferred`. Fallback always NoopAdapter.
- **D-07:** `NoopAdapter` -- all methods no-ops. Preserves v0.5.0 behavior exactly. Default adapter and fallback.
- **D-08:** `LandlockAdapter` -- Linux 5.13+ filesystem restriction. Network via Landlock v4 (kernel 6.7+) if available. Applies to subprocess only.
- **D-09:** `SeatbeltAdapter` -- `sandbox-exec` with generated SBPL profiles. Applies to subprocess. Note: deprecated by Apple but functional.
- **D-10:** YAML-only policy engine. Config at `~/.cloneguard/policy.yaml`. Direct YAML->PolicyDecision mapping. No IR compilation layer.
- **D-11:** Policy schema: `verdicts.thresholds` (global), `enforcement.suspicious` (per-tool constraints), `enforcement.malicious` (block), `sandbox.preferred`. Variable expansion for `${PROJECT_DIR}` and `${VENV_DIR}`.
- **D-12:** `PolicyDecision` frozen dataclass: `action` (allow/constrain/block), `constraints` (fs/network), `dry_run` (bool), `matched_rule`.
- **D-13:** `dry_run: true` default in YAML schema. Logs what constraints would apply without enforcing. Safe default for all new installations.
- **D-14:** Dry-run output to NDJSON audit events with `enforcement_action: "DRY_RUN"` and `would_apply` field.
- **D-15:** Package hallucination as PreToolUse detection signal. Extract package names from `npm install`/`pip install` commands, cross-reference against registry APIs.
- **D-16:** Returns `SignalResult` with `signal_type: "package_hallucination"`. Not-found -> `verdict: "detected"` with high confidence.
- **D-17:** Registry API calls cached per session. Network failures degrade gracefully (skip check, log warning, never block on network failure).
- **D-18:** Enforcement config exclusively at `~/.cloneguard/policy.yaml`. Never from repo-resident files.
- **D-19:** Config path follows existing pattern: `~/.cloneguard/allowlist.json` -> `~/.cloneguard/policy.yaml`.

### Claude's Discretion
- Internal module organization for enforcement layer (e.g., `cloneguard/enforcement/` package structure)
- Exact Landlock ruleset composition for filesystem restrictions
- Seatbelt profile generation strategy (template vs. programmatic)
- Registry API client implementation details (urllib3 vs. httpx vs. stdlib)
- Error handling for malformed policy YAML
- Test strategy for OS-specific sandbox adapters (mock vs. integration)

### Deferred Ideas (OUT OF SCOPE)
- OPA/Rego policy backend -- Phase 5 (GOVN-01)
- Cedar policy backend -- Phase 5 (GOVN-02)
- Policy IR compilation layer -- Phase 5 (GOVN-03)
- `snapshot()` / `rollback()` adapter methods -- Later phase
- `restrict_syscalls()` adapter method -- Phase 5
- Additional sandbox adapters (gVisor, Firecracker, WASM, Docker) -- Phase 5 (AGNT-05)
- MCP tool description fingerprinting -- Phase 4 (DETC-05)
- SPIFFE agent identity -- Phase 5 (GOVN-06)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ENFC-01 | Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) with configurable thresholds | Verdict enum extension from existing patterns.py; Pydantic-validated YAML for thresholds |
| ENFC-02 | Sandbox adapter interface (Protocol) with auto-selection | PEP 544 Protocol pattern already used in codebase (DetectionEngineProtocol); platform probe via sys.platform + kernel version check |
| ENFC-03 | NoopAdapter preserving v0.5.0 behavior exactly | All methods no-op; exit code mapping SAFE->0, SUSPICIOUS->0, MALICIOUS->2 identical to current |
| ENFC-04 | LandlockAdapter for Linux 5.13+ | Two approaches: ctypes preexec_fn (lightweight) or compiled helper binary (safer). Both use fork+restrict+exec pattern. Landlock ABI v1-v3 for filesystem, v4 (kernel 6.7+) for TCP |
| ENFC-05 | SeatbeltAdapter for macOS | ctypes call to sandbox_init_with_parameters from libSystem.dylib in preexec_fn. SBPL profile generated programmatically with deny-default baseline |
| ENFC-06 | Policy engine with YAML config | Pydantic models parse ~/.cloneguard/policy.yaml; variable expansion for ${PROJECT_DIR}/${VENV_DIR}; per-tool and per-agent overrides |
| ENFC-07 | Dry-run as default | PolicyDecision.dry_run=True by default; logs to NDJSON with enforcement_action="DRY_RUN" and would_apply constraints |
| ENFC-08 | Package hallucination detection | stdlib urllib.request to registry.npmjs.org/{pkg} and pypi.org/pypi/{pkg}/json; 200=exists, 404=hallucinated; session-cached |
| ENFC-09 | Config in operator-controlled paths only | ~/.cloneguard/policy.yaml following existing allowlist.py pattern; never read from repo |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Tech stack**: Python 3.11+, ONNX Runtime for inference, no external service dependencies for core detection
- **Performance**: <20ms per hook invocation for Tier 0+1.5, <370ms full repo scan
- **Ruff + mypy strict**: All code must pass `ruff check` and `mypy --strict`
- **No custom crypto**: Battle-tested, audited, well-maintained libraries only
- **Testing**: Minimum 80% coverage for business logic; Arrange-Act-Assert; mock external dependencies
- **Frozen dataclasses on hot path**: No Pydantic on detection hot path (Pitfall 6 from Phase 1 research)
- **Never log secrets**: Only content hashes, file paths
- **Conventional Commits**: `type(scope): description` format
- **Line length 100**: Ruff configured in pyproject.toml
- **Hook exit codes**: 0 = allow, 2 = block. Never introduce exit 1 for verdicts.
- **TOCTOU-safe**: All decisions bind to content in stdin JSON, never re-read from disk

## Standard Stack

### Core (already dependencies)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| pydantic | >=2.0 (installed: 2.12.5) | YAML policy schema validation, audit event types | Already a project dependency; frozen models for audit layer [VERIFIED: pip show] |
| pyyaml | >=6.0 (installed: 6.0.3) | YAML parsing for policy.yaml | Already a project dependency [VERIFIED: pip show] |

### New for Phase 2
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| (none -- stdlib only) | -- | Landlock via ctypes syscalls | Linux adapter: direct syscall via libc.so |
| (none -- stdlib only) | -- | Seatbelt via ctypes libSystem.dylib | macOS adapter: sandbox_init_with_parameters |
| (none -- stdlib only) | -- | Registry API via urllib.request | Package hallucination detection: HTTP HEAD/GET to npm/PyPI |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| stdlib ctypes for Landlock | `py-landlock` (PyPI) or `landlock` (PyPI) | Adds dependency; `landlock` package is v1.0.0.dev5, doesn't support ABI v4 (network). Direct ctypes is ~50 lines, no dependency, full ABI control [VERIFIED: pypi.org/project/landlock] |
| stdlib ctypes for Seatbelt | External Rust/C helper binary | More robust (no preexec_fn deadlock risk) but adds build complexity. ctypes to libSystem.dylib is proven pattern (see ai-jail, agent-harbor projects) [CITED: zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos] |
| stdlib urllib.request for registry | httpx or aiohttp | Adds dependency for simple GET requests. stdlib is sufficient for existence checks (200 vs 404). No auth needed. [VERIFIED: live curl tests against registry.npmjs.org and pypi.org] |
| pydantic for policy validation | cerberus or jsonschema | Pydantic already a dependency; avoids adding another validation library. Pydantic YAML pattern is well-established [CITED: docs.pydantic.dev] |

**Installation:**
```bash
# No new dependencies needed for Phase 2 core
# All features use stdlib (ctypes, urllib.request) + existing deps (pydantic, pyyaml)
```

## Architecture Patterns

### Recommended Module Structure
```
src/cloneguard/
  enforcement/
    __init__.py              # Public API: get_sandbox_adapter(), PolicyEngine
    types.py                 # PolicyDecision, EnforcementOutcome, Constraints (frozen dataclasses)
    policy.py                # YAMLPolicyEngine: load policy.yaml -> evaluate -> PolicyDecision
    adapter.py               # SandboxAdapter Protocol + NoopAdapter
    landlock.py              # LandlockAdapter (Linux 5.13+)
    seatbelt.py              # SeatbeltAdapter (macOS)
    registry.py              # PackageRegistryClient (npm/PyPI existence checks)
  detection/
    patterns.py              # Verdict enum: SAFE/SUSPICIOUS/MALICIOUS (extended)
    engine.py                # DetectionEngine: adds package_hallucination signal
    types.py                 # SignalResult: add signal_type="package_hallucination"
```

### Pattern 1: Fork+Restrict+Exec Sandbox Pattern
**What:** Apply OS-level sandbox restrictions in the child process between fork() and exec(), so only the subprocess is restricted, not CloneGuard itself.
**When to use:** Every SUSPICIOUS verdict with enforcement enabled (not dry-run).
**How it works:**

```
CloneGuard process (unrestricted)
    |
    +--- fork() ---> child process
                        |
                        +--- preexec_fn():
                        |      prctl(PR_SET_NO_NEW_PRIVS)  # Required for Landlock
                        |      landlock_create_ruleset()
                        |      landlock_add_rule()          # per-path rules
                        |      landlock_restrict_self()
                        |
                        +--- exec(tool_command)  # Runs under Landlock restrictions
```

[CITED: docs.kernel.org/userspace-api/landlock.html, pierce.dev/notes/a-deep-dive-on-agent-sandboxes]

**Critical safety note:** The `preexec_fn` is called between fork and exec. Only async-signal-safe functions are safe here. Landlock syscalls are raw kernel syscalls (no malloc), but Python's ctypes involves Python object allocation. Two mitigation strategies:

1. **Direct ctypes approach (simpler, slightly risky):** Call `libc.syscall()` directly with integer constants. Minimize Python object creation. Acceptable for CloneGuard because the hook process is single-threaded (no Python threading).
2. **Compiled helper binary (safer, more complex):** Ship a small C/Rust binary (`cloneguard-sandbox`) that accepts restrictions as CLI args, applies them, then exec's the target. Avoids preexec_fn entirely. This is the Codex pattern. [CITED: pierce.dev/notes/a-deep-dive-on-agent-sandboxes]

**Recommendation:** Start with direct ctypes in preexec_fn (simpler, CloneGuard is single-threaded). Add compiled helper binary as a follow-up if deadlock issues surface. [ASSUMED]

### Pattern 2: macOS Seatbelt via sandbox_init_with_parameters
**What:** Generate an SBPL profile string at runtime and apply it to the child process via ctypes call to `sandbox_init_with_parameters` from `libSystem.dylib`.
**When to use:** macOS SUSPICIOUS verdicts with enforcement enabled.
**Example:**

```python
# Source: zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos/
import ctypes

libsystem = ctypes.CDLL("libSystem.dylib")

def _seatbelt_preexec(profile: str, params: dict[str, str]) -> None:
    """Apply Seatbelt sandbox in child process before exec."""
    param_count = len(params)
    if param_count > 0:
        arr = (ctypes.c_char_p * (param_count * 2 + 1))()
        for i, (k, v) in enumerate(params.items()):
            arr[i * 2] = k.encode("utf-8")
            arr[i * 2 + 1] = v.encode("utf-8")
        arr[param_count * 2] = None
    else:
        arr = None

    errbuf = ctypes.POINTER(ctypes.c_char_p)()
    ret = libsystem.sandbox_init_with_parameters(
        ctypes.create_string_buffer(profile.encode("utf-8")),
        0,
        ctypes.cast(arr, ctypes.POINTER(ctypes.c_char_p)) if arr else None,
        ctypes.byref(errbuf),
    )
    if ret != 0:
        msg = "Unknown sandbox error"
        if errbuf:
            raw = ctypes.cast(errbuf, ctypes.c_char_p).value
            if raw:
                msg = raw.decode("utf-8")
            libsystem.free(errbuf)
        raise RuntimeError(f"Seatbelt error: {msg}")
```

[CITED: zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos]

### Pattern 3: SBPL Profile Generation (deny-default + selective allow)
**What:** Generate SBPL profiles programmatically as strings with parameterized paths.
**When to use:** SeatbeltAdapter constraint application.

```scheme
;; Generated SBPL profile template
(version 1)
(deny default)
(import "bsd.sb")

;; Parameters from PolicyDecision.constraints
(define projectDir (param "PROJECT_DIR"))

;; Process execution (always allowed)
(allow process-exec file-read*
  (subpath "/bin")
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/usr/lib"))

;; Python runtime (required for tool execution)
(allow file-read* (subpath "/Library/Frameworks/Python.framework"))
(allow file-read* (subpath "/usr/local/lib"))

;; Project directory (read+write per constraints)
(allow file-read* file-write* (subpath projectDir))

;; Temp directories (always writable - see Pitfall 2)
(allow file-read* file-write*
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath (param "TMPDIR")))

;; Network restrictions (if specified)
;; Note: SBPL supports domain-level filtering via:
;;   (allow network-outbound (remote ip "..."))
;; But domain resolution requires DNS, so we allow DNS always
;; and restrict at the IP/port level
```

[CITED: deepwiki.com/akitaonrails/ai-jail/4.5-macos:-seatbelt-sandboxing]

### Pattern 4: YAML Policy Parsing with Pydantic
**What:** Parse `~/.cloneguard/policy.yaml` into typed Pydantic models, then evaluate against DetectionResult to produce PolicyDecision.
**When to use:** Every detection event.

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pydantic import BaseModel, ConfigDict

# Policy schema (Pydantic for validation, loaded once at startup)
class ThresholdConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    suspicious_floor: float = 0.3
    malicious_floor: float = 0.7

class ConstraintConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    network: list[str] = []                    # Allowed domains/CIDRs
    filesystem_writable: list[str] = []         # Writable paths (${PROJECT_DIR} expanded)
    filesystem_readable: list[str] = []         # Additional readable paths
    snapshot: bool = False                      # Deferred to later phase

class PolicyConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    verdicts: dict[str, ThresholdConfig] = {}
    enforcement: dict[str, dict[str, ConstraintConfig]] = {}
    sandbox: dict[str, str] = {"preferred": "auto", "fallback": "noop"}
    dry_run: bool = True                        # Default: dry-run enabled

# Decision output (frozen dataclass, on hot path)
@dataclass(frozen=True)
class PolicyDecision:
    action: str           # "allow" | "constrain" | "block"
    constraints: dict[str, list[str]] = field(default_factory=dict)
    dry_run: bool = True
    matched_rule: str = ""
```

### Pattern 5: Package Registry Existence Check
**What:** Lightweight HTTP check against npm/PyPI registries to detect hallucinated packages.
**When to use:** PreToolUse when tool_name="Bash" and command contains install commands.

```python
import urllib.request
import urllib.error

_REGISTRY_URLS = {
    "npm": "https://registry.npmjs.org/{package}",
    "pypi": "https://pypi.org/pypi/{package}/json",
}

def check_package_exists(package: str, registry: str) -> bool | None:
    """Check if package exists. Returns True/False/None (network error)."""
    url = _REGISTRY_URLS[registry].format(package=package)
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None  # Unexpected error, degrade gracefully
    except (urllib.error.URLError, TimeoutError):
        return None  # Network failure, skip check
```

[VERIFIED: Live tests confirmed 200 for existing packages, 404 for non-existing, on both registry.npmjs.org and pypi.org]

### Anti-Patterns to Avoid
- **Restricting CloneGuard's own process:** Landlock/Seatbelt MUST only apply to the subprocess. If CloneGuard restricts itself, it cannot read policy files, emit audit events, or scan future tool calls. [CITED: docs.kernel.org/userspace-api/landlock.html -- "Once a thread is landlocked, there is no way to remove its security policy"]
- **Accumulating Landlock restrictions across calls:** Landlock is additive-only (can add restrictions, never remove). Each tool call needs fresh restriction evaluation. This means spawning a new subprocess per constrained call, not reusing a restricted process. [CITED: docs.kernel.org/userspace-api/landlock.html]
- **Policy engine inspecting tool content:** The policy engine maps verdict+context->action. It NEVER inspects tool_input content directly. Content inspection belongs in the detection engine. (Pitfall 6 from research) [CITED: .planning/research/PITFALLS.md]
- **Blocking on registry API calls:** Package existence checks MUST be async or have a short timeout (3s). Network failures -> skip check, not block agent. [D-17]
- **Pydantic on the hot path:** PolicyDecision is a frozen dataclass, NOT a Pydantic model. Pydantic is used only for policy YAML parsing (cold path at startup). [CITED: .planning/research/PITFALLS.md, Pitfall 6]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| YAML config parsing + validation | Custom YAML parser with manual type checks | Pydantic BaseModel with `yaml.safe_load()` input | Pydantic gives type coercion, error messages, nested validation for free. Already a dependency. |
| Landlock syscall wrappers | Full Landlock library binding | ~50 lines of ctypes calling libc.syscall() with SYS_landlock_* constants | Only need create_ruleset + add_rule + restrict_self. A library adds dependency for 3 syscalls. |
| SBPL profile generation | Complex template engine | f-string with parameterized path substitution | SBPL is simple enough that string building works. The ai-jail and agent-harbor projects both do this. |
| Package name extraction from install commands | Regex-from-scratch for all package managers | Pattern matching against known install command patterns already in BUILD_COMMANDS list | The detection engine already identifies `npm install`, `pip install` etc. Extend, don't rebuild. |
| HTTP client for registry checks | httpx/aiohttp dependency | stdlib urllib.request | Simple GET/HEAD with 3s timeout. No auth, no cookies, no redirect following. Stdlib is sufficient. |

**Key insight:** Phase 2 adds zero new dependencies. Every capability is achievable with stdlib (ctypes, urllib.request) plus existing deps (pydantic, pyyaml). This keeps the packaging story clean for `uv tool install`/`pipx`.

## Common Pitfalls

### Pitfall 1: Landlock Restrictions Are Irreversible and Cumulative
**What goes wrong:** Once `landlock_restrict_self()` is called, the restrictions cannot be removed. Additional rulesets can only ADD restrictions, never relax them. If CloneGuard applies Landlock to its own process, it permanently loses access to paths it needs.
**Why it happens:** Landlock is designed as a security primitive. Irreversibility prevents privilege escalation.
**How to avoid:** ALWAYS apply Landlock in the child subprocess only (via preexec_fn or wrapper binary). The parent CloneGuard process never calls landlock_restrict_self. Each tool invocation gets a fresh subprocess with fresh restrictions based on the current PolicyDecision.
**Warning signs:** CloneGuard fails to read policy.yaml after the first constrained tool call; audit events stop being emitted after enforcement.

### Pitfall 2: Sandbox Breaks Legitimate Tool Behavior
**What goes wrong:** A SUSPICIOUS npm install with filesystem restricted to ${PROJECT_DIR} fails because npm writes to `~/.npm/`, `~/.cache/`, `/tmp/`. A git push fails because network is restricted to registry.npmjs.org but it needs github.com.
**Why it happens:** Constraint policies are written for the threat model, not the benign baseline. Developer tools scatter files across the filesystem and make network calls to many services.
**How to avoid:** Define minimum always-allowed paths (`/tmp`, `~/.cache`, `${PROJECT_DIR}`) that no policy can restrict. Include common tool-specific paths in per-tool constraint templates (e.g., `npm_install` allows `~/.npm` and `registry.npmjs.org`). Ship dry-run first to collect data on what paths/domains tools actually need.
**Warning signs:** Users report cryptic "Permission denied" errors with no CloneGuard attribution. NoopAdapter usage stays at 100% because nobody trusts enforcement.

### Pitfall 3: preexec_fn Deadlock in Threaded Contexts
**What goes wrong:** `preexec_fn` runs between fork and exec. If any thread holds a lock (Python GIL, malloc mutex, logging lock), the child process deadlocks because it inherits the locked state but not the thread that holds the lock.
**Why it happens:** Python's subprocess uses fork() on POSIX. After fork, only the calling thread exists in the child, but all mutexes remain locked.
**How to avoid:** CloneGuard hook handlers are single-threaded (called by agent per-invocation). The risk is low but real if CloneGuard adds threading in the future. Keep preexec_fn functions minimal: only ctypes syscalls (no Python logging, no string formatting, no dict operations). If deadlocks surface, migrate to compiled helper binary pattern. [CITED: discuss.python.org/t/why-preexec-fn-in-subprocess-popen-may-lead-to-deadlock/16908]
**Warning signs:** Intermittent hangs in sandboxed subprocess execution. Timeouts on constrained tool calls that work fine with NoopAdapter.

### Pitfall 4: Seatbelt Deprecation by Apple
**What goes wrong:** `sandbox-exec` and `sandbox_init_with_parameters` are deprecated by Apple since macOS 10.15. A future macOS release could remove them.
**Why it happens:** Apple provides no unprivileged sandbox alternative for CLI tools. App Sandbox requires .app bundles with entitlements.
**How to avoid:** Design SeatbeltAdapter as easily replaceable behind the SandboxAdapter Protocol. Detection (NoopAdapter) provides value without enforcement. Monitor WWDC announcements. Both Claude Code and Chromium still use sandbox-exec, so Apple has strong backward-compat pressure. [CITED: news.ycombinator.com/item?id=44283454, chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md]
**Warning signs:** Apple removes sandbox-exec from macOS beta releases. Claude Code switches to a different sandbox mechanism.

### Pitfall 5: Exit Code Contract Violation
**What goes wrong:** SUSPICIOUS verdict with enforcement must still return exit 0 to the hook protocol. If enforcement produces a non-zero exit, agents interpret it as a CloneGuard error or block.
**Why it happens:** Claude Code hook protocol only understands exit 0 (allow) and exit 2 (block). There is no "allow with constraints" exit code.
**How to avoid:** Enforcement is applied outside the exit code channel. The sandbox restricts the subprocess; the hook still returns exit 0. Only MALICIOUS produces exit 2. Document this contract explicitly. Test against all 5 verified agent hook APIs (Claude Code, Gemini CLI, Cursor, Windsurf, Copilot).
**Warning signs:** Tests that check `exit_code == 2` for SUSPICIOUS verdicts. Agent logs showing "unexpected exit code."

### Pitfall 6: Network Timeout Blocks Agent
**What goes wrong:** Registry API call to check package existence takes >3 seconds due to DNS failure or registry downtime. The PreToolUse hook blocks, making the agent appear frozen.
**Why it happens:** Hook handlers have no explicit timeout budget. A slow network call consumes the entire hook latency budget.
**How to avoid:** Hard 3-second timeout on all registry API calls. Network failures return None (skip check). Package hallucination is an ADDITIONAL signal, never a gate. If the registry is unreachable, the install command proceeds normally -- detection-only mode.
**Warning signs:** Agent freezes for seconds during `npm install` when offline or on slow network.

## Code Examples

### Landlock Adapter via ctypes (Linux)
```python
# Source: docs.kernel.org/userspace-api/landlock.html + gist.github.com/ConnorNelson/
import ctypes
import ctypes.util
import os

# Syscall numbers (x86_64)
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

# ABI constants
LANDLOCK_RULE_PATH_BENEATH = 0x01
LANDLOCK_ACCESS_FS_READ_FILE = 0x04
LANDLOCK_ACCESS_FS_WRITE_FILE = 0x08
LANDLOCK_ACCESS_FS_READ_DIR = 0x10
LANDLOCK_ACCESS_FS_EXECUTE = 0x01

# Struct layouts
class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]

class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def _landlock_preexec(
    writable: list[str], readable: list[str],
) -> None:
    """Apply Landlock restrictions. Called in child process via preexec_fn."""
    # Set no-new-privs (required)
    _libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS = 38

    # Create ruleset handling all filesystem access types
    handled = (
        LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_EXECUTE
    )
    attr = LandlockRulesetAttr(handled_access_fs=handled)
    fd = _libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr), ctypes.sizeof(attr), 0,
    )
    if fd < 0:
        return  # Landlock unavailable, degrade to noop

    # Add read rules
    for path in readable:
        parent_fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
        rule = LandlockPathBeneathAttr(
            allowed_access=LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
            parent_fd=parent_fd,
        )
        _libc.syscall(
            SYS_LANDLOCK_ADD_RULE, fd,
            LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0,
        )
        os.close(parent_fd)

    # Add write rules (includes read)
    for path in writable:
        parent_fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
        rule = LandlockPathBeneathAttr(
            allowed_access=(
                LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_EXECUTE
            ),
            parent_fd=parent_fd,
        )
        _libc.syscall(
            SYS_LANDLOCK_ADD_RULE, fd,
            LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0,
        )
        os.close(parent_fd)

    # Apply restrictions
    _libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0)
    os.close(fd)
```

### Seatbelt Adapter via ctypes (macOS)
```python
# Source: zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos/
import ctypes

_libsystem = ctypes.CDLL("libSystem.dylib")

def _seatbelt_preexec(
    writable: list[str], readable: list[str], network_allow: list[str],
) -> None:
    """Apply Seatbelt sandbox in child process. Called via preexec_fn."""
    # Generate SBPL profile
    profile_lines = [
        '(version 1)',
        '(deny default)',
        '(import "bsd.sb")',
        # Process execution
        '(allow process-exec file-read*'
        ' (subpath "/bin") (subpath "/usr/bin")'
        ' (subpath "/usr/sbin"))',
        '(allow file-read*'
        ' (subpath "/usr/lib") (subpath "/usr/local/lib"))',
        # System libraries
        '(allow file-read*'
        ' (subpath "/Library/Frameworks")'
        ' (subpath "/System/Library"))',
    ]

    # Always-allowed temp paths
    for tmp in ["/tmp", "/private/tmp", "/private/var/folders"]:
        profile_lines.append(
            f'(allow file-read* file-write* (subpath "{tmp}"))'
        )

    # Readable paths
    for path in readable:
        escaped = path.replace("\\", "\\\\").replace('"', '\\"')
        profile_lines.append(
            f'(allow file-read* (subpath "{escaped}"))'
        )

    # Writable paths
    for path in writable:
        escaped = path.replace("\\", "\\\\").replace('"', '\\"')
        profile_lines.append(
            f'(allow file-read* file-write* (subpath "{escaped}"))'
        )

    # Network (if any allowed)
    if network_allow:
        profile_lines.append(
            '(allow network-outbound (remote ip "0.0.0.0/0"))'
        )
    # If no network_allow, default deny blocks all network

    profile = "\n".join(profile_lines)
    errbuf = ctypes.POINTER(ctypes.c_char_p)()
    ret = _libsystem.sandbox_init_with_parameters(
        ctypes.create_string_buffer(profile.encode("utf-8")),
        0, None, ctypes.byref(errbuf),
    )
    if ret != 0:
        pass  # Sandbox failure: degrade to noop, log in parent
```

### Pipeline Integration Point
```python
# In hooks.py handler (PreToolUse example):
def handle_pre_tool_use(data: dict[str, Any]) -> int:
    engine = _get_bridged_engine()
    detection_result = engine.scan_pre_tool_use(data)

    # NEW: Policy evaluation (Phase 2)
    policy_engine = get_policy_engine()  # Lazy singleton
    policy_decision = policy_engine.evaluate(detection_result, data)

    # NEW: Enforcement (Phase 2)
    adapter = get_sandbox_adapter()  # Auto-selected or from policy
    if (
        policy_decision.action == "constrain"
        and not policy_decision.dry_run
    ):
        adapter.restrict_filesystem(
            writable=policy_decision.constraints.get(
                "filesystem_writable", []
            ),
            readable=policy_decision.constraints.get(
                "filesystem_readable", []
            ),
        )
        adapter.restrict_network(
            allow=policy_decision.constraints.get("network", []),
        )

    # Emit audit event with enforcement details
    _emit_audit_event(
        data, detection_result, "PreToolUse", policy_decision
    )

    # Exit code unchanged: SAFE/SUSPICIOUS -> 0, MALICIOUS -> 2
    return detection_result.exit_code
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Detection-only (exit 0/2) | Detect+Constrain+Audit (three verdicts) | CloneGuard v2 design (2026-04) | Enables graduated response to ambiguous signals |
| Container-based sandboxing | Landlock+Seatbelt (unprivileged, no container) | Kernel 5.13 (Landlock, 2021), widely adopted 2024-2025 | ~0ms overhead vs ~200ms for Docker. Used by Codex, NVIDIA OpenShell [CITED: pierce.dev/notes/a-deep-dive-on-agent-sandboxes, earezki.com/ai-news/2026-03-19-nvidia-openshell] |
| Single sandbox implementation | Protocol-based adapter auto-selection | ai-jail, agent-harbor, Codex (2025-2026) | Cross-platform support without code changes above adapter layer |
| Manual package verification | Automated hallucination detection at install time | Slopsquatting awareness 2025-2026 | Catches AI-invented package names before they execute install scripts |

**Deprecated/outdated:**
- macOS `sandbox-exec` CLI: Deprecated since macOS 10.15 but still functional. Used by Chromium, Claude Code. No replacement API from Apple. [CITED: news.ycombinator.com/item?id=44283454]
- Python `preexec_fn`: Targeted for deprecation (CPython issue #82616) due to deadlock risk with threads. No alternative for arbitrary pre-exec setup. CloneGuard mitigates by being single-threaded. [CITED: github.com/python/cpython/issues/82616]

## Landlock ABI Version Reference

| ABI Version | Kernel | Key Addition | CloneGuard Use |
|-------------|--------|-------------|----------------|
| v1 | 5.13+ | Core filesystem access control | Filesystem restriction (primary) |
| v2 | 5.19+ | File reparenting (REFER) | Prevent symlink-based escapes |
| v3 | 6.2+ | File truncation | Complete write control |
| v4 | 6.7+ | TCP bind/connect | Network restriction |
| v5 | 6.10+ | Device IOCTL | Not needed for Phase 2 |
| v6 | 6.11+ | Abstract UNIX sockets, signals | Not needed for Phase 2 |
| v7 | 6.12+ | Audit logging | Useful for debugging |
| v8 | 6.14+ | TSYNC (multi-threaded enforcement) | Not needed (single-threaded) |

[CITED: docs.kernel.org/userspace-api/landlock.html]

**CloneGuard strategy:** Detect ABI version at runtime. Use highest available. Filesystem restrictions (v1) are the baseline. Network restrictions (v4) are additive. If only v1 is available, log that network restriction is unsupported and skip it.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Direct ctypes in preexec_fn is safe for single-threaded CloneGuard hook processes | Architecture Patterns, Pattern 1 | Deadlocks in production. Mitigation: compiled helper binary fallback is documented |
| A2 | 3-second timeout is sufficient for registry API calls | Pitfall 6 | Too short: misses legitimate slow responses. Too long: blocks agent. Easily tunable via policy config |
| A3 | HEAD requests work for npm registry existence checks | Code Examples, Pattern 5 | npm registry may not support HEAD method efficiently. Fallback: GET with small response. Verified GET works via live test |

## Open Questions

1. **How does CloneGuard apply sandbox restrictions when the agent spawns the subprocess, not CloneGuard?**
   - What we know: Hook handlers receive JSON on stdin and return exit codes. The agent spawns the tool subprocess, not CloneGuard. Landlock/Seatbelt can only be applied by the process spawning the subprocess (via preexec_fn or wrapper).
   - What's unclear: CloneGuard does not control subprocess spawning. The hook protocol has no channel for returning sandbox metadata to the agent.
   - Recommendation: Two viable approaches: (a) For PreToolUse Bash commands, CloneGuard wraps the command -- the hook response includes a modified command string that pipes through `cloneguard-sandbox-exec <restrictions> -- <original-command>`. This requires the agent to honor the modified command. (b) CloneGuard acts as the process launcher itself when enforcement is active, intercepting the subprocess spawn. Both need a spike to validate feasibility within the agent hook protocol.
   - **This is the highest-priority architectural spike for Phase 2.** The entire enforcement model depends on resolving this.

2. **SBPL network restrictions: per-domain or per-IP only?**
   - What we know: SBPL supports `(allow network-outbound (remote ip "x.x.x.x"))` for IP-level filtering.
   - What's unclear: Whether SBPL can filter by hostname directly.
   - Recommendation: Start with allow-all or deny-all network. Per-domain is a later refinement.

3. **npm registry HEAD method support**
   - What we know: GET to registry.npmjs.org/{pkg} returns 200/404 correctly (verified live).
   - What's unclear: Whether HEAD returns the same status codes without downloading the full packument.
   - Recommendation: Use GET with short timeout. The metadata response is small enough that overhead is negligible.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.11+ | Core runtime | Yes | 3.14.3 | -- |
| pydantic | Policy YAML validation | Yes | 2.12.5 | -- |
| pyyaml | YAML parsing | Yes | 6.0.3 | -- |
| macOS sandbox-exec | SeatbeltAdapter | Yes (macOS 26.3.1) | Deprecated but present | NoopAdapter |
| Landlock LSM | LandlockAdapter | No (macOS host) | -- | NoopAdapter; test in Linux CI |
| registry.npmjs.org | Package hallucination (npm) | Yes | -- | Skip check on failure |
| pypi.org | Package hallucination (PyPI) | Yes | -- | Skip check on failure |

**Missing dependencies with no fallback:**
- None. All enforcement adapters fall back to NoopAdapter.

**Missing dependencies with fallback:**
- Landlock LSM unavailable on macOS dev machine. All Landlock code must be tested in Linux CI (ubuntu-latest). Mock-based unit tests on macOS.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not applicable -- CloneGuard is a local tool |
| V3 Session Management | No | Session-scoped caching handled by Phase 1 |
| V4 Access Control | Yes | Landlock/Seatbelt filesystem+network restriction; operator-only config paths |
| V5 Input Validation | Yes | Pydantic validation for policy.yaml; yaml.safe_load only |
| V6 Cryptography | No | No crypto in enforcement layer |

### Known Threat Patterns for Enforcement

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Agent modifies policy.yaml | Tampering | Config at ~/.cloneguard/ (D-18); never from repo. TTY guard for write operations |
| Agent escapes sandbox via symlink | Elevation of Privilege | Landlock resolves symlinks (built-in). Seatbelt: canonicalize paths before profile generation |
| YAML deserialization attack | Tampering | yaml.safe_load only. Pydantic validation rejects unexpected fields |
| Sandbox restriction causes tool failure | Denial of Service (self) | Dry-run default (D-13). Always-allowed minimum paths. Clear error attribution |
| Package name typosquatting | Spoofing | Out of scope for Phase 2 -- existence check only. Typosquatting is Phase 4 |
| Registry API spoofing via DNS | Spoofing | Low risk for existence checks. Future: checksum verification |

## Sources

### Primary (HIGH confidence)
- [Linux Kernel Landlock Documentation](https://docs.kernel.org/userspace-api/landlock.html) - Syscall API, ABI versions v1-v8, inheritance model, restriction semantics
- CloneGuard codebase (`src/cloneguard/`) - Detection engine, audit types, hooks.py, allowlist patterns read directly
- [v2 Architecture Design Doc](docs/plans/2026-04-05-cloneguard-v2-architecture-design.md) - SandboxAdapter Protocol, YAML policy schema, three-verdict model
- [Phase 1 Pitfalls Research](.planning/research/PITFALLS.md) - FPR explosion, enforcement DoS, exit code contract, Seatbelt deprecation
- Live registry API verification - npm and PyPI both return 200/404 as expected [VERIFIED: curl tests]

### Secondary (MEDIUM confidence)
- [Sandboxing subprocesses in Python on macOS](https://zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos/) - sandbox_init_with_parameters ctypes pattern
- [Deep dive on agent sandboxes](https://pierce.dev/notes/a-deep-dive-on-agent-sandboxes) - Codex Landlock implementation, fork+restrict+exec pattern
- [ai-jail Seatbelt implementation](https://deepwiki.com/akitaonrails/ai-jail/4.5-macos:-seatbelt-sandboxing) - SBPL profile generation, deny-default, path escaping
- [Landlock ctypes gist](https://gist.github.com/ConnorNelson/d7b7202c714730c5edc4ea1819c4bc0f) - Pure Python ctypes Landlock with struct definitions
- [NVIDIA OpenShell](https://earezki.com/ai-news/2026-03-19-nvidia-openshell) - Production Landlock LSM for agent sandboxing

### Tertiary (LOW confidence)
- [CPython preexec_fn deprecation](https://github.com/python/cpython/issues/82616) - Planned but no timeline. Functional in 3.11-3.14.
- [Chromium Seatbelt design](https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md) - Apple backward-compat pressure

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Uses only existing dependencies + stdlib. Verified versions.
- Architecture: HIGH for patterns, MEDIUM for enforcement integration (Open Question 1)
- Pitfalls: HIGH - Grounded in Phase 1 research, kernel docs, published implementations
- Landlock details: HIGH on Linux, N/A for dev machine (macOS). Must test in CI.
- Seatbelt details: MEDIUM - Undocumented Apple API, proven by multiple projects.
- Package hallucination: HIGH - Verified live against both registries.

**Research date:** 2026-04-06
**Valid until:** 2026-05-06 (stable domain: Landlock ABI, SBPL, registry APIs change slowly)
