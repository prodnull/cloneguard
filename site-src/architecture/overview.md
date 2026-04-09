# Architecture Overview

CloneGuard operates as an independent trust boundary between the AI coding
agent and the commands it executes. It cannot be disabled by repository content
because it runs at the hook layer, outside the agent's control.

## Defense Layers

```
Repository files
       |
  Layer 0: Pre-execution scan (before agent launches)
       |
  Agent starts
       |
  Layer 1: InstructionsLoaded (scans CLAUDE.md, rules files)
       |
  Agent works...
       |
  Layer 2: PostToolUse (scans tool output for injected instructions)
       |
  Layer 3: PreToolUse (gates writes, builds, config changes)
       |
  Tool executes (or is blocked/constrained)
```

### Layer 0: Pre-Execution Wrapper

Scans all high-priority and medium-priority files in the repository before the
agent starts. Blocks agent launch if critical findings are detected.

Cannot be disabled by repository content -- executes before the agent reads
any files.

### Layer 1: InstructionsLoaded

Scans instruction files (CLAUDE.md, `.claude/rules/*.md`, `.cursorrules`) when
the agent loads them. Uses STRICT scan mode -- HIGH severity findings result in
a hard block.

### Layer 2: PostToolUse

Scans all tool output for injection patterns. Catches payloads injected via
tool results -- for example, a `cat` command reading a malicious file that
contains prompt injection.

### Layer 3: PreToolUse

Gates dangerous operations before execution:

- Blocks writes to protected paths (`~/.claude/settings.json`, trust stores)
- Scans content being written to sensitive files (package.json, Makefile)
- Warns on build commands (`npm install`, `pip install`, `cargo build`)
- Blocks allowlist manipulation (`cloneguard allow` in Bash)
- Blocks bypass attempts (`cloneguard --bypass`, `claude --bypass`)

## Detection Signals

Three independent signals are computed for each tool call:

| Signal | Method | Speed | Strengths |
|--------|--------|-------|-----------|
| Pattern | 240 compiled regex rules | <50ms | Fast, predictable, catches known patterns |
| Semantic | MiniLM-L6-v2 ONNX classifier | ~16ms/sample | Catches synonym substitution, encoding evasion, social engineering |
| Behavioral | CaMeL-lite session-wide monitoring | <0.5ms/event | Catches multi-step sequences (read credentials, then exfiltrate) |

Signals are combined by the fusion layer into a single verdict with calibrated
confidence. See [Detection Engine](detection-engine.md) for details.

## Enforcement Pipeline

```
Detection signals
       |
  Fusion layer (weighted combination)
       |
  Verdict: SAFE / SUSPICIOUS / MALICIOUS
       |
  Policy engine (YAML rules, per-tool overrides)
       |
  Action: allow / constrain (sandbox) / block
```

When enforcement is enabled, SUSPICIOUS verdicts can constrain the tool call
via OS-level sandboxing (Landlock on Linux, Seatbelt on macOS) without affecting
CloneGuard itself. See [Enforcement](enforcement.md) for details.

Default mode is dry-run: detect and log, do not enforce.

## Audit Trail

Every detection event emits structured logs in three formats:

- **NDJSON** -- one line per event, machine-readable
- **SARIF 2.1.0** -- for GitHub Advanced Security and code scanning tools
- **OTel spans** -- for observability pipelines (when enabled)

See [Audit](audit.md) for details.
