# CloneGuard Usage Guide

How CloneGuard protects you, what it does at each stage, and how to use it day-to-day.

## Who This Is For

You use an AI coding agent — Claude Code, Gemini CLI, Codex CLI, Cursor, or GitHub Copilot — and you work with code you didn't write: open-source repos, external PRs, contractor code, CI/CD pipelines processing third-party input. CloneGuard scans that content for prompt injection before the agent can act on it.

## The Problem in 30 Seconds

AI coding agents read files in your repo and follow instructions they find there. An attacker who controls any of that content — a CLAUDE.md, a README, a package.json, even an HTML comment in a GitHub issue — can inject instructions that make the agent exfiltrate secrets, install backdoors, or disable security controls. This is not theoretical: it has assigned CVEs, confirmed incidents, and published research demonstrating 84% attack success rates across major tools.

CloneGuard sits between untrusted content and your agent. It scans before the agent reads, and monitors while the agent works.

## Install

**From GitHub Release (recommended):**

Download the latest `.whl` from [Releases](https://github.com/prodnull/cloneguard/releases), then:

```bash
pip install cloneguard-*.whl            # Includes ONNX model
pip install "cloneguard[mini]" --find-links .  # Install runtime deps for the model
```

**From PyPI** (when available):

```bash
pip install cloneguard            # Tier 0 regex only (175 patterns, <50ms)
pip install cloneguard[mini]      # + Tier 1.5 ONNX model (recommended, ~16ms/file)
pip install cloneguard[all]       # + Ollama fallback
```

The `[mini]` install is recommended. It bundles a fine-tuned classifier (87 MB) that catches semantic attacks regex cannot — synonym substitution, social engineering, encoding evasion — with 95.9% cross-validated F1 and no external dependencies.

## Setup (One Time)

```bash
cloneguard setup
```

This does two things:

1. **Installs global hooks** into `~/.claude/settings.json` — these are Claude Code's hook system. Every time Claude Code loads instructions, uses a tool, or produces output, CloneGuard's hooks fire automatically.

2. **Adds a shell alias** (`alias claude='cloneguard'`) to your shell RC file (`.zshrc`, `.bashrc`, or `config.fish`). This means when you type `claude`, CloneGuard runs first, scans the repo, and then launches Claude Code.

After setup, activate it:

```bash
source ~/.zshrc   # or ~/.bashrc
```

That's it. You now use `claude` exactly as before. CloneGuard is transparent.

## What Happens When You Type `claude`

Because of the shell alias, `cloneguard` runs instead of `claude` directly. Here's the sequence:

### Layer 0: Pre-Execution Scan

Before the agent starts, CloneGuard scans every high-priority file in the repo:

| Files Scanned | Why |
|---------------|-----|
| `CLAUDE.md`, `GEMINI.md`, `.cursorrules` | Agent instruction files — highest risk |
| `.claude/rules/*.md`, `.claude/commands/*.md` | Claude Code custom rules and commands |
| `README.md`, `CONTRIBUTING.md` | Often contain hidden HTML comments with injections |
| `package.json`, `Makefile`, `pyproject.toml`, `setup.py` | Build scripts can contain payload triggers |
| `.github/workflows/*.yml`, `.github/copilot-instructions.md` | CI/CD and Copilot config |
| `.devcontainer/devcontainer.json` | Docker privilege escalation |
| `.claude/settings.json` | Hook/MCP tampering |
| `.env`, `.env.*` | Environment variable hijacking |
| `*.svg` | SVG script injection |
| Plus 15+ more medium-priority files | See source for full list |

**Tier 0 (regex)** runs on every file: 175 compiled patterns across 23 attack categories, completing in under 50ms.

**Tier 1.5 (ONNX model)** runs automatically if installed: catches what regex misses — semantic rephrasing, social engineering, encoded payloads — at ~16ms per file.

**Results determine what happens next:**

| Result | Action |
|--------|--------|
| All clean | Agent launches normally |
| Warnings (MEDIUM severity) | You're prompted: "Issues found. Proceed? [y/N]" |
| Blocked (HIGH/CRITICAL severity) | Agent refused to launch. You must fix or allowlist the files. |

**This layer cannot be disabled by repository content.** It runs before the agent reads anything.

### Layer 1: InstructionsLoaded Hook

When Claude Code loads instruction files (CLAUDE.md, `.claude/rules/*.md`), CloneGuard's hook fires and scans the content with STRICT mode. HIGH severity = hard block (exit 2). The agent cannot proceed until the file is cleaned or allowlisted.

### Layer 2: PostToolUse Hook

After every tool call (file reads, bash commands, web fetches), CloneGuard scans the output for injection patterns. If a `cat` command reveals a malicious file, or a tool returns poisoned content, CloneGuard catches it and injects a warning into the agent's context.

### Layer 3: PreToolUse Hook

Before dangerous operations execute, CloneGuard gates them:

- **Protected paths** — Blocks writes to `~/.claude/settings.json`, trust stores, and other config files. An injected instruction telling the agent to disable hooks is stopped here.
- **Content-aware write scanning** — When the agent writes to `package.json`, `Makefile`, `CLAUDE.md`, or other sensitive files, the content is scanned before it hits disk.
- **Allowlist protection** — Blocks `cloneguard allow` and `cloneguard remove` in Bash commands. An injected instruction cannot make the agent allowlist a malicious file.
- **Bypass prevention** — Blocks `cloneguard --bypass` and `claude --bypass` in Bash commands.
- **Build command warnings** — Warns on `npm install`, `pip install`, `cargo build`, etc. so you know when untrusted build scripts are about to execute.

## Standalone Scanning

You don't have to use the wrapper. You can scan any directory on demand:

```bash
# Quick regex scan
cloneguard scan /path/to/repo

# With semantic classification (recommended)
cloneguard scan --tier2

# With trust cache (skip unchanged files on repeat scans)
cloneguard scan --tier2 --cache

# Current directory
cloneguard scan
```

This is useful for:
- Scanning a repo before you `cd` into it
- CI/CD pipelines (scan before the agent runs)
- Batch scanning multiple repos
- Checking a specific directory without launching an agent

## Handling False Positives

Security documentation, pentesting guides, and research files will trigger detections because they describe attack patterns. This is expected.

```bash
# Review what triggered
cloneguard scan

# If you've verified the file is safe, allowlist it by content hash
cloneguard allow docs/SECURITY.md --reason "Documents attack patterns for defense"

# View allowlisted files
cloneguard list

# Remove from allowlist
cloneguard remove docs/SECURITY.md
```

**Key properties:**
- The allowlist is stored in `~/.cloneguard/allowlist.json` — outside the repo. Repository content cannot tamper with it.
- Entries are content-hash based. If you allowlist a file and someone later modifies it (even by one byte), the hash no longer matches and the file is scanned normally.
- `cloneguard allow` and `cloneguard remove` require an interactive terminal. They refuse to run in non-interactive mode (pipes, scripts, agent subprocesses).
- The PreToolUse hook blocks the agent from running these commands via Bash.

## Trust Cache

For large repos or repeated scans, the trust cache skips re-scanning files that haven't changed:

```bash
cloneguard scan --tier2 --cache
```

When a file passes scanning, its SHA-256 hash is cached in `~/.cloneguard/trust-cache.json`. On subsequent scans, if the hash matches, the file is skipped. Any modification invalidates the entry.

The cache is enabled automatically when using the `claude` wrapper (Layer 0).

## YOLO Mode Protection

If you (or someone else) runs Claude Code with `--dangerously-skip-permissions`, CloneGuard detects this and escalates scan strictness — MEDIUM findings become HIGH, increasing the chance of blocking before the agent auto-approves dangerous operations.

```bash
# CloneGuard detects YOLO and tightens scanning
claude --dangerously-skip-permissions
# Output: "YOLO mode detected — CloneGuard enforcing stricter scanning"
```

## What CloneGuard Does NOT Do

- **It is not a sandbox.** Once content passes all detection tiers and the agent starts processing it, CloneGuard does not constrain what the agent does. A novel payload that evades all tiers will execute normally.
- **It does not catch logic bugs or traditional vulnerabilities.** XSS, SQL injection, buffer overflows — these are not prompt injection and are not in scope.
- **It does not analyze build script behavior.** CloneGuard warns when build commands run, but it cannot predict what a Makefile will do.
- **It is not a replacement for code review.** CloneGuard catches prompt injection. You still need to review code for correctness and security.

## Agent Support

CloneGuard's **Layer 0 wrapper and standalone scanner** work with any workflow — they scan files before any agent runs. The regex patterns and ONNX classifier detect attacks targeting all major agents — detection is content-based, not agent-specific.

**Layers 1-3 (runtime hooks)** currently implement Claude Code's hook protocol. Four additional agents expose compatible hook APIs — all verified via source inspection, live testing, or official documentation:

| Agent | Layer 0 | Layers 1-3 | Events | Protocol | Config Location | Verified By |
|-------|:---:|:---:|:---:|----------|----------------|-------------|
| **Claude Code** | Yes | **Implemented** | 3 | JSON stdin/stdout, exit 0/2 | `~/.claude/settings.json` | Source + live |
| **Gemini CLI** | Yes | Planned | 11 | JSON stdin/stdout, exit 0/1/2 | `~/.gemini/settings.json` | Source + live test |
| **Cursor** | Yes | Planned | 19+ | JSON stdin/stdout, exit 0/2 | `.cursor/hooks.json` | [Docs](https://cursor.com/docs/hooks) |
| **Windsurf** | Yes | Planned | 12 | JSON stdin, exit 0/2 | `.windsurf/hooks.json` | [Docs](https://docs.windsurf.com/windsurf/cascade/hooks) |
| **VS Code Copilot** | Yes | Planned | 8 | JSON stdin/stdout, exit 0/2 | `.github/hooks/*.json` | [Docs](https://code.visualstudio.com/docs/copilot/customization/hooks) |
| **Codex CLI** | Yes | Not yet | — | — | — | — |
| **Roo Code** | Yes | Not yet | — | — | — | — |
| **Aider** | Yes | Not yet | — | — | — | — |

**Key finding:** All five hook-capable agents converge on the same core pattern: JSON config file, JSON on stdin, exit-code blocking (0=allow, 2=block). A single CloneGuard hook script works across all five with only config-file differences.

**Gemini CLI specifics (verified on v0.30.1):**
- `gemini hooks migrate --from-claude` auto-converts Claude Code hook config
- Maps events: `PreToolUse→BeforeTool`, `PostToolUse→AfterTool`, `UserPromptSubmit→BeforeAgent`
- Maps tool names: `Edit→replace`, `Bash→run_shell_command`, `Read→read_file`
- Unique events not in Claude Code: `BeforeModel`, `AfterModel`, `BeforeToolSelection`
- Hooks require trust via `~/.gemini/trusted_hooks.json` before they fire

**VS Code Copilot specifics:**
- Uses the **same config files** as Claude Code (`.claude/settings.json`)
- Uses the **same event names** (`PreToolUse`, `PostToolUse`, `SessionStart`, etc.)
- "Most restrictive wins" when multiple hooks run for the same tool invocation
- Preview feature, available in VS Code 1.109+ (January 2026)

**Cursor specifics:**
- Richest hook API (19+ events including `beforeShellExecution`, `beforeMCPExecution`, `afterAgentThought`)
- Unique `failClosed: true` option — hook failures block actions instead of allowing them
- Unique `prompt`-type hooks — uses LLM to evaluate natural language conditions
- Enterprise: system-level config at `/Library/Application Support/Cursor/hooks.json` (macOS)

**Windsurf specifics:**
- Uses snake_case event names (`pre_run_command`, `pre_write_code`, `pre_mcp_tool_use`)
- `show_output` flag to display hook results in Cascade UI
- Full transcript access via `post_cascade_response_with_transcript`
- Enterprise: MDM distribution, system-level config, cloud dashboard

### Event Mapping

CloneGuard's three hook events map to each agent as follows:

| CloneGuard Layer | Claude Code | Gemini CLI | Cursor | Windsurf | VS Code Copilot |
|-----------------|-------------|------------|--------|----------|-----------------|
| L1: InstructionsLoaded | `InstructionsLoaded` | *(none)* | *(none)* | *(none)* | *(none)* |
| L2: PostToolUse | `PostToolUse` | `AfterTool` | `postToolUse` | `post_run_command` / `post_read_code` | `PostToolUse` |
| L3: PreToolUse | `PreToolUse` | `BeforeTool` | `preToolUse` | `pre_run_command` / `pre_write_code` | `PreToolUse` |

**Gap:** No agent besides Claude Code has an `InstructionsLoaded` equivalent. Layer 0 (pre-execution scan) mitigates this by scanning instruction files before any agent starts.

### MCP Gateway Integration

For agents without hooks — or as an additional defense layer for any agent — the **MCP gateway pattern** provides agent-agnostic runtime scanning. An MCP gateway sits between the agent and MCP servers, intercepting all tool calls and responses:

```
Agent <-> CloneGuard MCP Gateway Plugin <-> MCP Server(s)
```

CloneGuard includes an MCP Gateway guardrail plugin (`cloneguard.mcp_plugin`) that integrates with the [MCP Gateway](https://github.com/lasso-security/mcp-gateway) (`pip install mcp-gateway`). The plugin scans tool requests and responses using Tier 0 regex + Tier 1.5 ONNX — entirely offline, no external API required.

**Time penalty per MCP request:**

| Component | Latency | What it covers |
|-----------|---------|---------------|
| Tier 0 regex scan | <5 ms | 175 patterns, known attack signatures |
| Tier 1.5 ONNX scan | ~16 ms | Semantic attacks, synonym evasion, social engineering |
| Combined | ~20 ms | Both tiers |
| Typical LLM API call | 2–30 sec | For comparison — CloneGuard adds <1% overhead |

The gateway plugin covers MCP-based tool calls regardless of the agent, but does not cover native file/shell operations (which require agent-specific hooks). Use both for defense in depth.

## Example Workflows

### Reviewing an External PR

```bash
cd my-project
git fetch origin pull/42/head:pr-42
git checkout pr-42
cloneguard scan --tier2
# Review results, then:
claude
```

### Working in an Unfamiliar Repo

```bash
git clone https://github.com/someone/their-repo.git
cd their-repo
cloneguard scan --tier2
# If clean:
claude   # wrapper scans again + hooks monitor at runtime
```

### CI/CD Pipeline

```bash
pip install cloneguard[mini]
cloneguard scan --tier2 /path/to/checkout
if [ $? -eq 2 ]; then
  echo "BLOCKED: Prompt injection detected"
  exit 1
fi
# Safe to proceed with AI agent
```

### Batch Scanning Multiple Repos

```bash
for repo in repos/*/; do
  echo "=== $repo ==="
  cloneguard scan --tier2 "$repo"
done
```
