# Claude Code Setup

Get CloneGuard running with Claude Code in under 5 minutes.

## Prerequisites

- Python 3.11+
- Claude Code installed and working

## Install

```bash
pip install "cloneguard[mini]"
```

This installs CloneGuard with the semantic classifier (recommended). Without
`[mini]`, only pattern matching is active.

## Configure Hooks

```bash
cloneguard init --global
```

This writes hook entries into `~/.claude/settings.json` for three events:

| Hook Event | What It Does |
|------------|--------------|
| `PreToolUse` | Gates writes, builds, and config changes before execution |
| `PostToolUse` | Scans tool output for injected instructions |
| `InstructionsLoaded` | Scans CLAUDE.md and rules files when loaded |

## Verify

Open Claude Code in any repository:

```bash
claude
```

CloneGuard scans transparently. When a detection fires, you'll see output in
the hook's stderr. To confirm hooks are registered, check your
`~/.claude/settings.json` for CloneGuard hook entries.

## Project-Level Hooks

For per-project configuration instead of global:

```bash
cd /path/to/project
cloneguard init --project
```

This writes hooks to `.claude/settings.json` in the project directory.

## Trust Cache

For repositories you scan repeatedly, enable the trust cache to skip unchanged
files:

```bash
cloneguard init --global --trust-cache
```

The cache stores SHA-256 content hashes in `~/.cloneguard/trust-cache.json`.
Any file modification -- even a single byte -- invalidates the entry.

## False Positives

Security documentation and research files may trigger detections. Allowlist
reviewed files by content hash:

```bash
cloneguard allow README.md --reason "Documents attack patterns for reference"
```

The allowlist lives in `~/.cloneguard/allowlist.json` -- outside the repository,
so repo content cannot tamper with it. If the file changes, the hash no longer
matches and it's scanned normally.

## What Happens When Something Is Detected

By default, CloneGuard operates in detection-only mode:

- **HIGH severity** findings exit with code 2, which tells Claude Code to block
  the tool call
- **MEDIUM severity** findings log a warning but allow the tool call
- **LOW severity** findings are logged only

To configure enforcement (sandboxing, blocking), see the
[policy engine guide](../guides/policy-engine.md).

## Uninstall

Remove CloneGuard hook entries from `~/.claude/settings.json` (or the
project-level `.claude/settings.json`), then remove the package:

```bash
pip uninstall cloneguard
```
