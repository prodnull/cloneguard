# Gemini CLI Setup

CloneGuard works with Gemini CLI v0.30.1+ via its hook system.

## Prerequisites

- Python 3.11+
- Gemini CLI installed and working

## Install

```bash
pip install "cloneguard[mini]"
```

## Configure Hooks

Gemini CLI supports migrating Claude Code hook configurations:

```bash
gemini hooks migrate --from-claude
```

Or configure manually. Gemini CLI supports 11 hook events with the same
JSON stdin/stdout protocol and exit-code semantics as Claude Code.

## Verify

```bash
gemini
```

CloneGuard scans tool calls transparently via Gemini's hook pipeline.

## Differences from Claude Code

- Gemini CLI exposes more hook events (11 vs 3), but CloneGuard uses the same
  core set: pre-tool, post-tool, and instructions-loaded
- Event names use the same convention
- Exit code 0 = allow, exit code 2 = block

## Next Steps

- [Policy engine configuration](../guides/policy-engine.md)
- [Architecture overview](../architecture/overview.md)
