# Gemini CLI Setup

!!! warning "Untested"
    Hook-level integration with Gemini CLI has not been verified. The
    instructions below are based on protocol compatibility, not testing.
    Standalone scanning (`cloneguard scan`) works regardless.

Gemini CLI uses the same JSON stdin/stdout hook protocol and exit-code
semantics as Claude Code. CloneGuard's hooks are expected to work but
require manual configuration.

## Install

```bash
pip install "cloneguard[mini]"
```

## Configure Hooks

CloneGuard does not have a `cloneguard init` command for Gemini CLI yet.
You need to manually configure hooks in Gemini CLI's settings to point
at `cloneguard hook-check --event <EventName>` for the relevant events.

The hook command format is the same as Claude Code:

```
cloneguard hook-check --event PreToolUse
cloneguard hook-check --event PostToolUse
```

Gemini CLI reads JSON from stdin and expects exit code 0 (allow) or 2
(block).

## Standalone Scan (verified)

Layer 0 standalone scanning works with any agent:

```bash
cloneguard scan /path/to/repo
```

Run this before opening a repo with Gemini CLI for pre-execution
protection.

## Help Us Test

If you use Gemini CLI with CloneGuard hooks, we want to hear about it.
[Open an issue](https://github.com/prodnull/cloneguard/issues) with
your experience.
