# Cursor Setup

!!! warning "Untested"
    Hook-level integration with Cursor has not been verified. The
    instructions below are based on protocol compatibility, not testing.
    Standalone scanning (`cloneguard scan`) works regardless.

Cursor uses the same JSON stdin/stdout hook protocol and exit-code
semantics as Claude Code. CloneGuard's hooks are expected to work but
require manual configuration.

## Install

```bash
pip install "cloneguard[mini]"
```

## Configure Hooks

CloneGuard does not have a `cloneguard init` command for Cursor yet.
You need to manually configure hooks in Cursor's settings to point
at `cloneguard hook-check --event <EventName>`.

Cursor uses exit code 0 (allow) or 2 (block).

## .cursorrules Protection (verified)

Cursor loads `.cursorrules` files from repositories automatically. This
is a known attack vector -- malicious repos can include `.cursorrules`
with prompt injection payloads.

CloneGuard's Layer 0 pre-scan catches these before Cursor processes
them. The `RH-003` (reasoning hijack) and `IO-*` (instruction override)
pattern families cover the most common `.cursorrules` attack patterns.

```bash
cloneguard scan /path/to/repo
```

This works today regardless of hook integration.

## Help Us Test

If you use Cursor with CloneGuard hooks, we want to hear about it.
[Open an issue](https://github.com/prodnull/cloneguard/issues) with
your experience.
