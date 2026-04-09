# Cursor Setup

CloneGuard works with Cursor v2.6.13+ via its hook system.

## Prerequisites

- Python 3.11+
- Cursor installed and working

## Install

```bash
pip install "cloneguard[mini]"
```

## Configure Hooks

Cursor supports 19+ hook events with `failClosed` and `prompt`-type hooks.
Configure CloneGuard in Cursor's hook settings to run on pre-tool and post-tool
events.

Cursor uses the same JSON stdin/stdout protocol and exit-code semantics:
exit 0 = allow, exit 2 = block.

## .cursorrules Protection

Cursor loads `.cursorrules` files from repositories automatically. This is a
known attack vector -- malicious repos can include `.cursorrules` with prompt
injection payloads.

CloneGuard's Layer 0 pre-scan catches these before Cursor processes them. The
`RH-003` (reasoning hijack) and `IO-*` (instruction override) pattern families
cover the most common `.cursorrules` attack patterns.

## Next Steps

- [Policy engine configuration](../guides/policy-engine.md)
- [Architecture overview](../architecture/overview.md)
