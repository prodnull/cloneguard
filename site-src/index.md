# CloneGuard

**Hook-level prompt injection defense for AI coding agents.**

Your AI agent reads untrusted repos. CloneGuard watches what it does next.

CloneGuard runs at the hook layer -- before tool calls execute, outside the
agent's control. It detects prompt injection attempts, constrains suspicious
operations via OS-level sandboxing, and emits structured audit logs.

<div class="grid cards" markdown>

- :material-clock-fast: **5-Minute Setup**

    Install from PyPI, run one command, and CloneGuard is active in Claude Code.

    [:octicons-arrow-right-24: Getting started](getting-started/claude-code.md)

- :material-shield-search: **240 Detection Rules**

    Pattern matching, semantic classification, and behavioral sequence monitoring
    across 34 attack categories.

    [:octicons-arrow-right-24: Detection engine](architecture/detection-engine.md)

- :material-lock-outline: **Detect, Constrain, Audit**

    Three-verdict enforcement with OS-level sandboxing. Dry-run by default.

    [:octicons-arrow-right-24: Enforcement](architecture/enforcement.md)

- :material-connection: **Works With Any Agent**

    Built for Claude Code. Standalone scan works with any agent.
    Hook protocol compatible with Gemini CLI, Cursor, and Windsurf.

    [:octicons-arrow-right-24: Getting started](getting-started/claude-code.md)

</div>

## Install

```bash
pip install cloneguard            # Pattern matching only
pip install "cloneguard[mini]"    # + semantic classifier (recommended)
```

## Development Status

CloneGuard is in active development (v0.6.0). The core detection engine is
tested with 1,677 automated tests and false positive rates calibrated against
208,127 real coding-agent sessions from published SWE-bench datasets.

Enterprise features (policy backends, SIEM connectors, fleet deployment) are
early-stage and experimental.

We want feedback -- [open an issue](https://github.com/prodnull/cloneguard/issues)
or contribute.
