# Gemini CLI Setup

CloneGuard works with Gemini CLI v0.37+ via hook integration. Tested
and verified on Gemini CLI 0.37.0.

## Install

```bash
pip install "cloneguard[mini]"
```

## Configure Hooks

Add CloneGuard hooks to `~/.gemini/settings.json`. Gemini CLI uses
`BeforeTool` and `AfterTool` event names (not Claude Code's
`PreToolUse`/`PostToolUse`). CloneGuard handles the translation
automatically.

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "cloneguard hook-check --event PreToolUse"
          }
        ]
      }
    ],
    "AfterTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "cloneguard hook-check --event PostToolUse"
          }
        ]
      }
    ]
  }
}
```

Use the full path to `cloneguard` if it's in a virtual environment.

## How It Works

CloneGuard normalizes Gemini CLI's hook format automatically:

- `BeforeTool` / `AfterTool` are mapped to `PreToolUse` / `PostToolUse`
- Tool names (`read_file`, `run_shell_command`, `edit_file`, `write_file`)
  are mapped to Claude Code equivalents (`Read`, `Bash`, `Edit`, `Write`)
- Tool output is extracted from `tool_response.llmContent`

Exit code 0 = allow, exit code 2 = block.

## Standalone Scan

Layer 0 standalone scanning works without any hook configuration:

```bash
cloneguard scan /path/to/repo
```

## Next Steps

- [Policy engine configuration](../guides/policy-engine.md)
- [Architecture overview](../architecture/overview.md)
