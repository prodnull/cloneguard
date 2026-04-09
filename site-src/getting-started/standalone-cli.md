# Standalone CLI

Scan any repository without agent integration. Useful for one-off audits,
CI pipelines, or agents without hook support.

## Install

```bash
pip install "cloneguard[mini]"
```

## Scan a Repository

```bash
cloneguard scan /path/to/repo
cloneguard scan                      # current directory
cloneguard scan --tier2              # with Ollama fallback (requires ollama)
cloneguard scan --cache              # with trust cache for repeated scans
```

## Output Format

```bash
cloneguard scan .                    # human-readable terminal output
```

Structured audit events are emitted as NDJSON to stderr during scanning.
See [Audit](../architecture/audit.md) for the event schema.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings, or findings below threshold |
| 1 | Error (invalid path, missing dependencies) |
| 2 | Findings at or above threshold severity |

## Manage False Positives

```bash
cloneguard allow README.md --reason "Documents attack patterns"
cloneguard list                      # show allowlisted files
cloneguard remove README.md          # remove from allowlist
```

## Next Steps

- [Detection engine details](../architecture/detection-engine.md)
- [Policy engine configuration](../guides/policy-engine.md)
