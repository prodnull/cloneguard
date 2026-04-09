# GitHub Actions Setup

Run CloneGuard as a CI check on pull requests. Uploads SARIF results to
GitHub's Security tab.

## Basic Workflow

```yaml
name: CloneGuard Scan
on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: prodnull/cloneguard-action@v1
        with:
          tier: "1.5"          # pattern + semantic (default)
          sarif: true          # upload to Security tab
          fail-on: "high"      # fail the check on HIGH findings
```

## SARIF Integration

When `sarif: true` is set, CloneGuard produces a SARIF 2.1.0 file validated
against the OASIS schema. Results appear in the repository's Security tab under
Code Scanning.

## Configuration

| Input | Default | Description |
|-------|---------|-------------|
| `tier` | `1.5` | Detection tier: `0` (regex only), `1.5` (+ semantic), `2` (+ Ollama) |
| `sarif` | `true` | Upload SARIF to GitHub Security tab |
| `fail-on` | `high` | Severity threshold to fail the check: `high`, `medium`, `low` |
| `scan-path` | `.` | Path to scan |

## Standalone (Without the Action)

```yaml
steps:
  - uses: actions/checkout@v4

  - run: pip install "cloneguard[mini]"

  - run: cloneguard scan --sarif results.sarif .

  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: results.sarif
```

## Next Steps

- [SARIF output format](../architecture/audit.md)
- [Policy engine configuration](../guides/policy-engine.md)
