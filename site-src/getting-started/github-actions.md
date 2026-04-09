# GitHub Actions Setup

Run CloneGuard as a CI check on pull requests with SARIF upload to
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

      - run: pip install "cloneguard[mini]"

      - name: Run CloneGuard scan
        run: cloneguard scan --sarif results.sarif .

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## SARIF Output

The `--sarif FILE` flag writes SARIF 2.1.0 output validated against the OASIS
schema. Results appear in the repository's Security tab under Code Scanning.

Human-readable output still prints to stdout alongside the SARIF file write.

## Without SARIF

For a simpler setup that just fails the check on findings:

```yaml
steps:
  - uses: actions/checkout@v4
  - run: pip install "cloneguard[mini]"
  - run: cloneguard scan .
```

Exit code 2 (findings at HIGH severity) will fail the workflow step.

## JSON Output

For custom CI integrations that parse structured output:

```yaml
- run: cloneguard scan --json . > results.ndjson
```

See [Standalone CLI](standalone-cli.md) for all output format options.
