# GitHub Actions Setup

GitHub Actions integration is planned for a future release.

This will include a reusable action (`prodnull/cloneguard-action`) for running
CloneGuard scans on pull requests as a CI check.

For now, you can run CloneGuard in CI by installing it directly:

```yaml
steps:
  - uses: actions/checkout@v4
  - run: pip install "cloneguard[mini]"
  - run: cloneguard scan .
```
