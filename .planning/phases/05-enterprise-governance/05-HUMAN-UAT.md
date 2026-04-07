---
status: partial
phase: 05-enterprise-governance
source: [05-VERIFICATION.md]
started: 2026-04-06
updated: 2026-04-06
---

## Current Test

[awaiting human testing]

## Tests

### 1. OPA and Cedar backends with libraries installed
expected: Install regopy and cedarpy, run `uv run pytest tests/test_policy_backends.py`. All 20 OPA/Cedar tests should pass (currently skip because libs not installed in dev env).
result: [pending]

### 2. Ansible idempotency on a real host
expected: Run site playbook twice against a test VM. Second run should report zero changes. Templates should render valid policy.yaml and settings.json.
result: [pending]

### 3. MDM profile deployment on macOS
expected: Sign a .mobileconfig and push via Jamf or Intune to a test device. Profile installs without warning, payload executes correctly.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
