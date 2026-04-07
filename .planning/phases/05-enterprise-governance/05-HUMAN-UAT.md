---
status: resolved
phase: 05-enterprise-governance
source: [05-VERIFICATION.md]
started: 2026-04-06
updated: 2026-04-07
---

## Current Test

[complete]

## Tests

### 1. OPA and Cedar backends with libraries installed
expected: Install regopy and cedarpy, run `uv run pytest tests/test_policy_backends.py`. All 20 OPA/Cedar tests should pass (currently skip because libs not installed in dev env).
result: PASSED — 29/29 tests passed with regopy==1.3.0 and cedarpy==4.8.0 installed. All OPA compile/validate/round-trip and Cedar compile/validate/round-trip tests green.

### 2. Ansible idempotency on a real host
expected: Run site playbook twice against a test VM. Second run should report zero changes. Templates should render valid policy.yaml and settings.json.
result: PASSED — Docker (python:3.12-slim + ansible-core). Run 1: changed=3 (dirs + templates). Run 2: changed=0 (fully idempotent). policy.yaml renders correct thresholds, dry_run, sandbox config. settings.json renders all three hook events correctly.

### 3. MDM profile deployment on macOS
expected: Sign a .mobileconfig and push via Jamf or Intune to a test device. Profile installs without warning, payload executes correctly.
result: SKIPPED — no MDM environment available. XML structure validated by test suite (41 tests).

## Summary

total: 3
passed: 2
issues: 0
pending: 0
skipped: 1
blocked: 0

## Gaps
