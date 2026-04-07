---
phase: 05-enterprise-governance
plan: 03
subsystem: infra
tags: [ansible, mdm, jamf, intune, fleet-deployment, mobileconfig, jinja2]

# Dependency graph
requires:
  - phase: 05-enterprise-governance
    provides: "Policy engine YAML config format (05-01)"
provides:
  - "Ansible role for CloneGuard fleet deployment (uv/pipx/pip)"
  - "Jinja2 templates for policy.yaml and Claude Code settings.json"
  - "MDM .mobileconfig profiles for Jamf and Intune macOS deployment"
  - "Example site playbook with developer_workstations and ci_runners groups"
affects: [fleet-management, enterprise-deployment, ci-cd-integration]

# Tech tracking
tech-stack:
  added: [ansible-role, mobileconfig-plist, jinja2-templates]
  patterns: [idempotent-deployment, unsigned-template-signing, safe-default-dry-run]

key-files:
  created:
    - src/cloneguard/fleet/ansible/roles/cloneguard/tasks/main.yml
    - src/cloneguard/fleet/ansible/roles/cloneguard/defaults/main.yml
    - src/cloneguard/fleet/ansible/roles/cloneguard/templates/policy.yaml.j2
    - src/cloneguard/fleet/ansible/roles/cloneguard/templates/settings.json.j2
    - src/cloneguard/fleet/ansible/roles/cloneguard/handlers/main.yml
    - src/cloneguard/fleet/ansible/roles/cloneguard/meta/main.yml
    - src/cloneguard/fleet/ansible/site.yml
    - src/cloneguard/fleet/mdm/jamf/cloneguard-install.mobileconfig
    - src/cloneguard/fleet/mdm/jamf/cloneguard-policy.mobileconfig
    - src/cloneguard/fleet/mdm/intune/cloneguard-install.mobileconfig
    - src/cloneguard/fleet/mdm/intune/cloneguard-policy.mobileconfig
    - src/cloneguard/fleet/mdm/README.md
    - tests/test_fleet_artifacts.py
  modified: []

key-decisions:
  - "Ship MDM profiles unsigned as templates with documented signing instructions (per research pitfall 5)"
  - "Safe default dry_run=true in both Ansible defaults and MDM policy profiles"
  - "Ansible tasks use become=false for all user-config operations (T-05-14 mitigation)"
  - "Policy files deployed with mode 0600 and backup=true (T-05-13 mitigation)"

patterns-established:
  - "Fleet artifact structure: src/cloneguard/fleet/{ansible,mdm}/ shipped in package"
  - "Idempotent Ansible role: version check before install, backup before overwrite"
  - "FQCN module references (ansible.builtin.*) throughout role tasks"
  - "Platform-specific MDM PayloadIdentifier prefixes (com.cloneguard vs com.microsoft.intune.cloneguard)"

requirements-completed: [GOVN-05]

# Metrics
duration: 5min
completed: 2026-04-06
---

# Phase 5 Plan 3: Fleet Deployment Summary

**Ansible role with idempotent uv/pipx/pip installation and Jinja2 policy templates, plus Jamf and Intune MDM profiles for macOS fleet deployment**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-06T23:39:37Z
- **Completed:** 2026-04-06T23:44:34Z
- **Tasks:** 2
- **Files modified:** 13

## Accomplishments
- Ansible role deploys CloneGuard with centralized policy to Linux servers and CI runners via uv, pipx, or pip
- Jinja2 templates generate valid policy.yaml (thresholds, sandbox, dry_run) and Claude Code settings.json (hook events)
- MDM .mobileconfig profiles for both Jamf and Intune deliver install scripts and policy with safe defaults
- 41 validation tests verify YAML parsing, FQCN usage, content patterns, XML validity, and plist keys

## Task Commits

Each task was committed atomically:

1. **Task 1: Ansible role for CloneGuard fleet deployment** - `45b6f32` (feat)
2. **Task 2: MDM profiles for Jamf and Intune macOS deployment** - `c6353d1` (feat)

## Files Created/Modified
- `src/cloneguard/fleet/ansible/roles/cloneguard/tasks/main.yml` - Idempotent task list with 9 tasks (version check, 3 install methods, directory setup, policy deploy, hook settings)
- `src/cloneguard/fleet/ansible/roles/cloneguard/defaults/main.yml` - 15 configurable variables with safe defaults
- `src/cloneguard/fleet/ansible/roles/cloneguard/templates/policy.yaml.j2` - Policy config template with threshold and sandbox variables
- `src/cloneguard/fleet/ansible/roles/cloneguard/templates/settings.json.j2` - Claude Code hook settings with event loop
- `src/cloneguard/fleet/ansible/roles/cloneguard/handlers/main.yml` - Post-deploy verification handler
- `src/cloneguard/fleet/ansible/roles/cloneguard/meta/main.yml` - Galaxy metadata for Ubuntu, Debian, EL, macOS
- `src/cloneguard/fleet/ansible/site.yml` - Example playbook with developer_workstations and ci_runners groups
- `src/cloneguard/fleet/mdm/jamf/cloneguard-install.mobileconfig` - Jamf install profile (auto-detects uv/pipx/pip3)
- `src/cloneguard/fleet/mdm/jamf/cloneguard-policy.mobileconfig` - Jamf policy profile (dry_run=true)
- `src/cloneguard/fleet/mdm/intune/cloneguard-install.mobileconfig` - Intune install profile
- `src/cloneguard/fleet/mdm/intune/cloneguard-policy.mobileconfig` - Intune policy profile
- `src/cloneguard/fleet/mdm/README.md` - Signing, deployment, customization, and troubleshooting guide
- `tests/test_fleet_artifacts.py` - 41 tests validating YAML structure, XML validity, content patterns

## Decisions Made
- Ship MDM profiles unsigned as templates with documented signing instructions -- per research pitfall 5, organizations must sign with their own certificates
- Safe default dry_run=true enforced in both Ansible defaults and MDM policy profiles -- production enforcement requires explicit opt-in
- All Ansible policy file tasks use become=false -- user-owned config files should never be written as root (T-05-14)
- Policy files use mode 0600 with backup=true -- restricts read access and preserves previous config (T-05-13)
- Intune profiles use com.microsoft.intune.cloneguard.* prefix to avoid PayloadIdentifier conflicts with Jamf profiles

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Test for site.yml host groups initially used yaml.safe_load_all (multi-document) when site.yml is a single YAML document containing a list of plays. Fixed by switching to yaml.safe_load and counting list items.

## User Setup Required

None - no external service configuration required. Fleet artifacts are templates that operators customize for their environment.

## Next Phase Readiness
- Fleet deployment artifacts ship inside the cloneguard package at src/cloneguard/fleet/
- Ansible role is ready for integration testing with actual target hosts
- MDM profiles need organization-specific signing before deployment
- All artifacts are covered by structural validation tests (41 tests, no Ansible/MDM tools required)

## Self-Check: PASSED

- All 14 files verified present on disk
- Both task commits verified in git history (45b6f32, c6353d1)
- 41/41 tests passing

---
*Phase: 05-enterprise-governance*
*Completed: 2026-04-06*
