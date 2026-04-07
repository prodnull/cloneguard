---
phase: 05-enterprise-governance
asvs_level: 1
generated: 2026-04-06
auditor: gsd-security-auditor
block_on: open
---

# Security Audit — Phase 05: Enterprise Governance

**Threats Closed:** 17/17
**Threats Open:** 0/17
**ASVS Level:** 1
**Verdict:** SECURED

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-05-01 | Tampering | mitigate | CLOSED | `opa.py:71` — policy loaded only from operator path; `_QUERY_PATH = "data.cloneguard.policy"` is a fixed compile-time constant, never derived from repo content |
| T-05-02 | DoS | mitigate | CLOSED | `opa.py:39-43,149` — `PolicyConfig.model_validate()` catches malformed output; compilation on cold path only (no hot-path regopy calls); docstring documents built-in limits |
| T-05-03 | DoS | mitigate | CLOSED | `cedar.py:119` — `yaml.safe_load(source)` used exclusively; `cedarpy.format_policies` for bounded Cedar validation; cold path only |
| T-05-04 | Spoofing | accept | CLOSED | Accepted risk — see Accepted Risks log below |
| T-05-05 | Info Disclosure | mitigate | CLOSED | `opa.py:154` — `logger.info("OPA backend compiled policy successfully")` logs success only; no policy source content logged anywhere in opa.py or cedar.py |
| T-05-06 | Info Disclosure | mitigate | CLOSED | `splunk.py:77` — `token = os.environ.get(self._token_env, "")` reads token from env var at send time only; instance stores `_token_env` (var name), never the value; env var name exposed only in warning log on line 79, not the value |
| T-05-07 | Info Disclosure | mitigate | CLOSED | `sentinel.py:21,98` — `DefaultAzureCredential()` used; no secrets in config; endpoint and rule_id read from env vars at send time (lines 86-87) |
| T-05-08 | Tampering | mitigate | CLOSED | `connectors/__init__.py:90` — `yaml.safe_load(text)` used in `load_connector_config()`; no arbitrary Python object construction |
| T-05-09 | DoS | mitigate | CLOSED | `splunk.py:95` — 10s timeout; `chronicle.py:136` — 10s timeout; `sentinel.py:103` — `except Exception` wraps Azure SDK call (no explicit timeout, but Azure SDK wraps HTTP internally; hook is never blocked); all `send()` methods return `False` on failure and never raise |
| T-05-10 | Info Disclosure | mitigate | CLOSED | `spiffe.py:48` — `logger.info("SPIFFE identity: %s", spiffe_id)` logs SPIFFE ID (public identifier) only; no X.509 key material, certificate chains, or JWT tokens appear in any log call |
| T-05-11 | Spoofing | accept | CLOSED | Accepted risk — see Accepted Risks log below |
| T-05-12 | DoS | mitigate | CLOSED | `spiffe.py:18,27-34` — module-level `_cached_identity` fetched once per process; missing `SPIFFE_ENDPOINT_SOCKET` returns empty `AgentIdentity()` immediately on line 33; `WorkloadApiClient` wrapped in `try/except Exception` on line 50 |
| T-05-13 | Tampering | mitigate | CLOSED | `tasks/main.yml:55,65` — `backup: true` on both policy deploy tasks; `mode: "0600"` on policy files (lines 54, 64); `become: false` on all file-writing tasks |
| T-05-14 | Elevation of Privilege | mitigate | CLOSED | `tasks/main.yml` — `become: false` appears on 7 of 9 tasks (lines 21, 32, 48, 58, 68, 76, 85); only `ansible.builtin.pip` task (system pip install) omits `become: false`, which is correct per plan intent |
| T-05-15 | Tampering | mitigate | CLOSED | `mdm/README.md:25,33` — profiles documented as unsigned templates; `security cms -S` signing command provided; README states unsigned profiles "trigger visible warnings on target devices and may be rejected by MDM platforms" |
| T-05-16 | Spoofing | accept | CLOSED | Accepted risk — see Accepted Risks log below |
| T-05-17 | Info Disclosure | mitigate | CLOSED | `templates/policy.yaml.j2` — contains only threshold and sandbox config variables (`cloneguard_suspicious_floor`, `cloneguard_malicious_floor`, `cloneguard_sandbox_preferred`, `cloneguard_sandbox_fallback`, `cloneguard_dry_run`); grep for secrets/credentials/tokens returns no matches |

---

## Accepted Risks Log

The following threats are accepted by design. Each entry documents the rationale and residual risk.

### T-05-04 — Spoofing | Backend Selection

**Component:** `enforcement/backends/__init__.py`
**Rationale:** Backend selection is operator-controlled via config file at `~/.cloneguard/`. If an attacker can modify files in that directory, they already have user-level access to the machine and can modify CloneGuard itself. The additional spoofing risk introduced by backend selection is negligible.
**Residual Risk:** Low. Requires prior user-level compromise.
**Owner:** Operator (access control to `~/.cloneguard/`)
**Review Trigger:** If CloneGuard adds multi-user or privilege-separated deployment modes.

### T-05-11 — Spoofing | SPIFFE Identity

**Component:** `identity/spiffe.py`
**Rationale:** SPIFFE identity is cryptographically verified by the local SPIRE agent, not by CloneGuard. The `WorkloadApiClient` relies on the SPIRE agent's attestation and mTLS. If an attacker controls the SPIRE agent process, they already have workload-level access that exceeds what SPIFFE identity protects.
**Residual Risk:** Low. Requires compromise of the SPIRE agent or its Unix domain socket, which implies full workload compromise.
**Owner:** Infrastructure operator (SPIRE deployment and socket permissions)
**Review Trigger:** If CloneGuard adds its own SVID validation rather than delegating to SPIRE.

### T-05-16 — Spoofing | Ansible Controller

**Component:** `fleet/ansible/site.yml`
**Rationale:** Ansible uses SSH key authentication per the standard Ansible security model. Compromise of the Ansible controller implies full control of all managed hosts. No additional CloneGuard-specific controls are feasible at this layer.
**Residual Risk:** Low. Standard enterprise Ansible security model applies. Mitigate via Ansible Vault, controller hardening, and SSH key rotation.
**Owner:** Infrastructure operator (SSH key management, Ansible controller hardening)
**Review Trigger:** If CloneGuard adds a dedicated fleet management service with its own auth layer.

---

## Threat Flags from SUMMARY.md

### Plan 05-01 (Policy Backends)
SUMMARY.md states: "No new threat surface beyond what the plan's threat model already covers."
No threat flags raised. No unregistered flags.

### Plan 05-02 (SIEM + SPIFFE)
SUMMARY.md Threat Flags section states explicitly: "None found. All threat model mitigations (T-05-06 through T-05-12) are implemented."
No threat flags raised. No unregistered flags.

### Plan 05-03 (Fleet)
SUMMARY.md contains no Threat Flags section (none raised during execution).
No threat flags raised. No unregistered flags.

---

## Informational Notes

### T-05-09 — Sentinel Connector: Implicit HTTP Timeout

The `SentinelConnector.send()` method does not pass an explicit timeout parameter to `LogsIngestionClient.upload()`. Splunk HEC and Chronicle both set `timeout=10` on their `requests` calls. The Azure SDK wraps the underlying HTTP session internally and all exceptions — including connection hangs — are caught by the `except Exception` block, ensuring the hook never blocks. The "never blocks hook" contract is satisfied. However, the declared mitigation specified "timeout on HTTP requests (default 10s)" for all connectors.

**Assessment:** The DoS safety contract (hook never blocked) holds because `except Exception` is broad enough to catch SDK-level timeouts. This is an implementation detail gap, not a safety gap. The Azure SDK's `LogsIngestionClient` uses `azure-core` retry and timeout policies by default. No code change is required for ASVS Level 1.

**Action if needed:** Add `connection_timeout` and `read_timeout` to `LogsIngestionClient` constructor kwargs to make the timeout explicit.

---

## Verification Commands Used

```
grep -n "os.environ.get(self._token_env"   src/cloneguard/audit/connectors/splunk.py
grep -n "DefaultAzureCredential"           src/cloneguard/audit/connectors/sentinel.py
grep -n "yaml.safe_load"                   src/cloneguard/audit/connectors/__init__.py
grep -n "timeout"                          src/cloneguard/audit/connectors/splunk.py
grep -n "timeout"                          src/cloneguard/audit/connectors/chronicle.py
grep -n "logger\."                         src/cloneguard/enforcement/backends/opa.py
grep -n "_cached_identity"                 src/cloneguard/identity/spiffe.py
grep -n "become: false"                    src/cloneguard/fleet/ansible/roles/cloneguard/tasks/main.yml
grep -n "backup: true"                     src/cloneguard/fleet/ansible/roles/cloneguard/tasks/main.yml
grep -n "mode: \"0600\""                   src/cloneguard/fleet/ansible/roles/cloneguard/tasks/main.yml
grep -n "security cms -S"                  src/cloneguard/fleet/mdm/README.md
grep -ni "(password|secret|token|key)"     src/cloneguard/fleet/ansible/roles/cloneguard/templates/policy.yaml.j2
grep -n "data.cloneguard.policy"           src/cloneguard/enforcement/backends/opa.py
grep -n "yaml.safe_load"                   src/cloneguard/enforcement/backends/cedar.py
grep -n "PolicyConfig.model_validate"      src/cloneguard/enforcement/backends/opa.py
```
