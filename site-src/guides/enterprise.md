# Enterprise Features

!!! warning "Experimental"
    Enterprise features are early-stage and should be considered experimental.
    APIs and configuration formats may change.

## Policy Backends

### OPA/Rego

Delegate policy decisions to Open Policy Agent using Rego policies.

```bash
pip install "cloneguard[opa]"
```

```yaml
policy_backend: opa
opa:
  policy_path: /path/to/cloneguard.rego
```

### Cedar

Use AWS Cedar for fine-grained, RBAC-style policy decisions.

```bash
pip install "cloneguard[cedar]"
```

```yaml
policy_backend: cedar
cedar:
  policy_path: /path/to/cloneguard.cedar
  entities_path: /path/to/entities.json
```

## SIEM Connectors

Forward audit events to your security information and event management platform.

### Splunk HEC

```bash
pip install "cloneguard[splunk]"
```

```yaml
siem:
  backend: splunk
  splunk:
    hec_url: "https://splunk.example.com:8088"
    token_env: "SPLUNK_HEC_TOKEN"
    index: "ai_security"
    source_type: "cloneguard"
```

### Microsoft Sentinel

```bash
pip install "cloneguard[sentinel]"
```

```yaml
siem:
  backend: sentinel
  sentinel:
    dcr_endpoint: "https://dcr.monitor.azure.com"
    dcr_id: "dcr-..."
    stream_name: "Custom-CloneGuard_CL"
```

### Google Chronicle

```bash
pip install "cloneguard[chronicle]"
```

```yaml
siem:
  backend: chronicle
  chronicle:
    region: "us"
    customer_id: "..."
    log_type: "CLONEGUARD"
```

## Agent Identity (SPIFFE)

Inject verified agent identity into audit events for multi-agent correlation.

```bash
pip install "cloneguard[spiffe]"
```

```yaml
identity:
  backend: spiffe
  spiffe:
    workload_api_addr: "unix:///tmp/spire-agent/public/api.sock"
```

Audit events will include the agent's SPIFFE ID
(`spiffe://trust-domain/agent/name`).

## Fleet Deployment

### Ansible

An Ansible role is included for deploying CloneGuard across a fleet of
developer workstations.

### MDM (macOS)

Configuration profiles are available for Jamf Pro and Microsoft Intune to
deploy CloneGuard policy via MDM on macOS.
