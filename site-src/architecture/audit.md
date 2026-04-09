# Audit

Every detection event produces a structured NDJSON audit record.

## NDJSON

One JSON line per event, emitted to stderr:

```json
{
  "schema_version": "cloneguard/event/v1",
  "timestamp": "2026-04-07T10:30:00Z",
  "session_id": "a1b2c3",
  "agent_type": "claude-code",
  "event_type": "pre_tool_use",
  "tool_name": "Bash",
  "tool_input_hash": "sha256:abc123...",
  "verdict": "malicious",
  "confidence": 0.94,
  "signals": {
    "tier0_matches": 2,
    "tier15_verdict": "malicious",
    "tier15_confidence": 0.91,
    "tier2_verdict": "",
    "tier2_confidence": 0.0,
    "sequence_rule": ""
  },
  "enforcement_action": "ALLOW",
  "sandbox_adapter": "noop",
  "cloneguard_version": "0.5.0",
  "source_path": ""
}
```

Fields are flat at the top level. The `signals` object contains detection
tier breakdowns (`tier0_matches`, `tier15_verdict`, `tier15_confidence`,
`tier2_verdict`, `tier2_confidence`, `sequence_rule`).

## Agent Identity (SPIFFE)

When SPIFFE is configured, audit events include the agent's SPIFFE identity
(`spiffe://trust-domain/agent/name`), enabling correlation across multi-agent
deployments.

```bash
pip install "cloneguard[spiffe]"
```

See [Enterprise guide](../guides/enterprise.md) for SPIFFE configuration.
