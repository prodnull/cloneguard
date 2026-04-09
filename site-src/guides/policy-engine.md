# Policy Engine

CloneGuard's behavior is configurable via YAML policy files.

## Configuration File

```yaml
# ~/.cloneguard/policy.yaml
```

CloneGuard reads policy from `~/.cloneguard/policy.yaml`. If absent, defaults
apply (detection-only, no enforcement).

## Basic Configuration

```yaml
# Detection thresholds
detection:
  suspicious_threshold: 0.5
  malicious_threshold: 0.8

# Enforcement
enforcement:
  enabled: false         # true to enable (default: false / dry-run)
  adapter: noop          # noop, landlock, seatbelt, docker, gvisor, firecracker, wasm
  dry_run: true          # log actions without enforcing (default: true)

# Behavioral sequences
sequences:
  SEQ-001:
    mode: enforce        # enforce or advisory
  SEQ-004:
    mode: advisory
```

## Per-Tool Overrides

```yaml
# Different thresholds for different tools
tools:
  Bash:
    suspicious_threshold: 0.4    # lower threshold (more sensitive)
    enforcement:
      adapter: landlock
  Write:
    suspicious_threshold: 0.6    # higher threshold (more permissive)
```

## Severity Mapping

```yaml
# Map verdicts to actions
actions:
  SAFE: allow
  SUSPICIOUS: constrain    # or: allow, log, block
  MALICIOUS: block         # or: allow, log, constrain
```

## Scan Mode Configuration

```yaml
# Override scan mode for specific paths
scan_modes:
  "CLAUDE.md": strict
  "tests/**": lenient
  "*.py": standard
```

## Advanced: OPA/Cedar Backends

For organizations using Open Policy Agent or Cedar for policy management,
CloneGuard can delegate policy decisions to external backends.

See [Enterprise guide](enterprise.md) for OPA and Cedar configuration.
