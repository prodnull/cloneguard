# Enforcement

CloneGuard defaults to detection-only mode. When enforcement is enabled, tool
calls receive one of three verdicts.

## Three-Verdict Model

| Verdict | Meaning | Default Action |
|---------|---------|----------------|
| SAFE | No signals fired or below threshold | Allow |
| SUSPICIOUS | Low-to-medium confidence detection | Constrain via sandbox |
| MALICIOUS | High-confidence detection | Block |

Confidence thresholds are operator-configurable via the
[policy engine](../guides/policy-engine.md).

## Sandbox Adapters

When a SUSPICIOUS verdict triggers constraint, CloneGuard restricts the tool
call subprocess using OS-level sandboxing. The CloneGuard process itself is
never affected.

| Adapter | Platform | Mechanism |
|---------|----------|-----------|
| NoopAdapter | Any | Detection only, no enforcement (default) |
| LandlockAdapter | Linux 5.13+ | Filesystem and network restrictions via Landlock LSM |
| SeatbeltAdapter | macOS | App Sandbox profiles via `sandbox-exec` |
| DockerAdapter | Any (Docker required) | Container isolation with configurable mounts |
| GVisorAdapter | Linux | User-space kernel via `runsc` |
| FirecrackerAdapter | Linux (KVM) | MicroVM isolation |
| WasmAdapter | Any (wasmtime required) | WebAssembly sandbox with capability-based security |

All adapters conform to the `SandboxAdapter` Protocol:

```python
class SandboxAdapter(Protocol):
    @property
    def name(self) -> str: ...
    def restrict_filesystem(self, writable: list[str], readable: list[str],
                            executable_writable: list[str] | None = None) -> None: ...
    def restrict_network(self, allow: list[str]) -> None: ...
    def apply_restrictions(self) -> None: ...
    def snapshot(self) -> Any: ...
    def rollback(self, snapshot: Any) -> None: ...
    def restrict_syscalls(self, allowed: list[str]) -> None: ...
    def get_audit_log(self) -> list[dict[str, Any]]: ...
```

Adapters are ordered by defense strength (D-08 ordering). The adapter registry
selects the strongest available adapter for the platform, or a specific adapter
can be configured via policy.

## Dry-Run Default

All new installations default to dry-run mode. Enforcement must be explicitly
enabled:

```yaml
# ~/.cloneguard/policy.yaml
enforcement:
  enabled: true
  adapter: landlock  # or seatbelt, docker, gvisor, firecracker, wasm
```

In dry-run mode, CloneGuard logs what actions would be taken without enforcing
them, so you can verify behavior before enabling enforcement.

## Snapshot and Rollback

Landlock and Seatbelt adapters support snapshot/rollback -- if a sandboxed tool
call fails, the sandbox state can be rolled back to pre-execution state.
