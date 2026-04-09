# Sandbox Adapters

When enforcement is enabled, CloneGuard can constrain SUSPICIOUS tool calls
using OS-level sandboxing.

## Available Adapters

### NoopAdapter (default)

Detection only. No enforcement. This is the default for all installations.

### LandlockAdapter (Linux)

Uses Linux Landlock LSM (kernel 5.13+) to restrict filesystem and network
access for the tool call subprocess.

```yaml
enforcement:
  adapter: landlock
  landlock:
    allowed_read: ["/usr", "/lib", "/etc"]
    allowed_write: ["/tmp"]
    network: deny
```

No special permissions required -- Landlock is unprivileged.

### SeatbeltAdapter (macOS)

Uses macOS App Sandbox via `sandbox-exec` to restrict the tool call subprocess.

```yaml
enforcement:
  adapter: seatbelt
  seatbelt:
    profile: strict    # strict, moderate, or custom path
```

### DockerAdapter

Runs the tool call in an isolated container.

```bash
pip install "cloneguard[docker]"
```

```yaml
enforcement:
  adapter: docker
  docker:
    image: "python:3.12-slim"
    network: none
    read_only: true
    mounts:
      - source: /path/to/repo
        target: /workspace
        read_only: true
```

### GVisorAdapter (Linux)

Uses gVisor's `runsc` runtime for user-space kernel isolation. Stronger
isolation than Landlock but requires gVisor installation.

```yaml
enforcement:
  adapter: gvisor
```

Requires `runsc` on PATH.

### FirecrackerAdapter (Linux)

MicroVM isolation via Firecracker. Strongest isolation, requires KVM.

```yaml
enforcement:
  adapter: firecracker
```

Requires `/dev/kvm` access and Firecracker binary.

### WasmAdapter

WebAssembly sandbox with capability-based security via wasmtime.

```bash
pip install "cloneguard[wasm]"
```

```yaml
enforcement:
  adapter: wasm
  wasm:
    fuel_limit: 1000000    # execution budget
```

## Adapter Selection

By default, CloneGuard selects the strongest available adapter for the platform.
Override with the `adapter` field in policy configuration.

Strength ordering (strongest to weakest):

1. Firecracker (MicroVM)
2. gVisor (user-space kernel)
3. Docker (container)
4. WASM (WebAssembly)
5. Landlock (Linux LSM)
6. Seatbelt (macOS sandbox)
7. Noop (no enforcement)
