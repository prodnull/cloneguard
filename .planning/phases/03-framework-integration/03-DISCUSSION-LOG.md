# Phase 3: Framework Integration - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-04-06
**Phase:** 03-framework-integration
**Mode:** auto
**Areas discussed:** Input Adapter Architecture, AGT Plugin Interface, MCP Middleware Approach, CI/CD Deployment Strategy, OTel Observability Design

---

## Input Adapter Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Protocol-based InputAdapter with registry | normalize() -> ToolCallEvent, per-agent modules, registry lookup | ✓ |
| Inheritance-based adapter hierarchy | ABC base class with shared parsing logic | |
| Configuration-driven adapter (no code) | YAML mapping of JSON paths to ToolCallEvent fields | |

**User's choice:** [auto] Protocol-based InputAdapter with registry (recommended default -- consistent with Phase 1/2 Protocol pattern)
**Notes:** Follows PEP 544 structural subtyping established in Phase 1 D-04 and Phase 2 D-04. hooks.py JSON parsing extracted into claude_code.py adapter.

---

## AGT Plugin Interface

| Option | Description | Selected |
|--------|-------------|----------|
| In-tree module with optional dependency | src/cloneguard/adapters/agt.py, graceful degradation | ✓ |
| Separate package (cloneguard-agt) | Independent release cycle, separate PyPI package | |
| Contrib directory (community-maintained) | Lower maintenance burden, slower iteration | |

**User's choice:** [auto] In-tree module with optional dependency (recommended default -- follows mcp_plugin.py precedent)
**Notes:** AGT SDK is optional import. Stub classes when SDK unavailable, same pattern as existing mcp_plugin.py.

---

## MCP Middleware Approach

| Option | Description | Selected |
|--------|-------------|----------|
| Refactor to MCP SDK direct usage | Evolve mcp_plugin.py into adapters/mcp.py, use MCP SDK | ✓ |
| Keep mcp-gateway plugin approach | Maintain current mcp_plugin.py architecture | |
| MCP proxy server (separate process) | Standalone MCP proxy that wraps any MCP server | |

**User's choice:** [auto] Refactor to MCP SDK direct usage (recommended default -- aligns with adapter abstraction, addresses STATE.md flag)
**Notes:** STATE.md flagged MCP SDK response interception API needs verification at planning time. Research step should confirm current MCP SDK middleware capabilities.

---

## CI/CD Deployment Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Composite action with SARIF upload | action.yml using uv install + cloneguard scan --sarif | ✓ |
| Docker-based action | Dockerfile with pre-installed cloneguard | |
| Reusable workflow (.github/workflows/) | Workflow template instead of action | |

**User's choice:** [auto] Composite action with SARIF upload (recommended default -- leverages Phase 1 SARIF output, minimal startup latency)
**Notes:** Composite actions avoid Docker pull overhead. uv caching across runs for fast subsequent installations.

---

## OTel Observability Design

| Option | Description | Selected |
|--------|-------------|----------|
| opentelemetry-api optional dependency | GenAI semantic conventions, spans per detection event | ✓ |
| Manual OTel JSON export | No SDK dependency, emit OTel-compatible JSON directly | |
| OTel Collector sidecar integration | Push to local collector, not emit spans from library | |

**User's choice:** [auto] opentelemetry-api optional dependency (recommended default -- standard Python instrumentation approach)
**Notes:** GenAI semantic conventions (draft) for span attributes. Zero overhead when OTel not installed (no-op tracer pattern).

---

## Claude's Discretion

- Internal adapter module organization
- Exact hook JSON parsing for Gemini CLI and Cursor
- AGT/MCP SDK version pinning
- GitHub Actions action.yml input/output schema details
- OTel span naming beyond specified attributes
- Test fixture strategy for multi-platform payloads

## Deferred Ideas

- Browser agent CDP adapter -- Phase 5
- Autonomous agent SDK middleware -- Phase 5
- Financial agent middleware -- Phase 5
- Windsurf and VS Code Copilot adapters -- incremental addition after core 3 adapters
