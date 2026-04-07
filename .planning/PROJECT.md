# CloneGuard v2: Universal Agentic Defense

## What This Is

CloneGuard evolves from a coding-agent prompt injection scanner into a universal agentic defense layer — the independent trust boundary between any AI agent and any execution environment. It detects, constrains, and audits tool calls across agent platforms from a position the agent itself cannot compromise.

## Core Value

The only vendor-neutral, sandbox-agnostic defense layer that fuses pattern + semantic + behavioral signals to detect prompt injection, then enforces adaptive constraints — not just allow/block but allow-but-constrain — across any agent type.

## Requirements

### Validated

- ✓ **204 regex patterns** across 25 YAML rule files — existing
- ✓ **MiniLM ONNX semantic classifier** (Tier 1.5) — existing
- ✓ **Ollama fallback classifier** (Tier 2) — existing
- ✓ **4 defense layers** (L0 wrapper, L1 InstructionsLoaded, L2 PostToolUse, L3 PreToolUse) — existing
- ✓ **6 SEQ behavioral rules** (3 enforce, 3 advisory) — existing
- ✓ **Claude Code hook integration** (JSON stdin/stdout, exit 0/2) — existing
- ✓ **Session trust caching** and TOCTOU-safe design — existing
- ✓ **Allowlist system** with content-hash verification — existing
- ✓ **1,321 tests passing**, eval harness (20/20, 0 FP) — existing
- ✓ **Trajectory dataset** (208,127 trajectories, 8.3M actions) — existing

### Active

- [ ] Structured event schema (NDJSON) and SARIF 2.1.0 emitter
- [ ] Detection engine extracted from hooks.py into standalone module
- [ ] Sandbox adapter interface with NoopAdapter, LandlockAdapter, SeatbeltAdapter
- [ ] Three-verdict model (SAFE / SUSPICIOUS / MALICIOUS)
- [ ] Policy engine with YAML configuration
- [ ] Input adapter abstraction (decouple from Claude Code hook protocol)
- [ ] Three-signal fusion layer calibrated on trajectory dataset
- [ ] Package hallucination detection (npm/pip cross-reference)
- [ ] MELON selective re-execution (SEQ-006)
- [ ] Microsoft AGT ToolCallInterceptor plugin
- [ ] MCP protocol middleware adapter
- [ ] CI/CD runner deployment (GitHub Actions)
- [ ] OTel span emission
- [ ] OPA/Rego and Cedar policy backends
- ✓ Browser, autonomous, financial, CI/CD agent pattern libraries (32 patterns, Phase 6)
- ✓ Additional sandbox adapters: Docker, gVisor, Firecracker, WASM with auto-selection (Phase 6)

### Out of Scope

- Building a governance framework — CloneGuard is a sensor that feeds governance, not governance itself
- Building a sandbox — CloneGuard orchestrates existing sandboxes via adapters
- Custom ML classifier training — MiniLM is commodity; value is in fusion + calibration
- Mobile/desktop GUI — CLI and library integration only
- SaaS deployment — on-device, no phone-home

## Context

- **Existing codebase**: Python 3.11+, PyYAML, ONNX Runtime, hatchling build
- **Current state**: v0.5.0 with detection-only (allow/block). No enforcement layer.
- **Competitive landscape**: $2.1B+ in acquisitions absorbed first-wave PI defense startups. Remaining independents pivoting to agentic AI security. None operate at hook/tool-call boundary.
- **Standards tailwinds**: EU AI Act Article 12 enforceable 2026-08-02, OWASP Agentic Top 10, MITRE ATLAS v5.4.0, NIST CAISI
- **Research assets**: 208K trajectory dataset, adaptive red team methodology, honest adversarial evaluation (16.7% bypass rate reported)
- **IP status**: Apache 2.0 license. CLA, trademark, provisional patent pending (~$5,500 total)

## Constraints

- **Tech stack**: Python 3.11+, ONNX Runtime for inference, no external service dependencies for core detection
- **Performance**: <20ms per hook invocation for Tier 0+1.5, <370ms full repo scan
- **Backward compatibility**: NoopAdapter must preserve current v0.5.0 exit-code behavior exactly
- **Security**: Layer 0 runs BEFORE agent — position must remain uncompromisable by repo content
- **Packaging**: Must support `uv tool install` / `pipx` standalone binary
- **Open-core split**: Core detection + basic adapters open source; enterprise features (fleet mgmt, compliance exports, SIEM integrations) proprietary

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) | Binary allow/block is too coarse for production use | -- Pending |
| Sandbox-agnostic adapter interface | Don't build a sandbox; orchestrate any sandbox | -- Pending |
| Format-agnostic policy engine (YAML/OPA/Cedar) | Meet enterprises where they are | -- Pending |
| MELON selective triggering (0.4-0.6 confidence zone) | Full re-execution overhead is prohibitive; selective limits to ~5-10% of calls | -- Pending |
| Simultaneous SARIF + OTel + NDJSON output | Different consumers need different formats; emit all three | -- Pending |
| Agent-type-agnostic core with per-type pattern libraries | Core engine shouldn't know about agent types; patterns are configuration | -- Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? -> Move to Out of Scope with reason
2. Requirements validated? -> Move to Validated with phase reference
3. New requirements emerged? -> Add to Active
4. Decisions to log? -> Add to Key Decisions
5. "What This Is" still accurate? -> Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check -- still the right priority?
3. Audit Out of Scope -- reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-07 after Phase 6 completion (all 6 phases complete)*
