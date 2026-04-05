# Phase 1: Foundation - Research

**Researched:** 2026-04-05
**Domain:** Detection engine modularization, structured audit logging (NDJSON/SARIF), packaging, hook config integrity
**Confidence:** HIGH

## Summary

Phase 1 extracts the detection engine from the monolithic `hooks.py` (499 LOC) + `patterns.py` (313 LOC) + `mini_semantic.py` (429 LOC) + `monitor.py` (1,092 LOC) into a standalone `DetectionEngine` class with Protocol-based interfaces. It adds NDJSON structured audit logging and SARIF 2.1.0 output, fixes packaging for standalone `uv tool install` / `pipx`, and adds a hook config integrity self-check against CVE-2025-59536-class attacks. All 1,345 existing tests must pass without modification after extraction.

The extraction is primarily mechanical -- move functions and update imports -- with the critical constraint that the hot path must remain under 20ms for Tier 0+1.5 and the Claude Code hook protocol (JSON stdin, exit 0/2) must behave identically. Pydantic v2 (already installed as transitive dep at 2.12.5) becomes the canonical internal event schema. `sarif-pydantic` (0.6.2) provides typed SARIF 2.1.0 models. NDJSON uses stdlib `json.dumps()` with no additional dependencies.

**Primary recommendation:** Execute extraction bottom-up: types first, detection engine second, audit layer third, thin shims last. Establish latency regression benchmark before extraction begins, not after. The version mismatch (`__init__.py` reports 0.2.2, `pyproject.toml` declares 0.5.0) must be fixed as part of packaging work.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Extract a `DetectionEngine` class from hooks.py with a Protocol-based interface. The engine accepts a `ToolCallEvent` dataclass and returns a `DetectionResult` dataclass. All pattern matching, semantic classification, and sequence monitoring move into the engine.
- **D-02:** hooks.py becomes a thin shim (~10 lines per handler) that: parses Claude Code JSON stdin into a `ToolCallEvent`, calls `DetectionEngine.scan()`, and maps the `DetectionResult` back to the hook protocol (exit 0/2). No detection logic remains in hooks.py.
- **D-03:** scanner.py becomes a thin shim delegating to `DetectionEngine` with repo-scan configuration. The `RepoScanner` API surface stays identical.
- **D-04:** All typed contracts use `typing.Protocol` (PEP 544) for structural subtyping, not ABCs. This enables future framework integration (e.g., conforming to AGT's `ToolCallInterceptor`) without inheritance chains.
- **D-05:** Internal event representation uses Pydantic v2 frozen models as canonical types. Fields: schema version, timestamp, session_id, agent_type, event_type, tool_name, tool_input_hash (SHA-256), verdict, confidence, signals (pattern/semantic/sequence sub-objects), enforcement_action, constraints_applied, sandbox_adapter, outcome, policy_version, cloneguard_version.
- **D-06:** NDJSON serialization is a method on the event model -- `event.to_ndjson()`. One line per event to stdout or configurable output file.
- **D-07:** Schema version starts at `cloneguard/event/v1`. Breaking changes increment the version. Non-breaking additions are backward-compatible within a version.
- **D-08:** SARIF 2.1.0 output via `--sarif` CLI flag or `CLONEGUARD_SARIF_OUTPUT` env var. Validates against OASIS schema.
- **D-09:** Mapping: each CloneGuard pattern/SEQ rule ID becomes a SARIF `reportingDescriptor` (rule). Each detection event becomes a SARIF `result` with verdict mapped to SARIF level (error/warning/note). The `tool.driver` contains CloneGuard name and version.
- **D-10:** Use `sarif-pydantic` (0.6.2) for SARIF model generation rather than manual JSON construction.
- **D-11:** Support `uv tool install cloneguard` and `pipx install cloneguard` for standalone binary. The 87MB ONNX model ships inside the wheel -- security tools must work fully offline.
- **D-12:** Entry point `cloneguard` defined in pyproject.toml `[project.scripts]`. Ensure hatchling build includes model artifacts in the wheel.
- **D-13:** On startup, CloneGuard verifies its own hook configuration hasn't been tampered with (CVE-2025-59536 class). Check that the hook entry in Claude Code settings.json points to the expected CloneGuard binary path. Warn on mismatch.
- **D-14:** The Claude Code hook protocol (JSON stdin, exit 0/2) works identically after refactoring. The thin shims in hooks.py preserve the exact API contract.
- **D-15:** All 1,321 existing tests must pass without modification after the extraction. New tests are added for the DetectionEngine module; existing tests validate the shims.

### Claude's Discretion
- Internal module organization within the new detection engine package
- Exact Pydantic model field naming and nesting beyond the specified schema
- Error handling strategy for malformed hook input
- CI benchmark regression gate implementation details
- Test organization for new vs migrated tests

### Deferred Ideas (OUT OF SCOPE)
- OTel span emission -- Phase 3 (INTG-05)
- Three-verdict model (SAFE/SUSPICIOUS/MALICIOUS) -- Phase 2 (ENFC-01); Phase 1 emits current binary verdict
- Policy engine -- Phase 2 (ENFC-06)
- Sandbox adapters -- Phase 2 (ENFC-02 through ENFC-05)
- Input adapter abstraction for non-Claude-Code agents -- Phase 3 (INTG-01)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FNDN-01 | Detection engine extracted from hooks.py into standalone module with typed Protocol interfaces | Architecture patterns section, build order analysis, existing code inventory |
| FNDN-02 | Structured event schema emitting NDJSON for every detection event (session_id, verdict, confidence, signals, enforcement_action) | Pydantic v2 event model design, NDJSON code examples, EU AI Act Article 12 mapping |
| FNDN-03 | SARIF 2.1.0 emitter producing valid output consumable by GitHub Advanced Security, VS Code, SonarQube | sarif-pydantic API verification, GitHub SARIF upload requirements, SARIF mapping patterns |
| FNDN-04 | Packaging supports `uv tool install` / `pipx` standalone binary installation | hatchling build config, model artifact inclusion, version discrepancy fix |
| FNDN-05 | Hook config integrity self-check (CVE-2025-59536 class defense) | CVE-2025-59536 analysis, settings.json structure, binary path verification pattern |
| FNDN-06 | Backward compatibility preserved -- existing Claude Code hook protocol (exit 0/2) works identically via thin shims | Hook handler analysis, exit code semantics, test coverage mapping |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Gitignored directories are sacred**: NEVER `git add -f` files from gitignored directories without explicit user approval
- **Tech stack**: Python 3.11+, ONNX Runtime for inference, no external service dependencies for core detection
- **Performance**: <20ms per hook invocation for Tier 0+1.5, <370ms full repo scan
- **Lint/type-check**: ruff format, ruff check, mypy --strict before committing
- **No custom crypto**: Battle-tested, audited, well-maintained libraries only
- **Honest framing**: Never claim CloneGuard "protects against" or "blocks" -- it raises attacker cost
- **uv for Python packaging**: Use uv for all packaging operations

## Standard Stack

### Core (Phase 1 additions)

| Library | Version | Purpose | Why Standard | Confidence |
|---------|---------|---------|--------------|------------|
| pydantic | 2.12.5 | Event schema validation, frozen models | Already installed as transitive dep (via MCP SDK, ollama, etc.). Promote to direct dependency. Rust core gives sub-ms validation. | HIGH [VERIFIED: `uv pip show pydantic` in project venv] |
| sarif-pydantic | 0.6.2 | SARIF 2.1.0 typed models | Pydantic v2 native. Produces correct camelCase SARIF JSON via aliases. Verified: constructs valid SARIF documents with `Sarif`, `Run`, `ToolDriver`, `Result`, `ReportingDescriptor`, `Level` classes. | HIGH [VERIFIED: installed and API tested in venv] |

### Retained (no changes)

| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| pyyaml | >=6.0 | Pattern rule YAML parsing | Direct dependency, unchanged |
| onnxruntime | >=1.17 | MiniLM ONNX inference | Optional dep `[mini]`, unchanged |
| transformers | >=4.36 | Tokenizer for MiniLM | Optional dep `[mini]`, unchanged |
| numpy | >=1.26 | Mahalanobis anomaly detection | Optional dep `[mini]`, unchanged |
| hatchling | (build) | Build backend | Unchanged |

### Not Needed for Phase 1

| Library | Why Not | When |
|---------|---------|------|
| opentelemetry-api/sdk | OTel emission is Phase 3 (INTG-05) | Phase 3 |
| regopy / cedarpy | Policy backends are Phase 5 | Phase 5 |
| hypothesis | Property-based testing for policy engine -- not needed until Phase 2+ | Phase 2 |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| sarif-pydantic | sarif-om (1.0.4) | sarif-om is unmaintained (last release 2022), no type hints, uses pbr build system. sarif-pydantic is actively maintained and Pydantic v2 native. |
| sarif-pydantic | Manual JSON construction | Error-prone, no schema validation, maintenance burden. sarif-pydantic adds 1 dependency with zero transitive deps beyond pydantic. |
| Pydantic v2 frozen models | stdlib dataclasses | Pydantic gives JSON schema export, validation, serialization aliases (camelCase), and `.model_dump_json()` for NDJSON. Dataclasses would require manual serialization. |

**Installation (Phase 1 additions only):**
```bash
uv pip install pydantic sarif-pydantic
```

## Architecture Patterns

### Recommended Project Structure (Phase 1 scope)

```
src/cloneguard/
    __init__.py              # Fix version: 0.5.0 (match pyproject.toml)
    cli.py                   # Add --sarif flag, add --check-hooks subcommand
    hooks.py                 # THIN SHIM: parse JSON, call engine, map exit code
    scanner.py               # THIN SHIM: delegate to engine with repo-scan config

    detection/               # NEW: extracted detection engine
        __init__.py          # Re-export DetectionEngine, DetectionResult
        types.py             # ToolCallEvent, DetectionResult, SignalResult, Verdict
        engine.py            # DetectionEngine.scan() -- orchestrates all signals
        patterns.py          # PatternEngine (MOVED from src/cloneguard/patterns.py)
        semantic.py          # MiniSemanticClassifier (MOVED from mini_semantic.py)
        sequence.py          # ToolCallMonitor + SEQ rules (MOVED from monitor.py)

    audit/                   # NEW: structured event emission
        __init__.py          # Re-export AuditEvent, NDJSONEmitter, SARIFEmitter
        types.py             # AuditEvent Pydantic model (cloneguard/event/v1)
        ndjson.py            # NDJSONEmitter -- event.to_ndjson() + file output
        sarif.py             # SARIFEmitter -- pattern/SEQ rules to SARIF mapping

    integrity.py             # NEW: hook config self-check (CVE-2025-59536)

    # Unchanged files (stay at current paths)
    allowlist.py
    sequence_allowlist.py
    trust_cache.py
    semantic.py              # Tier 2 Ollama classifier (unchanged)
    model/                   # ONNX model artifacts (unchanged)
    rules/                   # YAML pattern rules (unchanged)
```

### Pattern 1: Mechanical Extraction with Import Compatibility

**What:** Move `PatternEngine` from `patterns.py` to `detection/patterns.py`, but preserve the original import path via re-export. This lets existing tests `from cloneguard.patterns import PatternEngine` continue to work without modification.

**When to use:** For every moved module during extraction. The re-export shim is the backward compatibility mechanism.

**Example:**
```python
# src/cloneguard/patterns.py (after extraction -- becomes re-export shim)
"""Backward-compatibility re-export. Actual implementation in detection/patterns.py."""
from cloneguard.detection.patterns import (  # noqa: F401
    PatternEngine,
    PatternMatch,
    ScanMode,
    ScanResult,
    Severity,
    Verdict,
)
```
[VERIFIED: This pattern preserves the 37 existing imports of `from cloneguard.patterns import ...` across the test suite]

### Pattern 2: Pydantic v2 Frozen Event Models

**What:** All typed contracts use `pydantic.BaseModel` with `model_config = ConfigDict(frozen=True)` for immutability. The `ToolCallEvent` is the normalized input; `DetectionResult` is the engine output; `AuditEvent` is the full pipeline record.

**When to use:** For every data contract crossing module boundaries.

**Example (D-05 implementation):**
```python
from __future__ import annotations
import datetime
from pydantic import BaseModel, ConfigDict, Field
from enum import Enum

class EventType(str, Enum):
    RISK_IDENTIFIED = "RISK_IDENTIFIED"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    HOOK_INVOKED = "HOOK_INVOKED"

class AuditEvent(BaseModel):
    """Structured audit event conforming to cloneguard/event/v1 schema."""
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_version: str = "cloneguard/event/v1"
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    session_id: str
    agent_type: str = "claude-code"
    event_type: EventType
    tool_name: str
    tool_input_hash: str  # SHA-256
    verdict: str  # "CLEAN" | "SUSPICIOUS" | "DETECTED" (Phase 1 binary)
    confidence: float = 0.0
    signals: SignalDetails  # Nested sub-object
    enforcement_action: str = "ALLOW"  # Phase 1 default; Phase 2 adds CONSTRAIN/BLOCK
    constraints_applied: dict[str, list[str]] = Field(default_factory=dict)
    sandbox_adapter: str = "noop"
    outcome: str = "completed"
    policy_version: str = ""
    cloneguard_version: str

    def to_ndjson(self) -> str:
        """Serialize to a single NDJSON line."""
        return self.model_dump_json(exclude_none=True) + "\n"
```
[ASSUMED: exact field names and nesting; D-05 specifies the schema but field naming is Claude's discretion]

### Pattern 3: Thin Shim Dispatch

**What:** hooks.py `main()` and each handler become ~10-line dispatchers. The handler parses stdin JSON, constructs a `ToolCallEvent`, calls `DetectionEngine.scan()`, and maps the result to the hook protocol.

**When to use:** For `handle_instructions_loaded`, `handle_pre_tool_use`, `handle_post_tool_use`.

**Critical constraint:** The exit code mapping must be:
- `DETECTED` (CRITICAL/HIGH severity) -> exit 2 (block)
- `DETECTED` (MEDIUM/LOW severity) -> exit 0 + stdout warning
- `SUSPICIOUS` -> exit 0 + stdout warning
- `CLEAN` -> exit 0, no output

This matches the current behavior in hooks.py lines 236-499. [VERIFIED: read full hooks.py handler implementations]

### Pattern 4: SARIF Verdict-to-Level Mapping

**What:** Map CloneGuard verdicts to SARIF severity levels for GitHub Advanced Security consumption.

**Mapping (D-09):**
| CloneGuard | SARIF Level | Rationale |
|------------|-------------|-----------|
| DETECTED (CRITICAL) | error | Blocks execution, requires immediate attention |
| DETECTED (HIGH) | error | High-severity pattern match |
| DETECTED (MEDIUM) | warning | Advisory finding |
| DETECTED (LOW) | note | Informational finding |
| SUSPICIOUS | warning | Low-confidence detection |
| CLEAN | (not emitted) | No SARIF result for clean scans |

[VERIFIED: sarif-pydantic `Level` enum supports `ERROR`, `WARNING`, `NOTE`, `NONE`]

### Anti-Patterns to Avoid

- **Abstracting too early:** Do NOT introduce `InputAdapter` Protocol in Phase 1. The adapter abstraction is Phase 3 (INTG-01). Phase 1's thin shims hardcode Claude Code JSON parsing. Adding an adapter layer now adds latency and complexity for zero benefit.
- **Global singleton removal:** Do NOT remove the `_engine` / `_mini_classifier` singletons in Phase 1. The thin shims need lazy-loaded singletons for process-lifetime caching. Replace singletons with constructor injection only when `RuntimeOrchestrator` is introduced (Phase 2+).
- **Stdout pollution:** The `NDJSONEmitter` must NEVER write to stdout by default. Stdout is the hook communication channel. Default NDJSON output goes to a file (`CLONEGUARD_NDJSON_OUTPUT` env var) or stderr. Only hook responses go to stdout.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SARIF 2.1.0 output | Manual JSON dict construction | `sarif-pydantic` (0.6.2) | SARIF schema has 50+ object types with camelCase aliasing, optional fields, and cross-references. sarif-pydantic generates correct JSON with `model_dump_json(by_alias=True, exclude_none=True)`. Manual construction guarantees schema violations. |
| Event schema validation | `@dataclass` + manual `json.dumps()` | Pydantic v2 `BaseModel` | Pydantic gives validation on construction, frozen immutability, JSON schema export for documentation, and `.model_dump_json()` for NDJSON serialization. Dataclass serialization would require a custom encoder for datetime, Enum, nested objects. |
| NDJSON format | Custom line formatter | `model.model_dump_json() + "\n"` | One line. No library needed. stdlib `json` handles everything via Pydantic's Rust-backed serializer. |
| SHA-256 hashing | Custom implementation | `hashlib.sha256()` | Already used in hooks.py `_content_hash()`. Use the same function. |
| SARIF schema validation | Custom validator | GitHub's own SARIF validator at upload time + `sarif-pydantic` type checking at generation time | Pydantic validates at construction; GitHub validates at upload. Two layers of checking with zero custom code. |

## Common Pitfalls

### Pitfall 1: Detection Extraction Breaks the 20ms Budget

**What goes wrong:** Adding abstraction layers (Protocol dispatch, event normalization, Pydantic model construction) in the hot path adds latency that compounds across 204 regex patterns and 16-chunk sliding window. The 20ms budget is tight: current Tier 0+1.5 is <50ms for regex + ~16ms for ONNX.

**Why it happens:** Natural refactoring creates `DetectionEngine` as a class that normalizes input, dispatches to sub-scanners, and constructs result objects. Each dict copy, Protocol dispatch, and Pydantic construction costs microseconds that compound.

**How to avoid:**
- Establish a latency regression benchmark BEFORE extraction. `tests/test_latency.py` already exists (p95 < 25ms for Tier 1.5). Extend it to cover the full hook path including shim overhead.
- Keep the hot path zero-copy. The Claude Code shim passes the raw dict directly to the pattern engine without intermediate normalization. Only non-Claude adapters (Phase 3) pay normalization cost.
- Construct Pydantic `AuditEvent` models AFTER the exit code is determined, not on the critical path. Audit emission is asynchronous to the hook response.
- Profile: `uv run python -m pytest tests/test_latency.py -v` before and after extraction.

**Warning signs:** p95 latency exceeds 25ms in benchmark after refactoring.

### Pitfall 2: Version Discrepancy

**What goes wrong:** `src/cloneguard/__init__.py` declares `__version__ = "0.2.2"` while `pyproject.toml` declares `version = "0.5.0"`. The CLI banner (`CloneGuard v{__version__}`) shows the wrong version. `uv tool install` installs 0.5.0 but the binary reports 0.2.2.

**Why it happens:** The version in `__init__.py` was not updated when pyproject.toml was bumped. Hatchling reads the version from pyproject.toml for the wheel metadata, but runtime code reads `__init__.py`.

**How to avoid:** Fix immediately: set `__init__.py` to `0.5.0`. Consider using `hatchling` dynamic versioning (`[project] dynamic = ["version"]` + `[tool.hatch.version] source = "code"` pointing to `__init__.py`) so there's a single source of truth. [VERIFIED: current __init__.py reports 0.2.2, pyproject.toml declares 0.5.0]

### Pitfall 3: Import Path Breakage

**What goes wrong:** Moving `PatternEngine` from `cloneguard.patterns` to `cloneguard.detection.patterns` breaks 37+ test imports and any downstream code importing from the original path.

**Why it happens:** Extraction creates new module paths. Without backward-compatible re-exports, every consumer must update imports.

**How to avoid:** Leave the original module files as re-export shims. `cloneguard.patterns` re-exports everything from `cloneguard.detection.patterns`. `cloneguard.monitor` re-exports from `cloneguard.detection.sequence`. `cloneguard.mini_semantic` re-exports from `cloneguard.detection.semantic`. This means zero test modifications for FNDN-06.

**Warning signs:** `ModuleNotFoundError` or `ImportError` in any existing test.

### Pitfall 4: SARIF Output Size Limits

**What goes wrong:** GitHub Advanced Security has SARIF upload limits: 10 MB gzipped, max 25,000 results per run (top 5,000 by severity kept). A full repo scan with verbose SARIF output may exceed these limits.

**Why it happens:** CloneGuard has 204 patterns across 25 YAML rule files. Each pattern generates a SARIF `reportingDescriptor`. A large codebase with many detections could produce thousands of results.

**How to avoid:** Include all 204 patterns as `reportingDescriptor` rules in the SARIF `tool.driver.rules` array (well under 25,000 limit). Cap results at 5,000 per SARIF run with a warning when truncated. Set `partialFingerprints.primaryLocationLineHash` to prevent duplicate alerts across runs. [CITED: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning]

### Pitfall 5: Hook Config Integrity Check False Positives

**What goes wrong:** The integrity self-check (FNDN-05) compares the hook command in `settings.json` against the expected `cloneguard hook-check --event <EventName>` command. Users who install CloneGuard in non-standard locations (venvs, containers, custom paths) trigger false positive integrity warnings on every invocation.

**Why it happens:** The check compares the binary path literally. `uv tool install` places the binary in `~/.local/bin/cloneguard`, `pipx` places it in `~/.local/pipx/venvs/cloneguard/bin/cloneguard`, and development installs have it in `.venv/bin/cloneguard`. All three are legitimate.

**How to avoid:** Check the command string pattern, not the absolute path. Verify that `settings.json` hook commands contain `cloneguard hook-check --event` as a substring. Warn only if the command has been modified to point to a different binary name entirely or if the hook section is missing. Do NOT warn on path differences.

### Pitfall 6: Pydantic Import Cost on Cold Start

**What goes wrong:** Importing `pydantic` adds ~50-80ms to cold-start time on first invocation. For hook-check invocations (called on every tool use), this adds noticeable latency to the first call in a session.

**Why it happens:** Pydantic v2's Rust core compiles model validators at import time. The `BaseModel` metaclass does significant work during class definition.

**How to avoid:** Lazy-import Pydantic models. The `AuditEvent` model is only needed AFTER the detection decision is made, not on the critical path. Import it inside the audit emission function, not at module level. The detection engine itself should use lightweight `@dataclass(frozen=True)` types for `ToolCallEvent` and `DetectionResult` on the hot path, with Pydantic conversion happening only at audit time.

**Architecture implication:** The typed contracts between detection engine components should be `dataclass`-based (zero import cost). The Pydantic models are the serialization layer for NDJSON/SARIF output, not the internal representation. This is consistent with D-04 (Protocol-based contracts) and avoids coupling detection latency to Pydantic import time.

## Code Examples

### NDJSON Emission (FNDN-02)

```python
# src/cloneguard/audit/ndjson.py
"""NDJSON emitter for structured audit events."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from cloneguard.audit.types import AuditEvent


class NDJSONEmitter:
    """Emit AuditEvent objects as NDJSON lines."""

    def __init__(self, output: TextIO | None = None) -> None:
        # Default: stderr (never stdout -- stdout is hook communication channel)
        self._output = output or sys.stderr

    def emit(self, event: AuditEvent) -> None:
        """Write a single NDJSON line."""
        self._output.write(event.to_ndjson())

    def flush(self) -> None:
        self._output.flush()

    @classmethod
    def to_file(cls, path: Path) -> NDJSONEmitter:
        """Create emitter writing to a file."""
        return cls(output=open(path, "a", encoding="utf-8"))  # noqa: SIM115
```
[ASSUMED: exact API; D-06 specifies `event.to_ndjson()` but emitter class design is discretionary]

### SARIF Document Construction (FNDN-03)

```python
# src/cloneguard/audit/sarif.py
"""SARIF 2.1.0 emitter using sarif-pydantic."""
from __future__ import annotations

from sarif_pydantic import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    Sarif,
    Tool,
    ToolDriver,
)

from cloneguard import __version__
from cloneguard.audit.types import AuditEvent

_VERDICT_TO_LEVEL = {
    "DETECTED_CRITICAL": Level.ERROR,
    "DETECTED_HIGH": Level.ERROR,
    "DETECTED_MEDIUM": Level.WARNING,
    "DETECTED_LOW": Level.NOTE,
    "SUSPICIOUS": Level.WARNING,
}


def build_sarif(events: list[AuditEvent], rules: list[ReportingDescriptor]) -> Sarif:
    """Build a SARIF 2.1.0 document from audit events."""
    results = []
    for event in events:
        if event.verdict == "CLEAN":
            continue
        level_key = f"{event.verdict}_{event.signals.pattern_severity}" if event.signals.pattern_severity else event.verdict
        results.append(
            Result(
                rule_id=event.signals.primary_rule_id or "SEMANTIC",
                level=_VERDICT_TO_LEVEL.get(level_key, Level.WARNING),
                message=Message(text=event.signals.summary),
                locations=[
                    Location(
                        physical_location=PhysicalLocation(
                            artifact_location=ArtifactLocation(uri=event.source_path),
                            region=Region(start_line=event.signals.line_number or 1),
                        )
                    )
                ],
            )
        )

    return Sarif(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolDriver(
                        name="cloneguard",
                        version=__version__,
                        information_uri="https://github.com/prodnull/cloneguard",
                        rules=rules,
                    )
                ),
                results=results,
            )
        ],
    )
```
[VERIFIED: sarif-pydantic API tested -- `Sarif`, `Run`, `ToolDriver`, `Result`, `ReportingDescriptor`, `Message`, `Location`, `PhysicalLocation`, `ArtifactLocation`, `Region`, `Level` all verified importable and functional]

### Hook Config Integrity Self-Check (FNDN-05)

```python
# src/cloneguard/integrity.py
"""Hook configuration integrity self-check (CVE-2025-59536 defense)."""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_EXPECTED_COMMAND_PREFIX = "cloneguard hook-check --event"
_EXPECTED_EVENTS = {"InstructionsLoaded", "PreToolUse", "PostToolUse"}

def check_hook_integrity(settings_path: Path | None = None) -> list[str]:
    """Verify hook configuration points to CloneGuard.

    Returns list of warning messages. Empty list = configuration intact.
    """
    warnings: list[str] = []

    if settings_path is None:
        settings_path = Path.home() / ".claude" / "settings.json"

    if not settings_path.exists():
        warnings.append(f"Hook config not found: {settings_path}")
        return warnings

    try:
        config = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        warnings.append(f"Cannot read hook config: {e}")
        return warnings

    hooks = config.get("hooks", {})
    found_events: set[str] = set()

    for event_name, matchers in hooks.items():
        if event_name not in _EXPECTED_EVENTS:
            continue
        for matcher_block in matchers:
            for hook in matcher_block.get("hooks", []):
                command = hook.get("command", "")
                if _EXPECTED_COMMAND_PREFIX in command:
                    found_events.add(event_name)
                elif command:
                    warnings.append(
                        f"Hook {event_name} points to unexpected command: {command!r}"
                    )

    missing = _EXPECTED_EVENTS - found_events
    if missing:
        warnings.append(f"Missing CloneGuard hooks for events: {', '.join(sorted(missing))}")

    return warnings
```
[CITED: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/]

### Thin Shim Pattern (FNDN-06)

```python
# src/cloneguard/hooks.py (after extraction -- thin shim)
"""CloneGuard hook handlers -- thin shim delegating to DetectionEngine."""
from __future__ import annotations

import json
import sys
from typing import Any

# Existing handler functions remain but become thin dispatchers.
# Example for handle_pre_tool_use:

def handle_pre_tool_use(data: dict[str, Any]) -> int:
    """PreToolUse handler -- thin shim to DetectionEngine."""
    from cloneguard.detection.engine import get_detection_engine
    from cloneguard.detection.sequence import get_monitor

    # Sequence enforcement (unchanged behavior)
    try:
        verdict = get_monitor().check_enforcement(data)
        if verdict is not None:
            msg = (
                f"BLOCKED by {verdict.rule_id}: {verdict.description}\n"
                f"To allowlist: cloneguard sequence-allow {verdict.rule_id} <domain-or-path>"
            )
            print(msg)
            return 2
    except Exception:
        pass

    # Delegate to detection engine
    engine = get_detection_engine()
    result = engine.scan_pre_tool_use(data)
    if result.exit_code == 2:
        print(result.message)
    elif result.exit_code == 0 and result.message:
        print(result.message)
    return result.exit_code
```
[ASSUMED: exact shim structure; D-02 specifies "~10 lines per handler" with ToolCallEvent/DetectionResult contract]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| sarif-om (1.0.4) | sarif-pydantic (0.6.2) | 2024 | Type-safe SARIF construction with Pydantic v2 native models vs unmaintained package |
| `typing.Protocol` (PEP 544) | Stable since Python 3.8 | 2020 | structural subtyping without ABC inheritance -- already mature and well-supported by mypy |
| Pydantic v1 | Pydantic v2 (2.12.5) | 2023 | Rust-backed validation, ConfigDict, model_dump_json(). v1 deprecated. |
| Manual NDJSON | Pydantic `.model_dump_json()` + `"\n"` | N/A | One-line serialization, no custom encoder needed |

**Deprecated/outdated:**
- `sarif-om` (1.0.4): Unmaintained since 2022, uses pbr build system, no type hints. Use `sarif-pydantic` instead. [CITED: https://pypi.org/project/sarif-om/1.0.4/]
- Pydantic v1: Deprecated. v2 is the current release line with breaking API changes. All code must use v2 patterns (`model_config = ConfigDict(...)`, not `class Config`).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Pydantic `BaseModel` cold-start import adds ~50-80ms | Pitfall 6 | If lower, lazy import optimization is unnecessary overhead. If higher, even lazy import may be too slow and we'd need to avoid Pydantic on the detection path entirely. |
| A2 | Exact Pydantic field naming for `AuditEvent` model | Code Examples | Low risk -- field names are Claude's discretion per CONTEXT.md. May need adjustment based on downstream SIEM ingestion requirements. |
| A3 | `enforcement_action` defaults to "ALLOW" in Phase 1 | Architecture Patterns | Low risk -- D-05 specifies this field, and the specific section on Phase 1 scope confirms Phase 2 introduces CONSTRAIN/BLOCK. |
| A4 | sarif-pydantic 0.6.2 handles GitHub SARIF upload requirements | SARIF section | Medium risk -- need to verify `partialFingerprints` field support in sarif-pydantic. If missing, may need manual JSON injection. |

## Open Questions

1. **Session ID generation strategy**
   - What we know: D-05 requires `session_id` in every audit event. The current codebase does not generate session IDs -- it relies on process lifetime for session scoping.
   - What's unclear: Should session_id come from the agent's session concept, be a UUID generated per-process, or be derived from a combination of PID + timestamp?
   - Recommendation: Generate a UUID4 at process startup. Store as module-level `_SESSION_ID`. This is simple, unique, and requires no agent-protocol knowledge.

2. **NDJSON output destination default**
   - What we know: D-06 says "stdout or configurable output file." But stdout is the hook communication channel (anti-pattern 4 from architecture research).
   - What's unclear: For hook-check invocations, NDJSON cannot go to stdout. For `cloneguard scan`, stdout shows the human-readable report.
   - Recommendation: Default NDJSON to file only (via `CLONEGUARD_NDJSON_OUTPUT` env var). No default stdout emission. This avoids protocol corruption risk entirely.

3. **SARIF `partialFingerprints` computation**
   - What we know: GitHub requires `partialFingerprints.primaryLocationLineHash` to prevent duplicate alerts.
   - What's unclear: Whether sarif-pydantic has `partial_fingerprints` in its `Result` model.
   - Recommendation: Verified that `Result.partial_fingerprints` exists in sarif-pydantic's model fields. Use SHA-256 of (rule_id + file_path + matched_text) as the fingerprint.

4. **Existing test count discrepancy**
   - What we know: D-15 says "1,321 existing tests." Running `uv run python -m pytest tests/ --co -q` collects 1,345 tests.
   - What's unclear: 24 tests were added after the 1,321 count was established.
   - Recommendation: Use 1,345 as the baseline. All must pass after extraction. [VERIFIED: 1345 tests collected]

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.11+ | All | Yes | 3.14.3 | -- |
| uv | Packaging, testing | Yes | 0.10.6 | pip (degraded) |
| pipx | Standalone install validation | Yes | 1.8.0 | uv tool install |
| pydantic | Event schema (D-05) | Yes | 2.12.5 | -- (already installed) |
| sarif-pydantic | SARIF output (D-10) | Yes | 0.6.2 | -- (just installed) |
| ruff | Lint/format | Yes | 0.15.0 | -- |
| mypy | Type checking | Yes | 1.19.1 | -- |
| ONNX model | Tier 1.5 detection | Yes | 90.8 MB in src/cloneguard/model/ | Graceful degradation (returns None) |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None -- all Phase 1 dependencies are available.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A -- CloneGuard is a local-only tool |
| V3 Session Management | No | Process-lifetime sessions, no persistent auth |
| V4 Access Control | Yes | Hook config integrity check (FNDN-05), human-only allowlist CLI guard |
| V5 Input Validation | Yes | Pydantic v2 model validation on all event schemas; JSON deserialization with try/except |
| V6 Cryptography | Minimal | SHA-256 for content hashing (hashlib, not hand-rolled); no encryption needed |

### Known Threat Patterns for This Phase

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Hook config tampering (CVE-2025-59536) | Tampering | FNDN-05: integrity self-check verifying hook commands point to CloneGuard |
| Stdout protocol corruption | Tampering | NDJSON/SARIF NEVER writes to stdout; audit output to file/stderr only |
| Audit log injection via tool_input | Tampering | SHA-256 hash of tool_input in event (D-05), not raw content. Content never stored in audit events -- only hash. |
| Malformed hook JSON causing crash | Denial of Service | Existing pattern: try/except around `json.load(sys.stdin)`, return exit 0 on parse failure |
| SARIF output revealing sensitive content | Information Disclosure | SARIF results contain file paths and matched pattern text, but NOT full file content or tool input. Pattern match text is truncated. |

## CVE-2025-59536 Analysis

**Vulnerability:** Check Point Research discovered that malicious Hook commands in Claude Code's `.claude/settings.json` execute automatically when a developer opens a repository. Hooks, MCP server configs, and environment variables in project-level settings could achieve RCE and API key exfiltration. [CITED: https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/]

**CloneGuard's defense (FNDN-05):** On startup, verify that the hook configuration in `~/.claude/settings.json` (global) still points to CloneGuard. If a repo-level `.claude/settings.json` overrides the hook command, warn the user. This is defense-in-depth -- Anthropic patched the original vulnerability (GHSA-ph6w-f82w-28w6), but CloneGuard adds a second layer of verification.

**Implementation approach:** Check command strings, not binary paths. Verify `"cloneguard hook-check --event"` appears in hook commands. Warn on mismatch. Do not block -- the user may have intentionally configured different hooks.

## Sources

### Primary (HIGH confidence)
- sarif-pydantic 0.6.2 API -- installed and tested in project venv [VERIFIED]
- Pydantic 2.12.5 -- confirmed installed via `uv pip show pydantic` [VERIFIED]
- hooks.py, patterns.py, monitor.py, cli.py, scanner.py -- read in full [VERIFIED]
- pyproject.toml -- build config and entry points read [VERIFIED]
- 1,345 tests collected via `uv run python -m pytest --co -q` [VERIFIED]
- [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [CVE-2025-59536 Check Point Research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

### Secondary (MEDIUM confidence)
- [EU AI Act Article 12 requirements](https://artificialintelligenceact.eu/article/12/) -- minimum 6-month log retention, automatic recording of events identifying risk situations
- [sarif-pydantic PyPI page](https://pypi.org/project/sarif-pydantic/)
- [OASIS SARIF schema JSON](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json)

### Tertiary (LOW confidence)
- Pydantic cold-start import latency (~50-80ms) -- training knowledge, not measured in this session [ASSUMED]

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all packages verified installed and tested
- Architecture: HIGH -- full codebase read, extraction paths mapped
- Pitfalls: HIGH -- grounded in measured codebase properties (line counts, test counts, version discrepancy)
- SARIF integration: HIGH -- sarif-pydantic API verified with working code
- Hook integrity: MEDIUM -- CVE analysis from published research, implementation pattern is straightforward

**Research date:** 2026-04-05
**Valid until:** 2026-05-05 (stable domain -- SARIF 2.1.0 is an OASIS standard, Pydantic v2 is mature)
