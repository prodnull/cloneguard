# Phase 1: Foundation - Discussion Log (Auto Mode)

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions captured in CONTEXT.md -- this log preserves the analysis.

**Date:** 2026-04-05
**Phase:** 01-Foundation
**Mode:** auto
**Areas analyzed:** Detection Engine Extraction, Event Schema Design, SARIF Mapping, Packaging, Hook Config Integrity, Backward Compatibility

## Auto-Resolved Decisions

All decisions were auto-resolved using recommended defaults from research findings and the v2 architecture design document.

### Detection Engine Extraction
| Option | Description | Selected |
|--------|-------------|----------|
| Extract DetectionEngine with Protocol interface | hooks.py becomes thin shim | ✓ |
| Gradual extraction (one handler at a time) | Lower risk but longer | |
| Full rewrite | Clean but high regression risk | |

**Auto-selected:** Extract DetectionEngine with Protocol interface (recommended by architecture research)
**Rationale:** Research ARCHITECTURE.md validates this as the lowest-risk approach with clear dependency ordering. Thin shims maintain backward compat.

### Event Schema Design
| Option | Description | Selected |
|--------|-------------|----------|
| Pydantic v2 frozen models | Canonical internal representation | ✓ |
| Plain dataclasses | Zero dependencies | |
| TypedDict | Lightest weight | |

**Auto-selected:** Pydantic v2 frozen models (recommended by stack research)
**Rationale:** Pydantic v2 is already a transitive dependency. Frozen models enforce immutability. Built-in JSON serialization for NDJSON. sarif-pydantic uses same ecosystem.

### SARIF Output
| Option | Description | Selected |
|--------|-------------|----------|
| sarif-pydantic library | Type-safe SARIF generation | ✓ |
| Manual JSON construction | No dependency | |
| sarif-om (unmaintained) | Previously standard | |

**Auto-selected:** sarif-pydantic (0.6.2) (recommended by stack research)
**Rationale:** Replaces unmaintained sarif-om. Type-safe. Validates against OASIS schema.

### Packaging
| Option | Description | Selected |
|--------|-------------|----------|
| Ship model in wheel | Works offline, large package | ✓ |
| Separate model download | Smaller wheel, needs network | |
| Model as optional extra | Flexible but complex UX | |

**Auto-selected:** Ship model in wheel (recommended default)
**Rationale:** Security tools must work fully offline. 87MB is acceptable for a security tool.

### Backward Compatibility
| Option | Description | Selected |
|--------|-------------|----------|
| Thin shim + full test suite | Zero behavior change, verified by 1,321 tests | ✓ |
| Deprecation warnings | Signal future removal | |
| Clean break | Simpler but breaks users | |

**Auto-selected:** Thin shim + full test suite (only viable option)
**Rationale:** Exit code contract (0/2) is non-negotiable. All existing integrations depend on it.

## Claude's Discretion

- Internal module organization within detection engine package
- Exact Pydantic model field naming beyond specified schema
- Error handling for malformed hook input
- CI benchmark regression gate implementation
- Test organization for new vs migrated tests

## Deferred Ideas

- OTel span emission (Phase 3)
- Three-verdict model (Phase 2)
- Policy engine (Phase 2)
- Input adapter abstraction (Phase 3)
