# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on
**Current focus:** Phase 1 — Transferability Gate

## Current Position

Phase: 1 of 4 (Transferability Gate)
Plan: 0 of TBD in current phase
Status: Ready to plan
Last activity: 2026-03-10 — Roadmap created, milestone v0.3.0 initialized

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: —
- Total execution time: —

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Pre-milestone]: Parallel vote (option B) selected over cascade — GitHub issue title injection scenario requires both classifiers on all content
- [Pre-milestone]: Ensemble over perturbation detection — architecturally diverse models defeat transfer attacks
- [Pre-milestone]: Transferability experiment as hard gate — validate empirically, do not trust theory

### Pending Todos

None yet.

### Blockers/Concerns

- **[Phase 1 gate]:** If transfer rate >40%, milestone pivots — Phase 2 does not begin. Pivot path must be documented before Phase 1 planning.
- **[Phase 2 risk]:** DeBERTa ONNX export via optimum-cli is broken (issue #2075). Must use ORTModel programmatically. Sanity check (50 balanced samples, non-constant predictions) is mandatory post-export.
- **[Phase 2 risk]:** DeBERTa INT8 latency on Apple M-series is unverified (estimate only). Latency probe must be first step of Phase 2. Fallback: deberta-v3-xsmall if >80ms.
- **[Phase 3 risk]:** OR-vote inflates FPR from 3.8% toward 7-9%. Mode-gate OR-vote to STRICT mode. Confirm WARNING rate <= 10% on benign eval before Phase 4.
- **[Phase 4 risk]:** NIST AI 100-2e2025 requires adaptive attack evaluation. AdaEA full implementation may exceed scope — define minimum viable adaptive attack during Phase 4 planning.

## Session Continuity

Last session: 2026-03-10
Stopped at: Roadmap written, requirements traceability updated. Ready to plan Phase 1.
Resume file: None
