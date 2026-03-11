---
gsd_state_version: 1.0
milestone: v0.4
milestone_name: FPR Investigation, Pattern Expansion & Tool Call Monitoring
status: planning
stopped_at: Completed 05-02-PLAN.md — ScanMode threaded through hooks.py and scanner.py, combined pipeline FPR verified
last_updated: "2026-03-11T05:46:15.566Z"
last_activity: 2026-03-10 — Roadmap created, v0.4 phases 4-7 defined
progress:
  total_phases: 4
  completed_phases: 2
  total_plans: 4
  completed_plans: 4
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on
**Current focus:** Phase 4 — FPR Investigation & Documentation

## Current Position

Phase: 4 of 7 (FPR Investigation & Documentation)
Plan: Not started
Status: Ready to plan
Last activity: 2026-03-10 — Roadmap created, v0.4 phases 4-7 defined

Progress: [░░░░░░░░░░] 0%

## Accumulated Context

### Decisions

| Decision | Rationale | When |
|----------|-----------|------|
| Fold Campbell work into v0.4 | Investigation informs FPR tuning — natural first phases | 2026-03-10 |
| Add CaMeL-lite as phase 4 (Phase 7) | Previously v0.5, but natural arc: investigate → tune → expand → monitor | 2026-03-10 |
| Phase 4 bundles INV + DOC | Campbell citation is a direct output of the investigation — same delivery boundary | 2026-03-10 |
| Phase 5 depends on Phase 4 | Context-aware thresholds must be informed by INV-01/02 findings, not guessed | 2026-03-10 |
- [Phase 04]: Authorization paradox confirmed in Tier 1.5: +12.7pp FPR increase from auth preambles (9.25% baseline to 21.93%)
- [Phase 04]: MCP-005 strict-pattern FPR at 21% against legitimate defensive security content — highest of 4 audited patterns, warrants Phase 5 scope review
- [Phase 04]: Frame Campbell citation as independent empirical test, not validation of CloneGuard — honest framing per RESEARCH.md Pitfall 5
- [Phase 05-fpr-tuning]: STANDARD=(0.65, 0.88) and LENIENT=(0.75, 0.92) confirmed by calibration sweep on 757 benign samples
- [Phase 05-fpr-tuning]: Default mode=ScanMode.STANDARD on classify() for backward-compatibility with callers that omit mode
- [Phase 05-fpr-tuning]: Tier 0 CI-001 floor at 23.9% workflow FPR is the honest structural limit; Phase 5 cannot hit combined 24% target — deferred to Phase 6
- [Phase 05-fpr-tuning]: Path is primary mode signal: LENIENT/STRICT from path wins over hook_default; hook_default applies only when path returns STANDARD
- [Phase 05-fpr-tuning]: Content markers upgrade only: agent instruction marker upgrades to STRICT; workflow/CI markers confirm STANDARD without upgrading or downgrading
- [Phase 05-fpr-tuning]: Combined workflow FPR 30.2% is the honest structural result: Tier 0 CI-001 floor (~23.9%) cannot be addressed by Tier 1.5 tuning — deferred to Phase 6

### Pending Todos

None.

### Blockers/Concerns

None.

## Session Continuity

Last session: 2026-03-11T05:42:00.868Z
Stopped at: Completed 05-02-PLAN.md — ScanMode threaded through hooks.py and scanner.py, combined pipeline FPR verified
Resume file: None
