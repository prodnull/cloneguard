---
gsd_state_version: 1.0
milestone: v0.3
milestone_name: milestone
status: planning
stopped_at: Completed 02-02-PLAN.md
last_updated: "2026-03-10T18:31:50.643Z"
last_activity: 2026-03-10 — Phase 1 gate failed, pivot survey complete, roadmap updated
progress:
  total_phases: 3
  completed_phases: 1
  total_plans: 5
  completed_plans: 4
  percent: 33
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** Make prompt injection attacks against AI coding agents expensive enough that attackers move on
**Current focus:** Phase 2 — Adversarial Hardening

## Current Position

Phase: 2 of 3 (Adversarial Hardening)
Plan: 0 of TBD in current phase
Status: Ready to plan
Last activity: 2026-03-10 — Phase 1 gate failed, pivot survey complete, roadmap updated

Progress: [███░░░░░░░] 33%

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
| Phase 01-transferability-gate P01 | 8 | 2 tasks | 2 files |
| Phase 01-transferability-gate P02 | ~90min | 2 tasks | 2 files |
| Phase 02-deberta-training-and-onnx-export P01 | 8 | 2 tasks | 4 files |
| Phase 02-deberta-training-and-onnx-export P02 | ~4h | 3 tasks | 7 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Pre-milestone]: Parallel vote (option B) selected over cascade — GitHub issue title injection scenario requires both classifiers on all content
- [Pre-milestone]: Ensemble over perturbation detection — architecturally diverse models defeat transfer attacks
- [Pre-milestone]: Transferability experiment as hard gate — validate empirically, do not trust theory
- [Phase 01-transferability-gate]: TextFooler-BERTScore: substituted BERTScore for UniversalSentenceEncoder to avoid TensorFlow dependency
- [Phase 01-transferability-gate]: DeBERTa id2label loaded dynamically from model config (not hard-coded); verified: {0: SAFE, 1: INJECTION}
- [Phase 01-transferability-gate]: Pre-filter corpus to MiniLM-detected samples (score > 0.5) for transfer rate measurement on detectable inputs
- [Phase 01-transferability-gate]: PIVOT: ensemble (MiniLM + DeBERTa) abandoned — 58.0% transfer rate (CI: 47.5%–67.7%) exceeds 40% gate; failure is structural (fragmentation/implicit_instruction/truncation at 100% transfer), not model-specific
- [Phase 01-transferability-gate]: TextFooler-BERTScore not executed (silent failure on sample 0); PWWS-only result is conservative — pivot is stronger, not weaker
- [Pivot]: 12 alternative defenses evaluated. Adversarial hardening (AT + Mahalanobis) selected over second classifier, certified defenses, randomized smoothing, ensemble diversity, and others. Survey: docs/results/pivot-alternatives-survey-2026-03-10.md
- [Pivot]: Roadmap reduced from 4 phases to 3. Original Phases 2-4 (DeBERTa, ensemble, ensemble benchmark) → Phase 2 (adversarial hardening) + Phase 3 (benchmark + publication)
- [Phase 02-01]: dynamo=False in torch.onnx.export — PyTorch 2.9 dynamo exporter fails to propagate dynamic batch axis through LayerNorm; TorchScript exporter handles opset 18 dynamic axes correctly
- [Phase 02-01]: PromptInjectionClassifier.forward() returns (logits, cls_embedding) tuple — enables dual-output ONNX for Mahalanobis anomaly detection in Plan 02-03
- [Phase 02-01]: MiniLMOnnxWrapper copied in generate_pwws_augmentation.py (not imported) — .venv-transfer and .venv have incompatible installed packages, deliberate isolation
- [Phase 02-deberta-training-and-onnx-export]: ASR gate triggered after round 2: benchmark ASR 20.0% < 35% threshold; round 3 skipped
- [Phase 02-deberta-training-and-onnx-export]: 5-fold CV accuracy 94.51% meets >=94.5% success criterion on v4 augmented dataset (6,472 samples)
- [Phase 02-deberta-training-and-onnx-export]: ASR gate triggered after round 2: benchmark ASR 20.0% < 35% threshold; round 3 skipped per plan
- [Phase 02-deberta-training-and-onnx-export]: 5-fold CV accuracy 94.51% meets >=94.5% success criterion on v4 augmented dataset (6,472 samples)
- [Phase 02-deberta-training-and-onnx-export]: PWWS generation success rate declined 65.7% -> 31.7% across rounds, confirming model hardened against PWWS attacks

### Pending Todos

None yet.

### Blockers/Concerns

- **[Phase 1 gate — RESOLVED]:** Transfer rate 58.0% > 40%. Pivot executed. Original Phases 2-4 replaced.
- **[Phase 2 risk]:** ASR ≤35% target is a PROJECTION from A2T literature (Yoo & Qi 2021), not measured on our data. Must validate experimentally — success criteria may need revision based on empirical results.
- **[Phase 2 risk]:** Mahalanobis single-layer CLS AUC 75-85% is estimated, not benchmarked. Yoo et al. 2022 reported 85-98% for multi-feature RDE. Single-layer will be lower.
- **[Phase 2 risk]:** Adversarial augmentation is attack-specific — PWWS hardening may not generalize to TextFooler/BERT-Attack (<5% improvement on unseen attacks per ACL Findings 2023).
- **[Phase 3 risk]:** Adaptive attacks (PWWS against hardened model) will partially circumvent augmentation. Must report the ceiling honestly.

## Session Continuity

Last session: 2026-03-10T18:31:10.626Z
Stopped at: Completed 02-02-PLAN.md
Resume file: None
