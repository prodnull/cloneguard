---
phase: 3
slug: adversarial-benchmark-and-publication
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | pyproject.toml |
| **Quick run command** | `uv run pytest tests/test_hardened_benchmark.py tests/test_latency.py -x -q` |
| **Full suite command** | `uv run pytest tests/ -x -q` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `uv run pytest tests/ -x -q`
- **After every plan wave:** Run `uv run pytest tests/ -x -q`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | BENCH-01 | integration | `python3 -c "import json; d=json.load(open('docs/results/hardened-benchmark-final.json')); assert 'recall' in d and 'delta_from_v3' in d"` | ❌ W0 | ⬜ pending |
| 03-01-02 | 01 | 1 | BENCH-02 | integration | `.venv-transfer/bin/python scripts/adaptive_pwws_benchmark.py --dry-run` | ❌ W0 | ⬜ pending |
| 03-01-03 | 01 | 1 | BENCH-03 | integration | `python3 -c "import json; d=json.load(open('docs/results/hardened-benchmark-final.json')); assert 'correlated_failures' in d"` | ❌ W0 | ⬜ pending |
| 03-02-01 | 02 | 2 | BENCH-04 | manual | Grep published docs for "prevents"/"blocks"/"secure" | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing `tests/test_hardened_benchmark.py` and `tests/test_latency.py` from Phase 2 cover BENCH-01 output schema
- `scripts/hardened_benchmark.py` exists from Phase 2 — extend or create `scripts/adaptive_pwws_benchmark.py` for BENCH-02
- No new test framework or fixtures needed

*Existing infrastructure covers most phase requirements. Adaptive attack script is the main new artifact.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Framing language audit | BENCH-04 | Requires human judgment on tone/framing | `grep -rni "prevents\|blocks\|secure" docs/SECURITY.md docs/MINI-SEMANTIC-MODEL.md` — must return 0 matches in benchmark sections |
| Publication venue assessment | User request | Subjective editorial judgment | Review claims against methodology, assess conference fit |
| LinkedIn/Medium content | User request | Creative writing + editorial | Review drafts for accuracy, tone, honest framing |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
