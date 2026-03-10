---
phase: 1
slug: transferability-gate
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.0.2 |
| **Config file** | pyproject.toml |
| **Quick run command** | `pytest tests/test_mini_semantic.py -x -q` |
| **Full suite command** | `pytest tests/ -x -q` |
| **Estimated runtime** | ~15 seconds (existing suite); experiment script ~5-30 min depending on corpus size |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -x -q` (existing suite — no regressions)
- **After every plan wave:** Run experiment script dry-run: `python scripts/transfer_experiment.py --dry-run --limit 5`
- **Before `/gsd:verify-work`:** Full experiment run must complete with results JSON written
- **Max feedback latency:** 15 seconds (existing tests); experiment is long-running by nature

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 0 | XFER-01 | setup | `source .venv-transfer/bin/activate && python -c "import textattack"` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | XFER-01 | smoke | `python scripts/transfer_experiment.py --dry-run --limit 5` | ❌ W0 | ⬜ pending |
| 01-01-03 | 01 | 1 | XFER-02 | smoke | dry-run output includes DeBERTa labels | ❌ W0 | ⬜ pending |
| 01-01-04 | 01 | 2 | XFER-01,02 | integration | `python scripts/transfer_experiment.py` (full run) | ❌ W0 | ⬜ pending |
| 01-01-05 | 01 | 2 | XFER-03 | assertion | `test -f docs/results/transfer-gate-*.json && jq .gate_decision docs/results/transfer-gate-*.json` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `.venv-transfer/` — isolated venv with `textattack==0.3.10`, `transformers<5.0`, `torch`
- [ ] NLTK data: `wordnet`, `averaged_perceptron_tagger`, `omw-1.4`
- [ ] ProtectAI DeBERTa model prefetched to HuggingFace cache
- [ ] `scripts/transfer_experiment.py` — experiment script (created Wave 1, but structure planned Wave 0)

*Existing test infrastructure (`pytest`, `tests/`) covers regression checking.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Gate decision is intellectually honest | XFER-03 | Requires human judgement on framing | Review results doc for honest disclosure of limitations, proxy-vs-fine-tuned caveat |
| Results published with full methodology | XFER-03 | Publication quality check | Verify transfer rate, attack method, proxy identity, and limitations are all disclosed |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s (existing tests)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
