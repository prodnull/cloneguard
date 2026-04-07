---
phase: 6
slug: agent-expansion
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-07
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | `pyproject.toml` ([tool.pytest.ini_options]) |
| **Quick run command** | `python -m pytest tests/ -x -q --timeout=30` |
| **Full suite command** | `python -m pytest tests/ --timeout=60` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `python -m pytest tests/ -x -q --timeout=30`
- **After every plan wave:** Run `python -m pytest tests/ --timeout=60`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | TBD | AGNT-01 | — | Browser patterns detect DOM injection | unit | `python -m pytest tests/test_browser_patterns.py -v` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | AGNT-02 | — | Autonomous patterns detect goal hijacking | unit | `python -m pytest tests/test_autonomous_patterns.py -v` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | AGNT-03 | — | Financial patterns detect transaction manipulation | unit | `python -m pytest tests/test_financial_patterns.py -v` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | AGNT-04 | — | CI/CD patterns detect workflow injection | unit | `python -m pytest tests/test_cicd_agent_patterns.py -v` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | AGNT-05 | — | Sandbox adapters restrict filesystem/network/syscalls | integration | `python -m pytest tests/test_sandbox_adapters.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_browser_patterns.py` — stubs for AGNT-01 browser pattern detection
- [ ] `tests/test_autonomous_patterns.py` — stubs for AGNT-02 autonomous pattern detection
- [ ] `tests/test_financial_patterns.py` — stubs for AGNT-03 financial pattern detection
- [ ] `tests/test_cicd_agent_patterns.py` — stubs for AGNT-04 CI/CD agent pattern detection
- [ ] `tests/test_sandbox_adapters.py` — stubs for AGNT-05 sandbox adapter tests

*Existing pytest infrastructure covers all framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| gVisor adapter enforcement | AGNT-05 | Requires Linux with runsc installed | Run on Linux VM with gVisor, verify syscall restrictions |
| Firecracker adapter enforcement | AGNT-05 | Requires Linux with KVM | Run on bare-metal Linux with KVM, verify microVM isolation |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
