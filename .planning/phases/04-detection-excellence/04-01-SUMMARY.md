---
phase: 04-detection-excellence
plan: 01
subsystem: detection-fusion
tags: [fusion, detection, calibration, weight-profiles]
dependency_graph:
  requires: []
  provides: [FusionLayer, WeightProfile, FusionResult, load_weight_profile, calibrate_fusion]
  affects: [detection-engine, hook-pipeline]
tech_stack:
  added: []
  patterns: [collect-then-fuse, frozen-dataclass-immutability, weight-normalization, graceful-degradation]
key_files:
  created:
    - src/cloneguard/detection/fusion.py
    - src/cloneguard/detection/profiles/__init__.py
    - src/cloneguard/detection/profiles/default.yaml
    - src/cloneguard/detection/profiles/claude-code.yaml
    - src/cloneguard/detection/profiles/gemini-cli.yaml
    - src/cloneguard/detection/profiles/cursor.yaml
    - scripts/calibrate_fusion.py
    - tests/test_fusion.py
  modified:
    - src/cloneguard/detection/engine.py
    - src/cloneguard/detection/__init__.py
decisions:
  - "Fusion falls back to legacy waterfall when fusion module fails to import (graceful degradation)"
  - "WeightProfile uses nested tuples instead of dicts for frozen dataclass compatibility"
  - "Handler-specific scan methods (scan_instructions_loaded, scan_pre_tool_use, scan_post_tool_use) keep existing behavior; only generic scan() uses fusion"
  - "Calibration script exits cleanly with code 0 when no trajectory data available"
metrics:
  duration: 9 minutes
  completed: "2026-04-06T16:53:00Z"
  tasks_completed: 2
  tasks_total: 2
  files_created: 8
  files_modified: 2
  tests_added: 14
  tests_passing: 27
requirements:
  - DETC-01
  - DETC-02
---

# Phase 04 Plan 01: Three-Signal Fusion Layer Summary

Three-signal fusion layer replacing sequential waterfall with collect-then-fuse weighted scoring, including agent-type YAML profiles and offline calibration pipeline.

## What Was Built

### FusionLayer Module (`src/cloneguard/detection/fusion.py`)
- `WeightProfile` frozen dataclass: base weights (pattern=0.4, semantic=0.4, sequence=0.2), mode multipliers as nested tuples, `get_multiplier()` helper
- `FusionResult` frozen dataclass: calibrated confidence [0.0, 1.0], verdict, per-signal breakdown as tuple, MELON placeholders
- `FusionLayer` class: `fuse()` method that normalizes weights, computes weighted confidence, applies verdict thresholds (detected >= 0.6 with any detected signal, suspicious >= 0.4)
- `load_weight_profile()`: searches override path, agent-type profile, default profile; returns hardcoded defaults on any error

### Engine Refactor (`src/cloneguard/detection/engine.py`)
- `_collect_signals()`: collects pattern, semantic, and sequence signals WITHOUT early return -- all three tiers always consulted
- `scan()`: delegates to `FusionLayer.fuse()` for calibrated scoring, maps FusionResult to DetectionResult
- `_scan_waterfall()`: legacy fallback path preserving exact backward compatibility when fusion unavailable
- `_init_fusion()`: lazy initialization with graceful degradation

### Weight Profiles (`src/cloneguard/detection/profiles/`)
- Four YAML profiles: default, claude-code, gemini-cli, cursor
- Each contains: version, agent_type, base weights, mode multipliers (strict/standard/lenient), MELON configuration
- Agent-specific profiles are copies of default pending calibration data

### Calibration Pipeline (`scripts/calibrate_fusion.py`)
- Grid search over base weights (sum-to-1.0 constraint) and mode multipliers
- Content type classifier: ci_config, security_doc, test_fixture, mcp_tool_desc, source_code, other
- Supports JSONL and Parquet input formats
- Writes calibrated profiles and markdown report with dataset summary, top-5 results, per-type FPR

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 (RED) | 4a971d3 | Failing tests for FusionLayer, WeightProfile, engine signal collection |
| 1 (GREEN) | f35dd98 | FusionLayer implementation, engine refactor, all tests passing |
| 2 | e026bb6 | Weight profile YAMLs and calibration pipeline script |

## Deviations from Plan

None -- plan executed exactly as written.

## Verification Results

| Check | Result |
|-------|--------|
| `pytest tests/test_fusion.py -x -v` | 14 passed |
| `pytest tests/test_detection_engine.py -x` | 13 passed (backward compat) |
| `mypy src/cloneguard/detection/fusion.py --strict` | 0 errors |
| `ruff check src/cloneguard/detection/` | All checks passed |
| `from cloneguard.detection import FusionLayer, FusionResult, WeightProfile` | OK |
| Profile YAML validation (all 4 files) | Valid |
| `python scripts/calibrate_fusion.py --help` | exits 0 |

## Threat Model Compliance

| Threat ID | Mitigation | Status |
|-----------|------------|--------|
| T-04-01 | Profiles loaded from package directory only, not CWD/repo | Implemented |
| T-04-02 | Calibration report contains only FPR/TPR statistics | Accepted |
| T-04-03 | Fusion is O(3) constant time | Accepted |
| T-04-04 | FusionResult and WeightProfile are @dataclass(frozen=True) | Implemented |

## Known Stubs

None. All profiles ship with uncalibrated baseline weights that produce valid results. Calibration script is runnable but requires trajectory data to produce calibrated weights.

## Self-Check: PASSED
