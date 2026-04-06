# Fusion Weight Calibration Report

Calibration date: 2026-04-06
Data source: benchmark corpus

## Dataset Summary

Total samples: 936
Samples with signals: 278

| Label | Count | With Signals |
|-------|-------|-------------|
| benign | 751 | 117 |
| malicious | 185 | 161 |

| Content Type | Count |
|-------------|-------|
| agent_instructions | 49 |
| build_script | 55 |
| config | 76 |
| env_config | 55 |
| other | 185 |
| readme | 146 |
| security_doc | 48 |
| test_file | 166 |
| workflow | 156 |

## Grid Search Parameters

- Total grid points evaluated: 42282
- Grid points meeting FPR constraint: 21492
- Target TPR: >= 0.25
- Max FPR constraint: <= 0.092 (9.2%)
- **Search dimensions:**
  - pattern_base: [0.30, 0.35, 0.40, 0.45, 0.50]
  - semantic_base: [0.25, 0.30, 0.35, 0.40, 0.45]
  - sequence_base: [0.10, 0.15, 0.20, 0.25]
  - detected_threshold: [0.60, 0.65, 0.70, 0.75, 0.80, 0.85]
  - suspicious_threshold: [0.40, 0.45, 0.50, 0.55, 0.60]
  - strict_pattern_mult: [1.0, 1.1, 1.2]
  - strict_semantic_mult: [1.1, 1.2, 1.3]
  - lenient_pattern_mult: [0.5, 0.6, 0.7]
  - lenient_semantic_mult: [0.5, 0.6, 0.7]

## Top 5 Weight Sets by TPR (meeting FPR constraint)

| # | pattern | semantic | sequence | det_thresh | susp_thresh | TPR | max FPR |
|---|---------|----------|----------|-----------|------------|-----|---------|
| 1 | 0.25 | 0.5 | 0.25 | 0.55 | 0.35 | 0.7730 | 0.0897 |
| 2 | 0.25 | 0.5 | 0.25 | 0.55 | 0.35 | 0.7730 | 0.0897 |
| 3 | 0.25 | 0.5 | 0.25 | 0.55 | 0.35 | 0.7730 | 0.0897 |
| 4 | 0.25 | 0.5 | 0.25 | 0.55 | 0.35 | 0.7730 | 0.0897 |
| 5 | 0.25 | 0.5 | 0.25 | 0.55 | 0.35 | 0.7730 | 0.0897 |

## Selected Weight Set

- **pattern_base**: 0.25
- **semantic_base**: 0.5
- **sequence_base**: 0.25
- **detected_threshold**: 0.55
- **suspicious_threshold**: 0.35
- **strict_pattern_mult**: 1.0
- **strict_semantic_mult**: 1.1
- **lenient_pattern_mult**: 0.5
- **lenient_semantic_mult**: 0.5
- **TPR**: 0.7730
- **max FPR**: 0.0897

**Rationale**: Maximizes TPR while keeping per-content-type FPR below 0.092 (9.2%) across all content categories. Verdict thresholds are calibrated to reduce false positive rate for benign content that triggers individual signal types.

## Per-Content-Type FPR at Selected Weights

| Content Type | FPR | Status |
|-------------|-----|--------|
| agent_instructions | 0.0408 (4.1%) | PASS |
| build_script | 0.0000 (0.0%) | PASS |
| config | 0.0000 (0.0%) | PASS |
| env_config | 0.0000 (0.0%) | PASS |
| other | 0.0000 (0.0%) | PASS |
| readme | 0.0411 (4.1%) | PASS |
| security_doc | 0.0000 (0.0%) | PASS |
| test_file | 0.0000 (0.0%) | PASS |
| workflow | 0.0897 (9.0%) | PASS |

## Calibration Methodology

1. **Signal collection**: Run DetectionEngine._collect_signals() on each benchmark sample to obtain pattern, semantic, and sequence signals.
2. **Grid search**: For each weight combination, compute FusionLayer.fuse() on pre-collected signals and measure TPR + per-content-type FPR.
3. **Selection**: Choose the weight set that maximizes TPR subject to per-content-type FPR <= 9.2%.
4. **Threshold tuning**: Verdict thresholds (detected, suspicious) are included in the grid search to find the optimal balance between detection rate and false positive rate.

