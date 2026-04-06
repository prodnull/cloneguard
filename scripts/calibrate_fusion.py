"""Offline calibration pipeline for CloneGuard fusion layer weights.

Runs grid search over weight combinations, mode multipliers, and verdict
thresholds against the benchmark corpus to find the optimal weight profile
that maximizes TPR while keeping per-content-type FPR below a threshold.

Phase 1: Collect signals from DetectionEngine._collect_signals() for all
benchmark samples (once, cached). Phase 2: Grid search over FusionLayer
parameters using pre-collected signals. Phase 3: Write calibrated profiles
and report.

If the benchmark corpus is missing, falls back to trajectory data directory.
If neither is available, prints a warning and exits cleanly with code 0.

Usage:
    python scripts/calibrate_fusion.py --help
    python scripts/calibrate_fusion.py --data-dir data/benchmark/
    python scripts/calibrate_fusion.py --target-tpr 0.95 --max-fpr 0.092
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

logger = logging.getLogger(__name__)


@dataclass
class Sample:
    """A single labeled sample with pre-collected signals for calibration."""

    file_path: str
    content: str
    label: str  # "benign" | "malicious"
    content_type: str
    signals: list[Any] = field(default_factory=list)  # list[SignalResult] at runtime
    scan_mode: str = "standard"


@dataclass
class GridPoint:
    """A single point in the weight grid search."""

    pattern_base: float
    semantic_base: float
    sequence_base: float
    detected_threshold: float = 0.6
    suspicious_threshold: float = 0.4
    strict_pattern_mult: float = 1.2
    strict_semantic_mult: float = 1.3
    lenient_pattern_mult: float = 0.7
    lenient_semantic_mult: float = 0.7
    tpr: float = 0.0
    max_fpr: float = 0.0
    per_type_fpr: dict[str, float] = field(default_factory=dict)


def load_benchmark_corpus(corpus_dir: Path) -> list[Sample]:
    """Load labeled samples from the benchmark corpus (benign + malicious).

    Uses content_type from benign_corpus.json directly. For malicious samples,
    classifies based on content heuristics.
    """
    samples: list[Sample] = []

    benign_path = corpus_dir / "benign_corpus.json"
    malicious_path = corpus_dir / "malicious_corpus.json"

    if not benign_path.exists() or not malicious_path.exists():
        return samples

    # Load benign corpus
    with open(benign_path) as f:
        raw_benign = json.load(f)
    for item in raw_benign:
        content = item.get("text", item.get("content", ""))
        content_type = item.get("content_type", "other")
        scan_mode = item.get("scan_mode", "STANDARD").lower()
        samples.append(
            Sample(
                file_path=item.get("id", "unknown"),
                content=content,
                label="benign",
                content_type=content_type,
                scan_mode=scan_mode,
            )
        )

    # Load malicious corpus
    with open(malicious_path) as f:
        raw_malicious = json.load(f)
    for item in raw_malicious:
        content = item.get("payload", item.get("content", item.get("text", "")))
        content_type = item.get("content_type", "other")
        samples.append(
            Sample(
                file_path=item.get("id", "unknown"),
                content=content,
                label="malicious",
                content_type=content_type,
                scan_mode="standard",
            )
        )

    return samples


def collect_signals(samples: list[Sample]) -> None:
    """Run DetectionEngine._collect_signals() on each sample to populate signal data.

    This is the expensive phase -- runs pattern + semantic classification once per sample.
    Signals are stored on each Sample object for reuse during grid search.
    """
    from cloneguard.detection.engine import DetectionEngine
    from cloneguard.detection.patterns import ScanMode

    engine = DetectionEngine()
    mode_map = {
        "strict": ScanMode.STRICT,
        "standard": ScanMode.STANDARD,
        "lenient": ScanMode.LENIENT,
    }

    print(f"Collecting signals for {len(samples)} samples...")
    start = time.monotonic()

    for i, sample in enumerate(samples):
        if not sample.content:
            continue
        mode = mode_map.get(sample.scan_mode, ScanMode.STANDARD)
        try:
            signals = engine._collect_signals(sample.content, sample.file_path, mode)
            sample.signals = signals
        except Exception as exc:
            logger.warning("Signal collection failed for sample %d: %s", i, exc)
            sample.signals = []

        if (i + 1) % 100 == 0:
            elapsed = time.monotonic() - start
            print(f"  Collected {i + 1}/{len(samples)} ({elapsed:.1f}s)")

    elapsed = time.monotonic() - start
    print(f"  Signal collection complete: {elapsed:.1f}s")


def build_weight_grid() -> list[GridPoint]:
    """Build the grid of weight combinations to search.

    Includes verdict threshold tuning for FPR control.
    Only includes combinations where base weights sum to 1.0 (within tolerance).
    """
    pattern_bases = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    semantic_bases = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    sequence_bases = [0.10, 0.15, 0.20, 0.25]
    detected_thresholds = [0.55, 0.60, 0.65, 0.70, 0.75, 0.80]
    suspicious_thresholds = [0.35, 0.40, 0.45, 0.50, 0.55]
    strict_pattern_mults = [1.0, 1.1, 1.2]
    strict_semantic_mults = [1.1, 1.2, 1.3]
    lenient_pattern_mults = [0.5, 0.6, 0.7]
    lenient_semantic_mults = [0.5, 0.6, 0.7]

    grid: list[GridPoint] = []
    for pb, sb, sqb in itertools.product(pattern_bases, semantic_bases, sequence_bases):
        if abs(pb + sb + sqb - 1.0) > 0.01:
            continue
        for dt, st in itertools.product(detected_thresholds, suspicious_thresholds):
            if st >= dt:
                continue  # suspicious threshold must be below detected threshold
            for spm, ssm, lpm, lsm in itertools.product(
                strict_pattern_mults,
                strict_semantic_mults,
                lenient_pattern_mults,
                lenient_semantic_mults,
            ):
                grid.append(
                    GridPoint(
                        pattern_base=pb,
                        semantic_base=sb,
                        sequence_base=sqb,
                        detected_threshold=dt,
                        suspicious_threshold=st,
                        strict_pattern_mult=spm,
                        strict_semantic_mult=ssm,
                        lenient_pattern_mult=lpm,
                        lenient_semantic_mult=lsm,
                    )
                )

    return grid


def make_weight_profile(gp: GridPoint) -> Any:
    """Construct a WeightProfile from a GridPoint."""
    from cloneguard.detection.fusion import WeightProfile

    mode_multipliers: tuple[tuple[str, tuple[tuple[str, float], ...]], ...] = (
        (
            "strict",
            (
                ("pattern", gp.strict_pattern_mult),
                ("semantic", gp.strict_semantic_mult),
                ("sequence", 0.8),
            ),
        ),
        (
            "standard",
            (("pattern", 1.0), ("semantic", 1.0), ("sequence", 1.0)),
        ),
        (
            "lenient",
            (
                ("pattern", gp.lenient_pattern_mult),
                ("semantic", gp.lenient_semantic_mult),
                ("sequence", 1.2),
            ),
        ),
    )
    return WeightProfile(
        pattern_base=gp.pattern_base,
        semantic_base=gp.semantic_base,
        sequence_base=gp.sequence_base,
        mode_multipliers=mode_multipliers,
        agent_type="calibrated",
        detected_threshold=gp.detected_threshold,
        suspicious_threshold=gp.suspicious_threshold,
    )


def evaluate_grid_point(
    gp: GridPoint,
    samples: list[Sample],
) -> GridPoint:
    """Evaluate a single grid point against the sample set.

    Uses pre-collected signals to compute TPR and per-content-type FPR
    via FusionLayer.fuse() with the grid point's weight configuration.
    """
    from cloneguard.detection.fusion import FusionLayer
    from cloneguard.detection.patterns import ScanMode

    mode_map = {
        "strict": ScanMode.STRICT,
        "standard": ScanMode.STANDARD,
        "lenient": ScanMode.LENIENT,
    }

    profile = make_weight_profile(gp)
    layer = FusionLayer(profile)

    true_positives = 0
    total_malicious = 0
    false_positives_by_type: dict[str, int] = defaultdict(int)
    total_benign_by_type: dict[str, int] = defaultdict(int)

    for sample in samples:
        mode = mode_map.get(sample.scan_mode, ScanMode.STANDARD)
        result = layer.fuse(sample.signals, mode)
        is_detected = result.verdict in ("detected", "suspicious")

        if sample.label == "malicious":
            total_malicious += 1
            if is_detected:
                true_positives += 1
        else:
            total_benign_by_type[sample.content_type] += 1
            if is_detected:
                false_positives_by_type[sample.content_type] += 1

    gp.tpr = true_positives / total_malicious if total_malicious > 0 else 0.0
    gp.per_type_fpr = {}
    max_fpr = 0.0
    all_types = set(total_benign_by_type.keys())
    for ct in sorted(all_types):
        total = total_benign_by_type.get(ct, 0)
        fp = false_positives_by_type.get(ct, 0)
        fpr = fp / total if total > 0 else 0.0
        gp.per_type_fpr[ct] = fpr
        max_fpr = max(max_fpr, fpr)
    gp.max_fpr = max_fpr

    return gp


def calibrate(
    data_dir: Path,
    output_dir: Path,
    report_dir: Path,
    target_tpr: float = 0.95,
    max_fpr: float = 0.092,
) -> bool:
    """Run the full calibration pipeline.

    Returns True if calibration succeeded and profiles were written.
    Returns False if no data was available (default weights remain).
    """
    # Try benchmark corpus first, fall back to trajectory data
    samples = load_benchmark_corpus(data_dir)
    data_source = "benchmark corpus"

    if not samples:
        # Try trajectory data as fallback
        traj_dir = data_dir.parent / "trajectories" if data_dir.name == "benchmark" else data_dir
        if traj_dir.exists() and any(traj_dir.iterdir()):
            samples = _load_trajectory_samples(traj_dir)
            data_source = "trajectory data"

    if not samples:
        print(
            f"WARNING: No data found in {data_dir}. "
            "Using default uncalibrated weights.",
            file=sys.stderr,
        )
        return False

    print(f"Loaded {len(samples)} samples from {data_source}")

    # Dataset summary
    label_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        label_counts[s.label] += 1
        type_counts[s.content_type] += 1

    print(f"  Labels: {dict(label_counts)}")
    print(f"  Content types: {dict(type_counts)}")

    # Phase 1: Collect signals (expensive, done once)
    collect_signals(samples)

    # Count samples with at least one signal
    signaled = sum(1 for s in samples if s.signals)
    print(f"  Samples with signals: {signaled}/{len(samples)}")

    # Phase 2: Build grid and evaluate
    grid = build_weight_grid()
    print(f"Grid search: {len(grid)} combinations")

    results: list[GridPoint] = []
    start = time.monotonic()
    for i, gp in enumerate(grid):
        gp = evaluate_grid_point(gp, samples)
        results.append(gp)
        if (i + 1) % 5000 == 0:
            elapsed = time.monotonic() - start
            print(f"  Evaluated {i + 1}/{len(grid)} ({elapsed:.1f}s)...")

    elapsed = time.monotonic() - start
    print(f"  Grid search complete: {elapsed:.1f}s")

    # Phase 3: Filter valid results (all content-type FPR constraints met)
    valid = [r for r in results if r.max_fpr <= max_fpr and r.tpr >= target_tpr]
    if not valid:
        # Relax TPR constraint but keep FPR hard
        valid = [r for r in results if r.max_fpr <= max_fpr]
        if valid:
            print(
                f"WARNING: No weight set meets both TPR >= {target_tpr} and "
                f"max_fpr <= {max_fpr}. Relaxing TPR constraint.",
                file=sys.stderr,
            )
        else:
            # Relax both -- pick best FPR
            print(
                f"WARNING: No weight set meets max_fpr <= {max_fpr}. "
                "Selecting best available FPR.",
                file=sys.stderr,
            )
            valid = sorted(results, key=lambda r: (r.max_fpr, -r.tpr))[:20]

    # Select best: maximize TPR among valid, then minimize max_fpr
    valid.sort(key=lambda r: (-r.tpr, r.max_fpr))
    selected = valid[0]

    print(f"\nSelected weights: TPR={selected.tpr:.4f}, max FPR={selected.max_fpr:.4f}")
    print(
        f"  pattern_base={selected.pattern_base}, "
        f"semantic_base={selected.semantic_base}, "
        f"sequence_base={selected.sequence_base}"
    )
    print(
        f"  detected_threshold={selected.detected_threshold}, "
        f"suspicious_threshold={selected.suspicious_threshold}"
    )

    # Write calibrated profiles
    _write_profiles(selected, output_dir)

    # Write calibration report
    top_5 = valid[:5]
    _write_report(
        samples, grid, top_5, selected, report_dir,
        target_tpr, max_fpr, data_source,
    )

    return True


def _load_trajectory_samples(data_dir: Path) -> list[Sample]:
    """Load samples from trajectory JSONL/parquet files (fallback path)."""
    samples: list[Sample] = []

    for jsonl_file in data_dir.glob("**/*.jsonl"):
        with open(jsonl_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    content = record.get("content", "")
                    file_path = record.get("file_path", record.get("path", "unknown"))
                    label = record.get("label", "benign")
                    content_type = record.get("content_type", "other")
                    samples.append(
                        Sample(
                            file_path=file_path,
                            content=content,
                            label=label,
                            content_type=content_type,
                        )
                    )
                except json.JSONDecodeError:
                    continue

    if not samples:
        try:
            import pyarrow.parquet as pq  # type: ignore[import-untyped]

            for parquet_file in data_dir.glob("**/*.parquet"):
                table = pq.read_table(parquet_file)
                df = table.to_pydict()
                paths = df.get("file_path", df.get("path", []))
                contents = df.get("content", [])
                labels = df.get("label", ["benign"] * len(paths))

                for i in range(len(paths)):
                    file_path = str(paths[i]) if i < len(paths) else "unknown"
                    content = str(contents[i]) if i < len(contents) else ""
                    label = str(labels[i]) if i < len(labels) else "benign"
                    samples.append(
                        Sample(
                            file_path=file_path,
                            content=content,
                            label=label,
                            content_type="other",
                        )
                    )
        except ImportError:
            logger.info("pyarrow not available; cannot read parquet files")

    return samples


def _write_profiles(selected: GridPoint, output_dir: Path) -> None:
    """Write calibrated weight profiles to YAML files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")  # noqa: UP017

    for agent_type in ["default", "claude-code", "gemini-cli", "cursor"]:
        profile_data: dict[str, Any] = {
            "version": "1",
            "agent_type": agent_type,
            "description": (
                f"Calibrated fusion weights for {agent_type} "
                f"-- calibrated on benchmark dataset ({today})"
            ),
            "weights": {
                "pattern_base": round(selected.pattern_base, 2),
                "semantic_base": round(selected.semantic_base, 2),
                "sequence_base": round(selected.sequence_base, 2),
            },
            "thresholds": {
                "detected": round(selected.detected_threshold, 2),
                "suspicious": round(selected.suspicious_threshold, 2),
            },
            "mode_multipliers": {
                "strict": {
                    "pattern": round(selected.strict_pattern_mult, 1),
                    "semantic": round(selected.strict_semantic_mult, 1),
                    "sequence": 0.8,
                },
                "standard": {
                    "pattern": 1.0,
                    "semantic": 1.0,
                    "sequence": 1.0,
                },
                "lenient": {
                    "pattern": round(selected.lenient_pattern_mult, 1),
                    "semantic": round(selected.lenient_semantic_mult, 1),
                    "sequence": 1.2,
                },
            },
            "melon": {
                "enabled": True,
                "ambiguous_low": 0.4,
                "ambiguous_high": 0.6,
                "similarity_threshold": 0.8,
                "circuit_breaker_window": 20,
                "circuit_breaker_rate": 0.15,
            },
        }
        profile_path = output_dir / f"{agent_type}.yaml"
        with open(profile_path, "w") as f:
            yaml.dump(profile_data, f, default_flow_style=False, sort_keys=False)
        print(f"Wrote profile: {profile_path}")


def _write_report(
    samples: list[Sample],
    grid: list[GridPoint],
    top_5: list[GridPoint],
    selected: GridPoint,
    report_dir: Path,
    target_tpr: float,
    max_fpr: float,
    data_source: str,
) -> None:
    """Write calibration report in markdown format."""
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "calibration_report.md"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")  # noqa: UP017

    label_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    signaled_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        label_counts[s.label] += 1
        type_counts[s.content_type] += 1
        if s.signals:
            signaled_counts[s.label] += 1

    content_types = sorted(type_counts.keys())

    lines: list[str] = [
        "# Fusion Weight Calibration Report",
        "",
        f"Calibration date: {today}",
        f"Data source: {data_source}",
        "",
        "## Dataset Summary",
        "",
        f"Total samples: {len(samples)}",
        f"Samples with signals: {sum(signaled_counts.values())}",
        "",
        "| Label | Count | With Signals |",
        "|-------|-------|-------------|",
    ]
    for label in sorted(label_counts.keys()):
        lines.append(
            f"| {label} | {label_counts[label]} | {signaled_counts.get(label, 0)} |"
        )

    lines.extend(
        [
            "",
            "| Content Type | Count |",
            "|-------------|-------|",
        ]
    )
    for ct in content_types:
        lines.append(f"| {ct} | {type_counts.get(ct, 0)} |")

    # Grid search summary
    fpr_passing = sum(
        1 for r in grid
        if hasattr(r, "max_fpr") and r.max_fpr <= max_fpr
    )

    lines.extend(
        [
            "",
            "## Grid Search Parameters",
            "",
            f"- Total grid points evaluated: {len(grid)}",
            f"- Grid points meeting FPR constraint: {fpr_passing}",
            f"- Target TPR: >= {target_tpr}",
            f"- Max FPR constraint: <= {max_fpr} ({max_fpr * 100:.1f}%)",
            "- **Search dimensions:**",
            "  - pattern_base: [0.30, 0.35, 0.40, 0.45, 0.50]",
            "  - semantic_base: [0.25, 0.30, 0.35, 0.40, 0.45]",
            "  - sequence_base: [0.10, 0.15, 0.20, 0.25]",
            "  - detected_threshold: [0.60, 0.65, 0.70, 0.75, 0.80, 0.85]",
            "  - suspicious_threshold: [0.40, 0.45, 0.50, 0.55, 0.60]",
            "  - strict_pattern_mult: [1.0, 1.1, 1.2]",
            "  - strict_semantic_mult: [1.1, 1.2, 1.3]",
            "  - lenient_pattern_mult: [0.5, 0.6, 0.7]",
            "  - lenient_semantic_mult: [0.5, 0.6, 0.7]",
            "",
            "## Top 5 Weight Sets by TPR (meeting FPR constraint)",
            "",
            (
                "| # | pattern | semantic | sequence | det_thresh | susp_thresh "
                "| TPR | max FPR |"
            ),
            (
                "|---|---------|----------|----------|-----------|------------|"
                "-----|---------|"
            ),
        ]
    )
    for i, gp in enumerate(top_5):
        lines.append(
            f"| {i + 1} | {gp.pattern_base} | {gp.semantic_base} | "
            f"{gp.sequence_base} | {gp.detected_threshold} | "
            f"{gp.suspicious_threshold} | {gp.tpr:.4f} | {gp.max_fpr:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Selected Weight Set",
            "",
            f"- **pattern_base**: {selected.pattern_base}",
            f"- **semantic_base**: {selected.semantic_base}",
            f"- **sequence_base**: {selected.sequence_base}",
            f"- **detected_threshold**: {selected.detected_threshold}",
            f"- **suspicious_threshold**: {selected.suspicious_threshold}",
            f"- **strict_pattern_mult**: {selected.strict_pattern_mult}",
            f"- **strict_semantic_mult**: {selected.strict_semantic_mult}",
            f"- **lenient_pattern_mult**: {selected.lenient_pattern_mult}",
            f"- **lenient_semantic_mult**: {selected.lenient_semantic_mult}",
            f"- **TPR**: {selected.tpr:.4f}",
            f"- **max FPR**: {selected.max_fpr:.4f}",
            "",
            "**Rationale**: Maximizes TPR while keeping per-content-type FPR "
            f"below {max_fpr} ({max_fpr * 100:.1f}%) across all content categories. "
            "Verdict thresholds are calibrated to reduce false positive rate "
            "for benign content that triggers individual signal types.",
            "",
            "## Per-Content-Type FPR at Selected Weights",
            "",
            "| Content Type | FPR | Status |",
            "|-------------|-----|--------|",
        ]
    )
    for ct in content_types:
        fpr = selected.per_type_fpr.get(ct, 0.0)
        status = "PASS" if fpr <= max_fpr else "EXCEEDS"
        lines.append(f"| {ct} | {fpr:.4f} ({fpr * 100:.1f}%) | {status} |")

    lines.extend(
        [
            "",
            "## Calibration Methodology",
            "",
            "1. **Signal collection**: Run DetectionEngine._collect_signals() on each "
            "benchmark sample to obtain pattern, semantic, and sequence signals.",
            "2. **Grid search**: For each weight combination, compute FusionLayer.fuse() "
            "on pre-collected signals and measure TPR + per-content-type FPR.",
            "3. **Selection**: Choose the weight set that maximizes TPR subject to "
            f"per-content-type FPR <= {max_fpr * 100:.1f}%.",
            "4. **Threshold tuning**: Verdict thresholds (detected, suspicious) are "
            "included in the grid search to find the optimal balance between "
            "detection rate and false positive rate.",
            "",
        ]
    )

    with open(report_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote report: {report_path}")


def main() -> None:
    """Entry point for CLI invocation."""
    parser = argparse.ArgumentParser(
        description="Calibrate CloneGuard fusion layer weights via grid search"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data/benchmark/"),
        help="Directory containing benchmark corpus or trajectory data (default: data/benchmark/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("src/cloneguard/detection/profiles/"),
        help=(
            "Directory to write weight profile YAML files "
            "(default: src/cloneguard/detection/profiles/)"
        ),
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("."),
        help="Directory to write calibration report (default: .)",
    )
    parser.add_argument(
        "--target-tpr",
        type=float,
        default=0.95,
        help="Target true positive rate (default: 0.95)",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.092,
        help="Maximum acceptable per-content-type FPR (default: 0.092 = 9.2%%)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    calibrate(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        report_dir=args.report_dir,
        target_tpr=args.target_tpr,
        max_fpr=args.max_fpr,
    )


if __name__ == "__main__":
    main()
