"""Offline calibration pipeline for CloneGuard fusion layer weights.

Runs grid search over weight combinations and mode multipliers against
labeled trajectory data to find the optimal weight profile that maximizes
TPR while keeping per-content-type FPR below a threshold.

If the data directory is missing or empty, prints a warning and exits
cleanly with code 0 -- ships default uncalibrated weights.

Usage:
    python scripts/calibrate_fusion.py --help
    python scripts/calibrate_fusion.py --data-dir data/trajectories/
    python scripts/calibrate_fusion.py --target-tpr 0.95 --max-fpr 0.092
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

logger = logging.getLogger(__name__)

# Content type categories for per-type FPR analysis
CONTENT_TYPES = [
    "ci_config",
    "security_doc",
    "test_fixture",
    "mcp_tool_desc",
    "source_code",
    "other",
]

# File name patterns for content type classification
_CI_CONFIG_PATTERNS = {
    ".github/workflows/",
    ".gitlab-ci",
    "Jenkinsfile",
    "azure-pipelines",
    ".circleci/",
    ".travis.yml",
}
_SECURITY_DOC_PATTERNS = {
    "SECURITY",
    "security.md",
    "threat",
    "vulnerability",
    "cve-",
}
_TEST_FIXTURE_PATTERNS = {
    "test",
    "tests/",
    "fixtures/",
    "__tests__/",
    "testdata/",
    "spec/",
}
_MCP_TOOL_PATTERNS = {
    "mcp",
    "tool_desc",
    "tool_schema",
    "mcp_server",
}
_SOURCE_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".java",
    ".c",
    ".cpp",
    ".rb",
    ".sh",
}


def classify_content_type(file_path: str, content: str = "") -> str:
    """Classify a file into a content type category.

    Uses filename patterns and content heuristics to assign category.
    """
    path_lower = file_path.lower()

    for pattern in _CI_CONFIG_PATTERNS:
        if pattern.lower() in path_lower:
            return "ci_config"

    for pattern in _SECURITY_DOC_PATTERNS:
        if pattern.lower() in path_lower:
            return "security_doc"

    for pattern in _TEST_FIXTURE_PATTERNS:
        if pattern.lower() in path_lower:
            return "test_fixture"

    for pattern in _MCP_TOOL_PATTERNS:
        if pattern.lower() in path_lower:
            return "mcp_tool_desc"

    # Check file extension for source code
    suffix = Path(file_path).suffix.lower()
    if suffix in _SOURCE_CODE_EXTENSIONS:
        return "source_code"

    # Content heuristics as fallback
    if content:
        if "on:" in content and "jobs:" in content:
            return "ci_config"
        if "describe(" in content or "it(" in content or "def test_" in content:
            return "test_fixture"

    return "other"


@dataclass
class Sample:
    """A single labeled sample for calibration."""

    file_path: str
    content: str
    label: str  # "benign" | "malicious"
    content_type: str
    signals: list[Any] = field(default_factory=list)  # list[SignalResult] at runtime


@dataclass
class GridPoint:
    """A single point in the weight grid search."""

    pattern_base: float
    semantic_base: float
    sequence_base: float
    strict_pattern_mult: float = 1.2
    strict_semantic_mult: float = 1.3
    lenient_pattern_mult: float = 0.7
    lenient_semantic_mult: float = 0.7
    tpr: float = 0.0
    max_fpr: float = 0.0
    per_type_fpr: dict[str, float] = field(default_factory=dict)


def load_samples(data_dir: Path) -> list[Sample]:
    """Load labeled samples from the data directory.

    Supports JSONL files with fields: file_path, content, label.
    Falls back to Parquet files if available.
    """
    samples: list[Sample] = []

    # Try JSONL files first
    for jsonl_file in data_dir.glob("*.jsonl"):
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
                    content_type = classify_content_type(file_path, content)
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

    # Try Parquet files if no JSONL found
    if not samples:
        try:
            import pyarrow.parquet as pq  # type: ignore[import-untyped]

            for parquet_file in data_dir.glob("*.parquet"):
                table = pq.read_table(parquet_file)
                df = table.to_pydict()
                paths = df.get("file_path", df.get("path", []))
                contents = df.get("content", [])
                labels = df.get("label", ["benign"] * len(paths))

                for i in range(len(paths)):
                    file_path = str(paths[i]) if i < len(paths) else "unknown"
                    content = str(contents[i]) if i < len(contents) else ""
                    label = str(labels[i]) if i < len(labels) else "benign"
                    content_type = classify_content_type(file_path, content)
                    samples.append(
                        Sample(
                            file_path=file_path,
                            content=content,
                            label=label,
                            content_type=content_type,
                        )
                    )
        except ImportError:
            logger.info("pyarrow not available; cannot read parquet files")

    return samples


def build_weight_grid() -> list[GridPoint]:
    """Build the grid of weight combinations to search.

    Only includes combinations where base weights sum to 1.0 (within tolerance).
    """
    pattern_bases = [0.2, 0.3, 0.4, 0.5]
    semantic_bases = [0.2, 0.3, 0.4, 0.5]
    sequence_bases = [0.1, 0.15, 0.2, 0.3]
    strict_pattern_mults = [1.0, 1.1, 1.2, 1.3]
    strict_semantic_mults = [1.1, 1.2, 1.3, 1.5]
    lenient_pattern_mults = [0.6, 0.7, 0.8]
    lenient_semantic_mults = [0.6, 0.7, 0.8]

    grid: list[GridPoint] = []
    for pb, sb, sqb in itertools.product(pattern_bases, semantic_bases, sequence_bases):
        # Only evaluate combinations where sum == 1.0 (within tolerance)
        if abs(pb + sb + sqb - 1.0) > 0.01:
            continue
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
    )


def evaluate_grid_point(
    gp: GridPoint,
    samples: list[Sample],
    mode: Any = None,
) -> GridPoint:
    """Evaluate a single grid point against the sample set.

    Computes TPR and per-content-type FPR.
    """
    from cloneguard.detection.fusion import FusionLayer
    from cloneguard.detection.patterns import ScanMode

    if mode is None:
        mode = ScanMode.STANDARD
    profile = make_weight_profile(gp)
    layer = FusionLayer(profile)

    true_positives = 0
    total_malicious = 0
    false_positives_by_type: dict[str, int] = defaultdict(int)
    total_benign_by_type: dict[str, int] = defaultdict(int)

    for sample in samples:
        if sample.label == "malicious":
            total_malicious += 1
            result = layer.fuse(sample.signals, mode)
            if result.verdict in ("detected", "suspicious"):
                true_positives += 1
        else:
            total_benign_by_type[sample.content_type] += 1
            result = layer.fuse(sample.signals, mode)
            if result.verdict in ("detected", "suspicious"):
                false_positives_by_type[sample.content_type] += 1

    gp.tpr = true_positives / total_malicious if total_malicious > 0 else 0.0
    gp.per_type_fpr = {}
    max_fpr = 0.0
    for ct in CONTENT_TYPES:
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
    # Load samples
    if not data_dir.exists() or not any(data_dir.iterdir()):
        print(
            f"WARNING: Data directory {data_dir} does not exist or is empty. "
            "Using default uncalibrated weights.",
            file=sys.stderr,
        )
        return False

    samples = load_samples(data_dir)
    if not samples:
        print(
            f"WARNING: No labeled samples found in {data_dir}. "
            "Using default uncalibrated weights.",
            file=sys.stderr,
        )
        return False

    print(f"Loaded {len(samples)} samples from {data_dir}")

    # Dataset summary
    label_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        label_counts[s.label] += 1
        type_counts[s.content_type] += 1

    print(f"  Labels: {dict(label_counts)}")
    print(f"  Content types: {dict(type_counts)}")

    # Build grid and evaluate
    grid = build_weight_grid()
    print(f"Grid search: {len(grid)} combinations")

    results: list[GridPoint] = []
    for i, gp in enumerate(grid):
        gp = evaluate_grid_point(gp, samples)
        results.append(gp)
        if (i + 1) % 1000 == 0:
            print(f"  Evaluated {i + 1}/{len(grid)}...")

    # Filter valid results (FPR constraint met)
    valid = [r for r in results if r.max_fpr <= max_fpr]
    if not valid:
        print(
            f"WARNING: No weight combination meets max_fpr <= {max_fpr}. "
            "Relaxing constraint to find best available.",
            file=sys.stderr,
        )
        valid = sorted(results, key=lambda r: r.max_fpr)[:10]

    # Select best: maximize TPR among valid
    valid.sort(key=lambda r: (-r.tpr, r.max_fpr))
    selected = valid[0]

    print(f"\nSelected weights: TPR={selected.tpr:.4f}, max FPR={selected.max_fpr:.4f}")
    print(
        f"  pattern_base={selected.pattern_base}, "
        f"semantic_base={selected.semantic_base}, "
        f"sequence_base={selected.sequence_base}"
    )

    # Write calibrated profiles
    _write_profiles(selected, output_dir)

    # Write calibration report
    top_5 = valid[:5]
    _write_report(samples, grid, top_5, selected, report_dir, target_tpr, max_fpr)

    return True


def _write_profiles(selected: GridPoint, output_dir: Path) -> None:
    """Write calibrated weight profiles to YAML files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for agent_type in ["default", "claude-code", "gemini-cli", "cursor"]:
        profile_data: dict[str, Any] = {
            "version": "1",
            "agent_type": agent_type,
            "description": f"Calibrated fusion weights for {agent_type}",
            "weights": {
                "pattern_base": selected.pattern_base,
                "semantic_base": selected.semantic_base,
                "sequence_base": selected.sequence_base,
            },
            "mode_multipliers": {
                "strict": {
                    "pattern": selected.strict_pattern_mult,
                    "semantic": selected.strict_semantic_mult,
                    "sequence": 0.8,
                },
                "standard": {
                    "pattern": 1.0,
                    "semantic": 1.0,
                    "sequence": 1.0,
                },
                "lenient": {
                    "pattern": selected.lenient_pattern_mult,
                    "semantic": selected.lenient_semantic_mult,
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
) -> None:
    """Write calibration report in markdown format."""
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "calibration_report.md"

    label_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        label_counts[s.label] += 1
        type_counts[s.content_type] += 1

    lines: list[str] = [
        "# Fusion Weight Calibration Report",
        "",
        "## Dataset Summary",
        "",
        f"Total samples: {len(samples)}",
        "",
        "| Label | Count |",
        "|-------|-------|",
    ]
    for label, count in sorted(label_counts.items()):
        lines.append(f"| {label} | {count} |")

    lines.extend(
        [
            "",
            "| Content Type | Count |",
            "|-------------|-------|",
        ]
    )
    for ct in CONTENT_TYPES:
        lines.append(f"| {ct} | {type_counts.get(ct, 0)} |")

    lines.extend(
        [
            "",
            "## Grid Search Parameters",
            "",
            f"- Total grid points: {len(grid)}",
            f"- Target TPR: >= {target_tpr}",
            f"- Max FPR constraint: <= {max_fpr}",
            "- pattern_base: [0.2, 0.3, 0.4, 0.5]",
            "- semantic_base: [0.2, 0.3, 0.4, 0.5]",
            "- sequence_base: [0.1, 0.15, 0.2, 0.3]",
            "- strict_pattern_mult: [1.0, 1.1, 1.2, 1.3]",
            "- strict_semantic_mult: [1.1, 1.2, 1.3, 1.5]",
            "- lenient_pattern_mult: [0.6, 0.7, 0.8]",
            "- lenient_semantic_mult: [0.6, 0.7, 0.8]",
            "",
            "## Top 5 Weight Sets by TPR",
            "",
            "| # | pattern | semantic | sequence | TPR | max FPR |",
            "|---|---------|----------|----------|-----|---------|",
        ]
    )
    for i, gp in enumerate(top_5):
        lines.append(
            f"| {i + 1} | {gp.pattern_base} | {gp.semantic_base} | "
            f"{gp.sequence_base} | {gp.tpr:.4f} | {gp.max_fpr:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Selected Weight Set",
            "",
            f"- **pattern_base**: {selected.pattern_base}",
            f"- **semantic_base**: {selected.semantic_base}",
            f"- **sequence_base**: {selected.sequence_base}",
            f"- **strict_pattern_mult**: {selected.strict_pattern_mult}",
            f"- **strict_semantic_mult**: {selected.strict_semantic_mult}",
            f"- **lenient_pattern_mult**: {selected.lenient_pattern_mult}",
            f"- **lenient_semantic_mult**: {selected.lenient_semantic_mult}",
            f"- **TPR**: {selected.tpr:.4f}",
            f"- **max FPR**: {selected.max_fpr:.4f}",
            "",
            "**Rationale**: Maximizes TPR while keeping per-content-type FPR "
            f"below {max_fpr} ({max_fpr * 100:.1f}%) across all content categories.",
            "",
            "## Per-Content-Type FPR at Selected Weights",
            "",
            "| Content Type | FPR |",
            "|-------------|-----|",
        ]
    )
    for ct in CONTENT_TYPES:
        fpr = selected.per_type_fpr.get(ct, 0.0)
        lines.append(f"| {ct} | {fpr:.4f} |")

    lines.append("")

    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Wrote report: {report_path}")


def main() -> None:
    """Entry point for CLI invocation."""
    parser = argparse.ArgumentParser(
        description="Calibrate CloneGuard fusion layer weights via grid search"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data/trajectories/"),
        help="Directory containing labeled trajectory data (default: data/trajectories/)",
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
    calibrate(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        report_dir=args.report_dir,
        target_tpr=args.target_tpr,
        max_fpr=args.max_fpr,
    )


if __name__ == "__main__":
    main()
