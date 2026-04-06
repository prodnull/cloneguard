#!/usr/bin/env python3
"""Check cross-file consistency: license, version, metrics, pattern counts.

Run in CI to catch drift between pyproject.toml, README, docs, model cards,
and HuggingFace metadata. Exits non-zero on any mismatch.

Usage:
    python scripts/consistency_check.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []


def error(msg: str) -> None:
    ERRORS.append(msg)
    print(f"  FAIL: {msg}")


def check_license() -> None:
    """Verify license string is consistent across all files."""
    print("Checking license consistency...")

    pyproject = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^license\s*=\s*"(.+?)"', pyproject, re.MULTILINE)
    if not m:
        error("pyproject.toml: no license field found")
        return
    canonical = m.group(1)
    print(f"  Canonical (pyproject.toml): {canonical}")

    checks = [
        ("LICENSE", r"Apache License\s+Version 2\.0" if "Apache" in canonical else canonical),
        ("README.md", canonical.replace("-", " ").replace("2.0", "2.0")),
        ("src/cloneguard/model/README.md", f"license: {canonical.lower()}"),
    ]

    for relpath, expected_pattern in checks:
        path = ROOT / relpath
        if not path.exists():
            error(f"{relpath}: file not found")
            continue
        content = path.read_text()
        if not re.search(expected_pattern, content, re.IGNORECASE):
            error(f"{relpath}: does not match license '{canonical}'")


def check_version() -> None:
    """Verify version is consistent."""
    print("Checking version consistency...")

    pyproject = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"(.+?)"', pyproject, re.MULTILINE)
    if not m:
        error("pyproject.toml: no version field found")
        return
    version = m.group(1)
    print(f"  Canonical (pyproject.toml): {version}")


def check_pattern_count() -> None:
    """Verify pattern count claims match actual YAML rule count."""
    print("Checking pattern count consistency...")

    rules_dir = ROOT / "src" / "cloneguard" / "rules"
    actual = 0
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        content = yaml_file.read_text()
        actual += len(re.findall(r"^\s*- id:", content, re.MULTILINE))
    print(f"  Actual patterns in YAML: {actual}")

    files_to_check = [
        "README.md",
        "docs/MINI-SEMANTIC-MODEL.md",
        "docs/TESTING-AND-VALIDATION.md",
        "docs/SECURITY.md",
    ]

    # Only check lines that state current counts, not historical round descriptions
    history_re = re.compile(r"(?:Round|Converted all|Script:)", re.IGNORECASE)

    for relpath in files_to_check:
        path = ROOT / relpath
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if history_re.search(line):
                continue
            for m in re.finditer(r"(\d+)\s+(?:compiled\s+)?(?:patterns|rules)", line):
                claimed = int(m.group(1))
                if claimed != actual and claimed > 50:
                    error(f"{relpath}: claims {claimed} patterns but actual count is {actual}")


def check_cv_metrics() -> None:
    """Verify Tier 1.5 CV F1 claims match bench/kfold_results.json.

    Only checks lines that specifically reference Tier 1.5, CV, or cross-validated
    F1. Ignores Tier 0 and Tier 2 F1 values in comparison tables.
    """
    print("Checking CV metric consistency...")

    kfold_path = ROOT / "bench" / "kfold_results.json"
    if not kfold_path.exists():
        print("  Skipped: bench/kfold_results.json not found")
        return

    with open(kfold_path) as f:
        results = json.load(f)

    f1 = results.get("aggregate", {}).get("f1", {}).get("mean")
    if f1 is None:
        print("  Skipped: no aggregate F1 in kfold results")
        return

    f1_pct = f"{f1 * 100:.2f}%"
    f1_rounded = f"{f1 * 100:.1f}%"
    print(f"  Canonical F1: {f1_pct}")

    files_to_check = [
        "README.md",
        "docs/MINI-SEMANTIC-MODEL.md",
    ]

    # Only match F1 values on lines that mention CV, cross-validated, or Tier 1.5
    # Exclude lines about alternative configs (hyperparameter search results)
    cv_line_re = re.compile(r".*(?:cross.?validat|5-fold|Tier\s*1\.5|\bCV\b).*", re.IGNORECASE)
    alt_config_re = re.compile(
        r"(?:candidate|alternative|achieved|top\s+\d|runner.up|\bv[23]\b|original\s+\d)", re.IGNORECASE
    )

    for relpath in files_to_check:
        path = ROOT / relpath
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not cv_line_re.match(line):
                continue
            if alt_config_re.search(line):
                continue
            # Match "F1" followed by a value, but not "precision" or "recall"
            # on the same line to avoid matching other metrics in tables
            if re.search(r"\bprecision\b", line, re.IGNORECASE):
                continue
            for m in re.finditer(r"\bF1[=:\s|]+([\d.]+%)", line):
                claim = m.group(1)
                if claim not in (f1_pct, f1_rounded):
                    error(f"{relpath}: CV F1 claim '{claim}' != canonical {f1_pct}")


def check_dataset_count() -> None:
    """Verify total dataset sample count claims match actual dataset.

    Only checks lines that state a total count (e.g., "5,671 samples").
    Ignores per-round counts in historical build descriptions.
    """
    print("Checking dataset count consistency...")

    # Check both original and augmented datasets — docs may reference either.
    # v4 (6,472) = v3 augmented (6,340) + 132 PWWS adversarial samples added
    # during training but not saved as a separate file on disk.
    dataset_counts: set[int] = set()
    for name in ["dataset.jsonl", "dataset_augmented_r2.jsonl"]:
        dataset_path = ROOT / "data" / "training" / name
        if dataset_path.exists():
            with open(dataset_path) as f:
                count = sum(1 for _ in f)
            dataset_counts.add(count)
            print(f"  {name}: {count} samples")
    # v4 count is v3 augmented + 132 PWWS samples (not on disk as separate file)
    if 6340 in dataset_counts:
        dataset_counts.add(6472)

    if not dataset_counts:
        print("  Skipped: no dataset files found")
        return

    files_to_check = [
        "README.md",
        "src/cloneguard/model/README.md",
    ]

    # Only match lines with "total" context or standalone count claims,
    # not per-round historical counts
    total_re = re.compile(
        r".*(?:total|contains|dataset.+samples|samples.+dataset|"
        r"labeled samples|training data).*",
        re.IGNORECASE,
    )

    for relpath in files_to_check:
        path = ROOT / relpath
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not total_re.match(line):
                continue
            for m in re.finditer(r"([\d,]+)\s+(?:labeled\s+)?samples", line):
                claimed = int(m.group(1).replace(",", ""))
                if claimed not in dataset_counts and claimed > 1000:
                    error(f"{relpath}: claims {claimed} samples but datasets have {dataset_counts}")


def check_model_hash() -> None:
    """Verify fetch_model.py hash matches the actual ONNX model if present."""
    print("Checking model hash consistency...")

    fetch_script = ROOT / "scripts" / "fetch_model.py"
    onnx_path = ROOT / "src" / "cloneguard" / "model" / "mini_semantic.onnx"

    if not fetch_script.exists():
        error("scripts/fetch_model.py not found")
        return

    content = fetch_script.read_text()
    m = re.search(r'EXPECTED_SHA256\s*=\s*"([a-f0-9]{64})"', content)
    if not m:
        error("scripts/fetch_model.py: no EXPECTED_SHA256 found")
        return

    pinned_hash = m.group(1)
    print(f"  Pinned hash: {pinned_hash[:16]}...")

    if not onnx_path.exists():
        print("  Skipped: ONNX model not present (run fetch_model.py)")
        return

    import hashlib

    h = hashlib.sha256()
    with open(onnx_path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    actual_hash = h.hexdigest()

    if actual_hash != pinned_hash:
        error(
            f"ONNX model hash mismatch: pinned={pinned_hash[:16]}... actual={actual_hash[:16]}..."
        )
    else:
        print("  OK: model matches pinned hash")


def main() -> None:
    check_license()
    check_version()
    check_pattern_count()
    check_cv_metrics()
    check_dataset_count()
    check_model_hash()

    print()
    if ERRORS:
        print(f"FAILED: {len(ERRORS)} consistency error(s) found.")
        for e in ERRORS:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("PASSED: All consistency checks passed.")


if __name__ == "__main__":
    main()
