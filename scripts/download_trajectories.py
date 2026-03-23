#!/usr/bin/env python3
"""Download trajectory datasets from HuggingFace for benign baseline mining.

Downloads:
  - SWE-bench/SWE-smith-trajectories (splits: tool, xml, ticks)
  - nebius/SWE-agent-trajectories (split: train)
  - nebius/SWE-rebench-openhands-trajectories (split: train)

Saves as parquet to data/trajectories/<dataset>/<split>.parquet
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from datasets import load_dataset

PROJ_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = PROJ_ROOT / "data" / "trajectories"

DATASETS = [
    {
        "repo": "SWE-bench/SWE-smith-trajectories",
        "splits": ["tool", "xml", "ticks"],
        "subdir": "swe-smith",
    },
    {
        "repo": "nebius/SWE-agent-trajectories",
        "splits": ["train"],
        "subdir": "nebius-sweagent",
    },
    {
        "repo": "nebius/SWE-rebench-openhands-trajectories",
        "splits": ["train"],
        "subdir": "openhands",
    },
]


def download_all() -> None:
    for ds_info in DATASETS:
        repo = ds_info["repo"]
        subdir = OUT_DIR / ds_info["subdir"]
        subdir.mkdir(parents=True, exist_ok=True)

        for split in ds_info["splits"]:
            out_path = subdir / f"{split}.parquet"
            if out_path.exists():
                print(f"[skip] {out_path} already exists")
                continue

            print(f"[download] {repo} split={split} ...")
            t0 = time.time()
            ds = load_dataset(repo, split=split)
            elapsed = time.time() - t0
            print(f"  loaded {len(ds)} rows in {elapsed:.1f}s")

            ds.to_parquet(str(out_path))
            size_mb = out_path.stat().st_size / 1e6
            print(f"  saved {out_path} ({size_mb:.1f} MB)")

    print("\n[done] All datasets downloaded.")
    # Summary
    total_rows = 0
    for ds_info in DATASETS:
        subdir = OUT_DIR / ds_info["subdir"]
        for split in ds_info["splits"]:
            out_path = subdir / f"{split}.parquet"
            if out_path.exists():
                ds = load_dataset("parquet", data_files=str(out_path), split="train")
                total_rows += len(ds)
                print(f"  {out_path.name}: {len(ds)} rows")
    print(f"\nTotal trajectories: {total_rows}")


if __name__ == "__main__":
    download_all()
