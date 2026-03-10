#!/usr/bin/env python3
"""Download the ONNX model from HuggingFace with SHA-256 verification.

Usage:
    python scripts/fetch_model.py           # download if missing or corrupted
    python scripts/fetch_model.py --force   # re-download even if present
    python scripts/fetch_model.py --verify  # verify existing file only

The model is published at:
    https://huggingface.co/prodnull/minilm-prompt-injection-classifier

This script requires no dependencies beyond the Python standard library.
"""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.request
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent.parent / "src" / "cloneguard" / "model"
ONNX_PATH = MODEL_DIR / "mini_semantic.onnx"

# Pinned SHA-256 of the current production model (v4, adversarially hardened — FreeLB + PWWS).
# Update this hash after retraining: shasum -a 256 src/cloneguard/model/mini_semantic.onnx
EXPECTED_SHA256 = "e7fb93add94c4eb3c7e094bc3ce466573aad3ac7433fbab29aa19a694c40edcf"

# HuggingFace direct download URL (resolve endpoint, follows to CDN).
HF_REPO = "prodnull/minilm-prompt-injection-classifier"
HF_FILENAME = "mini_semantic.onnx"
DOWNLOAD_URL = f"https://huggingface.co/{HF_REPO}/resolve/main/{HF_FILENAME}"


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):  # 1 MB chunks
            h.update(chunk)
    return h.hexdigest()


def verify(path: Path) -> bool:
    """Verify the ONNX model exists and matches the pinned hash."""
    if not path.exists():
        print(f"MISSING: {path}")
        return False
    actual = sha256_file(path)
    if actual != EXPECTED_SHA256:
        print("HASH MISMATCH:")
        print(f"  expected: {EXPECTED_SHA256}")
        print(f"  actual:   {actual}")
        print(f"  file:     {path}")
        return False
    print(f"OK: {path}")
    print(f"  sha256: {actual}")
    return True


def download(path: Path) -> None:
    """Download the model from HuggingFace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {HF_FILENAME} from {HF_REPO} ...")

    # Authenticate if HF_TOKEN is set (required for gated repos).
    req = urllib.request.Request(DOWNLOAD_URL)
    hf_token = os.environ.get("HF_TOKEN", "")
    if hf_token:
        req.add_header("Authorization", f"Bearer {hf_token}")
    else:
        print("  (no HF_TOKEN set — will fail if repo is gated)")

    # Stream download with progress
    try:
        resp_ctx = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.code == 401 or e.code == 403:
            print(f"AUTH ERROR ({e.code}): Set HF_TOKEN environment variable.")
            print(
                "  The model repo is gated. Get a token at https://huggingface.co/settings/tokens"
            )
            sys.exit(1)
        raise
    with resp_ctx as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        h = hashlib.sha256()
        with open(path, "wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
                h.update(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1 << 20)
                    print(f"\r  {mb:.1f} MB ({pct}%)", end="", flush=True)
        print()

    actual = h.hexdigest()
    if actual != EXPECTED_SHA256:
        path.unlink()
        print("INTEGRITY FAILURE — downloaded file does not match pinned hash.")
        print(f"  expected: {EXPECTED_SHA256}")
        print(f"  actual:   {actual}")
        print("  The file has been deleted. This could indicate:")
        print("    - The HuggingFace repo was updated without updating this script")
        print("    - The download was corrupted in transit")
        print("    - The HuggingFace account was compromised")
        print("  To update the hash after a legitimate retrain:")
        print("    1. Retrain: python scripts/train_mini_model.py")
        print(f"    2. Upload: hf upload {HF_REPO} {path} {HF_FILENAME}")
        print("    3. Update EXPECTED_SHA256 in this script")
        sys.exit(1)

    print(f"  sha256: {actual} (verified)")
    print(f"  saved:  {path}")


def main() -> None:
    force = "--force" in sys.argv
    verify_only = "--verify" in sys.argv

    if verify_only:
        sys.exit(0 if verify(ONNX_PATH) else 1)

    if ONNX_PATH.exists() and not force:
        if verify(ONNX_PATH):
            print("Model already present and verified.")
            return
        print("Model exists but hash mismatch — re-downloading.")

    download(ONNX_PATH)


if __name__ == "__main__":
    main()
