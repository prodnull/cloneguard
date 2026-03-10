"""Fit Mahalanobis anomaly detector on v4 ONNX CLS embeddings.

Loads the dual-output v4 ONNX model, extracts CLS embeddings from the final
augmented training dataset, fits per-class Gaussians, calibrates the threshold
at 5% FPR on the 234-sample benign eval set, and saves parameters to
src/cloneguard/model/mahalanobis_params.npz.

Usage:
    .venv/bin/python scripts/fit_mahalanobis.py \
        --dataset data/training/dataset_v4_r2.jsonl \
        --benign-eval data/benchmark/benign_eval_751.json \
        --output src/cloneguard/model/mahalanobis_params.npz
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np

# Resolve project root so imports work regardless of CWD.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _load_onnx_session(model_path: Path):  # type: ignore[return]
    try:
        import onnxruntime as ort  # type: ignore[import-untyped]

        session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        return session
    except ImportError:
        logger.error("onnxruntime not installed. Run: pip install onnxruntime")
        sys.exit(1)


def _tokenize(tokenizer, texts: list[str], max_length: int = 256) -> dict:
    return tokenizer(
        texts,
        return_tensors="np",
        truncation=True,
        max_length=max_length,
        padding="max_length",
    )


def _extract_cls_embeddings(
    session, tokenizer, texts: list[str], batch_size: int = 32
) -> np.ndarray:
    """Extract CLS embeddings (output index 1) from the dual-output ONNX model."""
    all_embeddings: list[np.ndarray] = []
    n = len(texts)

    for start in range(0, n, batch_size):
        batch = texts[start : start + batch_size]
        enc = _tokenize(tokenizer, batch)
        outputs = session.run(
            None,
            {
                "input_ids": enc["input_ids"],
                "attention_mask": enc["attention_mask"],
            },
        )
        if len(outputs) < 2:
            logger.error(
                "Model only has %d outputs. Expected dual-output v4 ONNX "
                "(logits + cls_embedding). Is this the right model?",
                len(outputs),
            )
            sys.exit(1)
        cls_batch = outputs[1]  # shape (batch, 384)
        all_embeddings.append(cls_batch)

        if (start // batch_size) % 10 == 0:
            pct = min(start + batch_size, n) / n * 100
            print(
                f"  Extracting embeddings... {pct:.0f}% ({min(start + batch_size, n)}/{n})",
                end="\r",
                flush=True,
            )

    print()  # newline after progress
    return np.concatenate(all_embeddings, axis=0)


def _load_training_dataset(path: Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sample = json.loads(line)
            texts.append(sample["text"])
            labels.append(int(sample["label"]))
    return texts, labels


def _load_benign_eval(path: Path) -> list[str]:
    with open(path) as f:
        data = json.load(f)
    # Support both list-of-dicts and list-of-strings.
    if data and isinstance(data[0], dict):
        return [item["text"] for item in data]
    return list(data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fit Mahalanobis detector on v4 ONNX CLS embeddings"
    )
    parser.add_argument("--dataset", required=True, type=Path, help="Training dataset .jsonl")
    parser.add_argument(
        "--benign-eval",
        required=True,
        type=Path,
        help="Benign eval .json for threshold calibration",
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="Output .npz path for fitted parameters"
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=_ROOT / "src" / "cloneguard" / "model" / "mini_semantic.onnx",
        help="Path to v4 dual-output ONNX model",
    )
    parser.add_argument(
        "--target-fpr", type=float, default=0.05, help="Target FPR for threshold calibration"
    )
    parser.add_argument(
        "--batch-size", type=int, default=32, help="Batch size for embedding extraction"
    )
    args = parser.parse_args()

    # Validate inputs.
    if not args.dataset.exists():
        logger.error("Dataset not found: %s", args.dataset)
        sys.exit(1)
    if not args.benign_eval.exists():
        logger.error("Benign eval file not found: %s", args.benign_eval)
        sys.exit(1)
    if not args.model.exists():
        logger.error("ONNX model not found: %s", args.model)
        sys.exit(1)

    print("\nFitting Mahalanobis detector on v4 ONNX model")
    print(f"  Dataset:     {args.dataset}")
    print(f"  Benign eval: {args.benign_eval}")
    print(f"  ONNX model:  {args.model}")
    print(f"  Output:      {args.output}")
    print(f"  Target FPR:  {args.target_fpr:.1%}")

    # Load model and tokenizer.
    print("\n[1/5] Loading ONNX model and tokenizer...")
    session = _load_onnx_session(args.model)
    model_dir = args.model.parent
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
    output_names = [o.name for o in session.get_outputs()]
    print(f"  ONNX outputs: {output_names}")

    # Load training data.
    print("\n[2/5] Loading training dataset...")
    texts, labels = _load_training_dataset(args.dataset)
    label_arr = np.array(labels)
    class0 = int((label_arr == 0).sum())
    class1 = int((label_arr == 1).sum())
    print(f"  Total: {len(texts)} samples (class 0 benign: {class0}, class 1 malicious: {class1})")

    # Extract training CLS embeddings.
    print("\n[3/5] Extracting CLS embeddings from training set...")
    train_embeddings = _extract_cls_embeddings(
        session, tokenizer, texts, batch_size=args.batch_size
    )
    print(f"  Training embeddings shape: {train_embeddings.shape}")

    # Fit per-class Gaussians.
    print("\n[4/5] Fitting per-class Gaussians...")
    from cloneguard.mahalanobis import MahalanobisDetector

    detector = MahalanobisDetector()
    detector.fit(train_embeddings, label_arr)
    print(f"  Fitted {len(detector.class_labels)} classes: {list(detector.class_labels)}")

    # Load benign eval, extract embeddings, calibrate threshold.
    print("\n[5/5] Calibrating threshold on benign eval set...")
    benign_texts = _load_benign_eval(args.benign_eval)
    print(f"  Benign eval: {len(benign_texts)} samples")
    benign_embeddings = _extract_cls_embeddings(
        session, tokenizer, benign_texts, batch_size=args.batch_size
    )
    threshold = detector.fit_threshold(benign_embeddings, target_fpr=args.target_fpr)

    # Report scores on training data for sanity check.
    print("\n--- Sanity check: score distribution on training set ---")
    benign_scores = np.array([detector.score(e) for e in train_embeddings[label_arr == 0][:200]])
    malicious_scores = np.array([detector.score(e) for e in train_embeddings[label_arr == 1][:200]])
    print(
        f"  Benign  scores: mean={benign_scores.mean():.4f}, std={benign_scores.std():.4f}, "
        f"p95={np.percentile(benign_scores, 95):.4f}"
    )
    print(
        f"  Malicious scores: mean={malicious_scores.mean():.4f}, "
        f"std={malicious_scores.std():.4f}, "
        f"p95={np.percentile(malicious_scores, 95):.4f}"
    )
    print(f"  Threshold: {threshold:.4f}")

    # Save parameters.
    detector.save(args.output)
    print(f"\nSaved Mahalanobis parameters to {args.output}")

    # Verify load round-trip.
    loaded = MahalanobisDetector.load(args.output)
    test_vec = train_embeddings[0]
    orig_score = detector.score(test_vec)
    load_score = loaded.score(test_vec)
    diff = abs(orig_score - load_score)
    status = "OK" if diff < 1e-5 else "WARN"
    print(f"Save/load round-trip verification: score diff = {diff:.2e} {status}")
    print("\nDone. Mahalanobis detector ready for integration into scan pipeline.")


if __name__ == "__main__":
    main()
