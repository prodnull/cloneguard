#!/usr/bin/env python3
"""K-fold cross-validation for the mini semantic model.

Trains k independent models on k-1 folds each, assesses on the held-out fold.
Reports per-fold and aggregate metrics with confidence intervals.

This answers: "Is our 98.97% full-dataset number inflated by overfitting,
or does the model genuinely generalize?"

Usage:
    python scripts/kfold_eval.py              # 5-fold (default)
    python scripts/kfold_eval.py --folds 10   # 10-fold
    python scripts/kfold_eval.py --epochs 4   # faster, less accurate
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold
from torch.utils.data import DataLoader

# Re-use dataset and model classes from training script
sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_mini_model import (
    BASE_MODEL,
    BATCH_SIZE,
    DATASET_PATH_DEFAULT,
    LR,
    MAX_SEQ_LEN,
    SEED,
    WARMUP_RATIO,
    InjectionDataset,
    PromptInjectionClassifier,
    load_dataset,
    select_device,
)
from transformers import AutoTokenizer, get_linear_schedule_with_warmup


def train_one_fold(
    train_texts: list[str],
    train_labels: list[int],
    val_texts: list[str],
    val_labels: list[int],
    tokenizer,
    device: torch.device,
    epochs: int,
    fold_num: int,
) -> dict:
    """Train a model on one fold and return metrics on the held-out set."""

    train_ds = InjectionDataset(train_texts, train_labels, tokenizer, MAX_SEQ_LEN)
    val_ds = InjectionDataset(val_texts, val_labels, tokenizer, MAX_SEQ_LEN)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)

    model = PromptInjectionClassifier(BASE_MODEL).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR)

    total_steps = epochs * len(train_loader)
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    # Train
    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        step = 0
        for batch in train_loader:
            ids = batch["input_ids"].to(device)
            mask = batch["attention_mask"].to(device)
            labels_b = batch["labels"].to(device)

            optimizer.zero_grad()
            logits, _ = model(ids, mask)
            loss = criterion(logits, labels_b)
            loss.backward()
            optimizer.step()
            scheduler.step()

            running_loss += loss.item()
            step += 1

        avg_loss = running_loss / step
        print(f"  Fold {fold_num} epoch {epoch}/{epochs}  train_loss={avg_loss:.4f}")

    # Assess on held-out fold
    model.train(False)
    all_preds = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for batch in val_loader:
            ids = batch["input_ids"].to(device)
            mask = batch["attention_mask"].to(device)
            labels_b = batch["labels"].to(device)
            logits, _ = model(ids, mask)
            probs = torch.softmax(logits, dim=1)
            preds = logits.argmax(dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels_b.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)
    all_probs = np.array(all_probs)

    acc = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)
    prec = precision_score(all_labels, all_preds)
    rec = recall_score(all_labels, all_preds)
    cm = confusion_matrix(all_labels, all_preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "fold": fold_num,
        "accuracy": acc,
        "f1": f1,
        "precision": prec,
        "recall": rec,
        "fpr": fpr,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "val_size": len(all_labels),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="K-fold cross-validation")
    parser.add_argument("--folds", type=int, default=5, help="Number of folds (default: 5)")
    parser.add_argument("--epochs", type=int, default=8, help="Epochs per fold (default: 8)")
    parser.add_argument(
        "--dataset", type=Path, default=DATASET_PATH_DEFAULT, help="Path to dataset JSONL"
    )
    args = parser.parse_args()

    k = args.folds
    epochs = args.epochs

    torch.manual_seed(SEED)
    np.random.seed(SEED)

    device = select_device()
    print(f"Device: {device}")
    print(f"K-fold cross-validation: {k} folds, {epochs} epochs each\n")

    # Load data
    texts, labels = load_dataset(args.dataset)
    texts_arr = np.array(texts)
    labels_arr = np.array(labels)
    n_mal = sum(labels)
    n_ben = len(labels) - n_mal
    print(f"Dataset: {len(texts)} samples ({n_mal} malicious, {n_ben} benign)")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=SEED)
    fold_results = []

    t0 = time.time()
    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(texts_arr, labels_arr), 1):
        print(f"\n{'=' * 60}")
        print(f"Fold {fold_idx}/{k}  (train={len(train_idx)}, val={len(val_idx)})")
        print(f"{'=' * 60}")

        train_texts = texts_arr[train_idx].tolist()
        train_labels = labels_arr[train_idx].tolist()
        val_texts = texts_arr[val_idx].tolist()
        val_labels = labels_arr[val_idx].tolist()

        result = train_one_fold(
            train_texts,
            train_labels,
            val_texts,
            val_labels,
            tokenizer,
            device,
            epochs,
            fold_idx,
        )
        fold_results.append(result)

        print(f"\n  Fold {fold_idx} results:")
        print(f"    Accuracy:  {result['accuracy']:.4f}")
        print(f"    F1:        {result['f1']:.4f}")
        print(f"    Precision: {result['precision']:.4f}")
        print(f"    Recall:    {result['recall']:.4f}")
        print(f"    FPR:       {result['fpr']:.4f}")
        tp, fp = result["tp"], result["fp"]
        tn, fn = result["tn"], result["fn"]
        print(f"    Confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    elapsed = time.time() - t0

    # Aggregate
    print(f"\n{'=' * 60}")
    print(f"AGGREGATE ({k}-fold cross-validation)")
    print(f"{'=' * 60}")

    metrics = ["accuracy", "f1", "precision", "recall", "fpr"]
    for m in metrics:
        values = [r[m] for r in fold_results]
        mean = np.mean(values)
        std = np.std(values, ddof=1)
        lo = mean - 1.96 * std / np.sqrt(k)
        hi = mean + 1.96 * std / np.sqrt(k)
        print(f"  {m:>10s}: {mean:.4f} +/- {std:.4f}  (95% CI: [{lo:.4f}, {hi:.4f}])")

    # Total confusion matrix
    total_tp = sum(r["tp"] for r in fold_results)
    total_fp = sum(r["fp"] for r in fold_results)
    total_tn = sum(r["tn"] for r in fold_results)
    total_fn = sum(r["fn"] for r in fold_results)
    print("\n  Aggregate confusion matrix:")
    print(f"    TP={total_tp}  FP={total_fp}")
    print(f"    FN={total_fn}  TN={total_tn}")

    # Comparison with reported numbers
    print(f"\n{'=' * 60}")
    print("OVERFITTING ASSESSMENT")
    print(f"{'=' * 60}")
    cv_f1 = np.mean([r["f1"] for r in fold_results])
    cv_acc = np.mean([r["accuracy"] for r in fold_results])
    print(f"  Cross-validated F1:       {cv_f1:.4f}")
    print(f"  Cross-validated accuracy: {cv_acc:.4f}")
    print("  Reported full-dataset F1: 0.9908")
    print("  Reported full-dataset acc: 0.9897")
    print("  Single-split val acc:     0.9528")
    print()
    if cv_f1 > 0.97:
        print("  VERDICT: Model generalizes well. Full-dataset numbers are slightly")
        print("  inflated by train-set inclusion, but the model is not memorizing.")
    elif cv_f1 > 0.94:
        print("  VERDICT: Model generalizes reasonably. Full-dataset numbers are")
        print("  somewhat inflated. Cross-validated metrics are the honest ones.")
    else:
        print("  VERDICT: Significant overfitting detected. Full-dataset numbers are")
        print("  unreliable. Cross-validated metrics should replace them in docs.")

    print(f"\nTotal time: {elapsed:.0f}s ({elapsed / 60:.1f} min)")

    # Save results
    results_dir = Path(__file__).resolve().parent.parent / "bench"
    results_dir.mkdir(exist_ok=True)
    results_path = results_dir / "kfold_results.json"
    with open(results_path, "w") as f:
        json.dump(
            {
                "folds": k,
                "epochs": epochs,
                "seed": SEED,
                "fold_results": fold_results,
                "aggregate": {
                    m: {
                        "mean": float(np.mean([r[m] for r in fold_results])),
                        "std": float(np.std([r[m] for r in fold_results], ddof=1)),
                    }
                    for m in metrics
                },
            },
            f,
            indent=2,
        )
    print(f"Results saved to {results_path}")


if __name__ == "__main__":
    main()
