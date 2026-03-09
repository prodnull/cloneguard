#!/usr/bin/env python3
"""Comprehensive hyperparameter sweep for mini semantic model.

Full grid search over epochs, dropout, learning rate, weight decay, and
hidden dimension. All evaluated via 5-fold stratified CV.

Usage:
    python scripts/comprehensive_sweep.py
"""

from __future__ import annotations

import json
import sys
import time
from itertools import product
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from torch.utils.data import DataLoader

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_mini_model import (
    BASE_MODEL,
    DATASET_PATH,
    MAX_SEQ_LEN,
    SEED,
    InjectionDataset,
    load_dataset,
    select_device,
)

from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

K_FOLDS = 5
BATCH_SIZE = 32

# ---------------------------------------------------------------------------
# Search grid
# ---------------------------------------------------------------------------
GRID = {
    "epochs":       [3, 4, 6, 8],
    "dropout":      [0.1, 0.2, 0.3, 0.4],
    "lr":           [2e-5, 3e-5, 5e-5],
    "weight_decay": [0.01, 0.05],
    "hidden_dim":   [64, 128],
}

# Total configs: 4 * 4 * 3 * 2 * 2 = 192
# At ~1.7 min/config with 2-fold screening: ~5.5 hours
# Phase 2 (top 15, 5-fold): ~40 min
# Total: ~6 hours

SCREENING_FOLDS = 2  # Fast screening
FULL_FOLDS = 5       # Full validation on top candidates
TOP_N = 15           # Number of candidates to promote to full CV


class FlexibleClassifier(nn.Module):
    def __init__(self, model_name: str, dropout: float, hidden_dim: int):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)
        self.classifier = nn.Sequential(
            nn.Linear(384, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 2),
        )

    def mean_pooling(self, model_output, attention_mask):
        token_embeddings = model_output.last_hidden_state
        mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        return torch.sum(token_embeddings * mask_expanded, dim=1) / torch.clamp(
            mask_expanded.sum(dim=1), min=1e-9,
        )

    def forward(self, input_ids, attention_mask):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = self.mean_pooling(outputs, attention_mask)
        return self.classifier(pooled)


def run_kfold(
    texts_arr: np.ndarray,
    labels_arr: np.ndarray,
    tokenizer,
    device: torch.device,
    epochs: int,
    dropout: float,
    lr: float,
    weight_decay: float,
    hidden_dim: int,
    n_folds: int,
    verbose: bool = False,
) -> dict:
    """Run k-fold CV for one configuration."""

    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=SEED)
    fold_metrics = []

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(texts_arr, labels_arr), 1):
        train_texts = texts_arr[train_idx].tolist()
        train_labels = labels_arr[train_idx].tolist()
        val_texts = texts_arr[val_idx].tolist()
        val_labels = labels_arr[val_idx].tolist()

        train_ds = InjectionDataset(train_texts, train_labels, tokenizer, MAX_SEQ_LEN)
        val_ds = InjectionDataset(val_texts, val_labels, tokenizer, MAX_SEQ_LEN)
        train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE)

        model = FlexibleClassifier(BASE_MODEL, dropout, hidden_dim).to(device)
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
        total_steps = epochs * len(train_loader)
        warmup_steps = int(total_steps * 0.10)
        scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

        for _ in range(epochs):
            model.train()
            for batch in train_loader:
                ids = batch["input_ids"].to(device)
                mask = batch["attention_mask"].to(device)
                lab = batch["labels"].to(device)
                optimizer.zero_grad()
                logits = model(ids, mask)
                loss = criterion(logits, lab)
                loss.backward()
                optimizer.step()
                scheduler.step()

        model.train(False)
        all_preds, all_labels_list = [], []
        with torch.no_grad():
            for batch in val_loader:
                ids = batch["input_ids"].to(device)
                mask = batch["attention_mask"].to(device)
                lab = batch["labels"].to(device)
                logits = model(ids, mask)
                all_preds.extend(logits.argmax(dim=1).cpu().numpy())
                all_labels_list.extend(lab.cpu().numpy())

        y_true = np.array(all_labels_list)
        y_pred = np.array(all_preds)
        fold_metrics.append({
            "accuracy": accuracy_score(y_true, y_pred),
            "f1": f1_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
        })

        if verbose:
            print(f"    fold {fold_idx}: f1={fold_metrics[-1]['f1']:.4f}")

    result = {}
    for metric in ["accuracy", "f1", "precision", "recall"]:
        values = [fm[metric] for fm in fold_metrics]
        result[metric] = {"mean": float(np.mean(values)), "std": float(np.std(values, ddof=1))}
    return result


def main() -> None:
    torch.manual_seed(SEED)
    np.random.seed(SEED)
    device = select_device()
    print(f"Device: {device}")

    texts, labels = load_dataset(DATASET_PATH)
    texts_arr = np.array(texts)
    labels_arr = np.array(labels)
    print(f"Dataset: {len(texts)} samples ({sum(labels)} mal, {len(labels)-sum(labels)} ben)\n")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    # Generate all configs
    keys = list(GRID.keys())
    all_configs = []
    for values in product(*GRID.values()):
        all_configs.append(dict(zip(keys, values)))

    total = len(all_configs)
    print(f"Total configurations: {total}")
    print(f"Phase 1: {SCREENING_FOLDS}-fold screening on all {total} configs")
    print(f"Phase 2: {FULL_FOLDS}-fold full CV on top {TOP_N} candidates\n")

    # Phase 1: Screening
    print(f"{'='*70}")
    print(f"PHASE 1: SCREENING ({SCREENING_FOLDS}-fold CV)")
    print(f"{'='*70}")

    screening_results = []
    t0 = time.time()

    for i, cfg in enumerate(all_configs, 1):
        cfg_label = (f"ep={cfg['epochs']} do={cfg['dropout']} "
                     f"lr={cfg['lr']:.0e} wd={cfg['weight_decay']} hd={cfg['hidden_dim']}")

        result = run_kfold(
            texts_arr, labels_arr, tokenizer, device,
            cfg["epochs"], cfg["dropout"], cfg["lr"],
            cfg["weight_decay"], cfg["hidden_dim"],
            n_folds=SCREENING_FOLDS,
        )

        screening_results.append({"config": cfg, "results": result})
        f1_mean = result["f1"]["mean"]

        elapsed = time.time() - t0
        eta = (elapsed / i) * (total - i)
        print(f"  [{i:3d}/{total}] F1={f1_mean:.4f}  {cfg_label}  "
              f"({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)")

    # Rank by CV F1
    screening_results.sort(key=lambda x: x["results"]["f1"]["mean"], reverse=True)

    print(f"\nPhase 1 complete in {time.time()-t0:.0f}s")
    print(f"\nTop {TOP_N} screening results:")
    print(f"{'Rank':>4s}  {'CV F1':>7s}  {'Config'}")
    print("-" * 70)
    for rank, sr in enumerate(screening_results[:TOP_N], 1):
        cfg = sr["config"]
        f1 = sr["results"]["f1"]["mean"]
        print(f"  {rank:2d}.  {f1:.4f}  ep={cfg['epochs']} do={cfg['dropout']} "
              f"lr={cfg['lr']:.0e} wd={cfg['weight_decay']} hd={cfg['hidden_dim']}")

    # Phase 2: Full CV on top candidates
    print(f"\n{'='*70}")
    print(f"PHASE 2: FULL CV ({FULL_FOLDS}-fold) on top {TOP_N}")
    print(f"{'='*70}")

    full_results = []
    t1 = time.time()

    for i, sr in enumerate(screening_results[:TOP_N], 1):
        cfg = sr["config"]
        cfg_label = (f"ep={cfg['epochs']} do={cfg['dropout']} "
                     f"lr={cfg['lr']:.0e} wd={cfg['weight_decay']} hd={cfg['hidden_dim']}")

        print(f"\n  Candidate {i}/{TOP_N}: {cfg_label}")

        result = run_kfold(
            texts_arr, labels_arr, tokenizer, device,
            cfg["epochs"], cfg["dropout"], cfg["lr"],
            cfg["weight_decay"], cfg["hidden_dim"],
            n_folds=FULL_FOLDS,
            verbose=True,
        )

        full_results.append({"config": cfg, "results": result})
        r = result
        print(f"  >> F1={r['f1']['mean']:.4f}+/-{r['f1']['std']:.4f}  "
              f"Acc={r['accuracy']['mean']:.4f}  "
              f"Prec={r['precision']['mean']:.4f}  "
              f"Rec={r['recall']['mean']:.4f}")

    # Final ranking
    full_results.sort(key=lambda x: x["results"]["f1"]["mean"], reverse=True)

    total_elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"FINAL RANKING (5-fold CV)")
    print(f"{'='*70}")
    print(f"{'Rank':>4s}  {'CV F1':>12s}  {'CV Acc':>8s}  {'CV Prec':>8s}  {'CV Rec':>8s}  Config")
    print("-" * 95)

    for rank, fr in enumerate(full_results, 1):
        cfg = fr["config"]
        r = fr["results"]
        f1_str = f"{r['f1']['mean']:.4f}+/-{r['f1']['std']:.4f}"
        print(f"  {rank:2d}.  {f1_str:>12s}  {r['accuracy']['mean']:>8.4f}  "
              f"{r['precision']['mean']:>8.4f}  {r['recall']['mean']:>8.4f}  "
              f"ep={cfg['epochs']} do={cfg['dropout']} lr={cfg['lr']:.0e} "
              f"wd={cfg['weight_decay']} hd={cfg['hidden_dim']}")

    best = full_results[0]
    baseline_f1 = 0.9579  # From our previous kfold run
    best_f1 = best["results"]["f1"]["mean"]

    print(f"\n{'='*70}")
    print(f"RECOMMENDATION")
    print(f"{'='*70}")
    print(f"  Best config: ep={best['config']['epochs']} do={best['config']['dropout']} "
          f"lr={best['config']['lr']:.0e} wd={best['config']['weight_decay']} "
          f"hd={best['config']['hidden_dim']}")
    print(f"  Best CV F1:     {best_f1:.4f}")
    print(f"  Baseline CV F1: {baseline_f1:.4f}")
    print(f"  Improvement:    {(best_f1 - baseline_f1)*100:+.2f}pp")

    if best_f1 > baseline_f1 + 0.005:
        print(f"\n  Meaningful improvement found. Retrain with best config.")
    elif best_f1 > baseline_f1:
        print(f"\n  Marginal improvement. Consider whether the complexity is worth it.")
    else:
        print(f"\n  No improvement over baseline. Current config is already near-optimal for this data.")

    print(f"\nTotal sweep time: {total_elapsed:.0f}s ({total_elapsed/3600:.1f} hours)")

    # Save
    results_dir = Path(__file__).resolve().parent.parent / "bench"
    results_dir.mkdir(exist_ok=True)
    results_path = results_dir / "comprehensive_sweep.json"
    with open(results_path, "w") as f:
        json.dump({
            "grid": GRID,
            "total_configs": total,
            "screening_folds": SCREENING_FOLDS,
            "full_folds": FULL_FOLDS,
            "top_n": TOP_N,
            "screening_top15": [
                {"config": sr["config"], "screening_f1": sr["results"]["f1"]["mean"]}
                for sr in screening_results[:TOP_N]
            ],
            "full_results": full_results,
            "best": best,
            "baseline_cv_f1": baseline_f1,
        }, f, indent=2)
    print(f"Results saved to {results_path}")


if __name__ == "__main__":
    main()
