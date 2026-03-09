#!/usr/bin/env python3
"""Hyperparameter sweep to reduce overfitting.

Tests combinations of epochs and dropout, reporting cross-validated metrics.
Identifies the configuration with the best CV F1 (not full-dataset F1).

Usage:
    python scripts/hyperparameter_sweep.py
"""

from __future__ import annotations

import json
import sys
import time
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
    BATCH_SIZE,
    DATASET_PATH,
    LR,
    MAX_SEQ_LEN,
    SEED,
    WARMUP_RATIO,
    InjectionDataset,
    load_dataset,
    select_device,
)

from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

K_FOLDS = 5

# Configurations to test
CONFIGS = [
    {"epochs": 8, "dropout": 0.1, "label": "baseline (8ep, 0.1do)"},
    {"epochs": 4, "dropout": 0.1, "label": "fewer epochs (4ep, 0.1do)"},
    {"epochs": 6, "dropout": 0.2, "label": "mid epochs + dropout (6ep, 0.2do)"},
    {"epochs": 4, "dropout": 0.2, "label": "fewer + dropout (4ep, 0.2do)"},
    {"epochs": 4, "dropout": 0.3, "label": "fewer + high dropout (4ep, 0.3do)"},
    {"epochs": 6, "dropout": 0.3, "label": "mid + high dropout (6ep, 0.3do)"},
]


class PromptInjectionClassifierCustom(nn.Module):
    """Same architecture but with configurable dropout."""

    def __init__(self, model_name: str, dropout: float):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)
        self.classifier = nn.Sequential(
            nn.Linear(384, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 2),
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
) -> dict:
    """Run k-fold CV for one configuration. Returns aggregate metrics."""

    skf = StratifiedKFold(n_splits=K_FOLDS, shuffle=True, random_state=SEED)
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

        model = PromptInjectionClassifierCustom(BASE_MODEL, dropout).to(device)
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(model.parameters(), lr=LR)
        total_steps = epochs * len(train_loader)
        warmup_steps = int(total_steps * WARMUP_RATIO)
        scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_steps)

        # Train
        for epoch in range(epochs):
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

        # Assess
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
            "precision": precision_score(y_true, y_pred),
            "recall": recall_score(y_true, y_pred),
        })

        print(f"    fold {fold_idx}: acc={fold_metrics[-1]['accuracy']:.4f}  f1={fold_metrics[-1]['f1']:.4f}")

    # Aggregate
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
    print(f"Dataset: {len(texts)} samples\n")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    all_results = []
    t0 = time.time()

    for i, cfg in enumerate(CONFIGS, 1):
        print(f"\n{'='*60}")
        print(f"Config {i}/{len(CONFIGS)}: {cfg['label']}")
        print(f"  epochs={cfg['epochs']}  dropout={cfg['dropout']}")
        print(f"{'='*60}")

        cfg_t0 = time.time()
        result = run_kfold(texts_arr, labels_arr, tokenizer, device, cfg["epochs"], cfg["dropout"])
        cfg_elapsed = time.time() - cfg_t0

        entry = {**cfg, "results": result, "time_s": cfg_elapsed}
        all_results.append(entry)

        print(f"\n  >> {cfg['label']}:")
        print(f"     F1:        {result['f1']['mean']:.4f} +/- {result['f1']['std']:.4f}")
        print(f"     Accuracy:  {result['accuracy']['mean']:.4f} +/- {result['accuracy']['std']:.4f}")
        print(f"     Precision: {result['precision']['mean']:.4f} +/- {result['precision']['std']:.4f}")
        print(f"     Recall:    {result['recall']['mean']:.4f} +/- {result['recall']['std']:.4f}")
        print(f"     Time:      {cfg_elapsed:.0f}s")

    elapsed = time.time() - t0

    # Summary table
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"{'Config':<40s} {'CV F1':>8s} {'CV Acc':>8s} {'CV Prec':>8s} {'CV Rec':>8s}")
    print("-" * 80)

    best = None
    for entry in all_results:
        r = entry["results"]
        f1_mean = r["f1"]["mean"]
        print(f"{entry['label']:<40s} {f1_mean:>8.4f} {r['accuracy']['mean']:>8.4f} "
              f"{r['precision']['mean']:>8.4f} {r['recall']['mean']:>8.4f}")
        if best is None or f1_mean > best["results"]["f1"]["mean"]:
            best = entry

    print(f"\nBest config: {best['label']}")
    print(f"  CV F1 = {best['results']['f1']['mean']:.4f}")
    print(f"\nTotal sweep time: {elapsed:.0f}s ({elapsed/60:.1f} min)")

    # Save
    results_dir = Path(__file__).resolve().parent.parent / "bench"
    results_dir.mkdir(exist_ok=True)
    results_path = results_dir / "hyperparameter_sweep.json"
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Results saved to {results_path}")


if __name__ == "__main__":
    main()
