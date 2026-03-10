#!/usr/bin/env python3
"""Transferability experiment: adversarial examples against MiniLM scored on DeBERTa proxy.

Run in .venv-transfer/ environment. See .planning/phases/01-transferability-gate/ for methodology.

Purpose
-------
Generate adversarial examples that fool MiniLM ONNX (CloneGuard Tier 1.5) using:
  - PWWS (Probability Weighted Word Saliency) — no TensorFlow dependency
  - TextFooler-BERTScore — USE constraint replaced with BERTScore (no TensorFlow/USE)

Score each successful adversarial example against ProtectAI/deberta-v3-base-prompt-injection-v2.
Transfer status = True when DeBERTa classifies the adversarial text as SAFE (attack transfers).

Gate threshold: transfer_rate > 0.40 → pivot; ≤ 0.40 → proceed to Phase 2.

Usage
-----
  .venv-transfer/bin/python scripts/transfer_experiment.py --dry-run --limit 3
  .venv-transfer/bin/python scripts/transfer_experiment.py \
    --output docs/results/transfer-experiment-YYYY-MM-DD.json
  .venv-transfer/bin/python scripts/transfer_experiment.py --pwws-only
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Path setup — must be before cloneguard imports
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from cloneguard.mini_semantic import MiniSemanticClassifier  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MALICIOUS_CORPUS = _REPO_ROOT / "data/benchmark/malicious_corpus.json"
RESULTS_DIR = _REPO_ROOT / "docs/results"

# DeBERTa id2label verified on 2026-03-10: {0: 'SAFE', 1: 'INJECTION'}
# Loaded dynamically at startup — not hard-coded here
_DEBERTA_MODEL_ID = "ProtectAI/deberta-v3-base-prompt-injection-v2"

# Wilson 95% CI z-value (z_{0.975})
_Z_95 = 1.959963985


# ---------------------------------------------------------------------------
# ONNX ModelWrapper for TextAttack
# ---------------------------------------------------------------------------


class MiniLMOnnxWrapper:
    """TextAttack ModelWrapper wrapping the MiniLM ONNX classifier.

    Implements the __call__ interface expected by TextAttack's attack recipes:
    input: list[str], output: np.ndarray of shape [batch, 2]
      col 0 = P(benign/SAFE), col 1 = P(malicious)

    References the raw inference pattern from scripts/adversarial_benchmark.py
    (_score_raw) to bypass classify() thresholds and sliding window.
    """

    def __init__(self, classifier: MiniSemanticClassifier) -> None:
        # TextAttack ModelWrapper protocol requires self.model attribute
        self.model = classifier
        self.tokenizer = classifier._tokenizer

    def __call__(self, text_inputs: list[str]) -> np.ndarray:  # type: ignore[override]
        results = []
        for text in text_inputs:
            inputs = self.tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=256,
                padding="max_length",
            )
            logits = self.model._session.run(
                None,
                {
                    "input_ids": inputs["input_ids"],
                    "attention_mask": inputs["attention_mask"],
                },
            )[0][0]
            exp_logits = np.exp(logits - logits.max())  # numerically stable softmax
            probs = exp_logits / exp_logits.sum()
            results.append(probs)  # [p_benign, p_malicious]
        return np.array(results, dtype=np.float32)


# ---------------------------------------------------------------------------
# DeBERTa proxy
# ---------------------------------------------------------------------------


def load_deberta_pipeline() -> tuple[Any, dict[int, str]]:
    """Load ProtectAI DeBERTa proxy pipeline and return (pipeline, id2label).

    id2label is read from model config — not hard-coded — so any future
    label changes in the upstream model are caught automatically.
    """
    import torch
    from transformers import AutoModelForSequenceClassification, pipeline

    model = AutoModelForSequenceClassification.from_pretrained(_DEBERTA_MODEL_ID)
    id2label: dict[int, str] = {int(k): v for k, v in model.config.id2label.items()}
    print(f"DeBERTa id2label: {id2label}", file=sys.stderr)

    pipe = pipeline(
        "text-classification",
        model=_DEBERTA_MODEL_ID,
        truncation=True,
        max_length=512,
        device=torch.device("cpu"),
    )
    return pipe, id2label


def score_deberta(
    pipe: Any,
    id2label: dict[int, str],
    text: str,
) -> dict[str, Any]:
    """Score a text sample with the DeBERTa proxy pipeline.

    Returns: {"label": str, "score": float, "is_injection": bool}
    is_injection=True means DeBERTa flagged the text as an injection attempt.
    transfer=True means is_injection=False (DeBERTa was fooled — attack transferred).
    """
    result = pipe(text)[0]
    label: str = result["label"]
    score: float = float(result["score"])
    # Determine injection label name from id2label
    injection_labels = {v for k, v in id2label.items() if k == 1}
    is_injection = label in injection_labels
    return {"label": label, "score": score, "is_injection": is_injection}


# ---------------------------------------------------------------------------
# TextFooler-BERTScore attack builder (no TensorFlow / no USE)
# ---------------------------------------------------------------------------


def build_textfooler_bertscore(model_wrapper: MiniLMOnnxWrapper) -> Any:
    """Build a TextFooler-style attack with BERTScore substituted for USE.

    Original TextFooler uses UniversalSentenceEncoder (TensorFlow) as the
    sentence-level semantic constraint. Here we substitute BERTScore (bert-base-uncased)
    to achieve a torch-native, TF-free equivalent.

    Retains all other TextFooler components:
    - WordSwapEmbedding(max_candidates=50) — counter-fitted PARAGRAM embeddings
    - WordEmbeddingDistance(min_cos_sim=0.5)
    - PartOfSpeech(allow_verb_noun_swap=True)
    - RepeatModification, StopwordModification
    - GreedyWordSwapWIR(wir_method="delete")
    """
    from textattack import Attack
    from textattack.constraints.grammaticality import PartOfSpeech
    from textattack.constraints.pre_transformation import (
        RepeatModification,
        StopwordModification,
    )
    from textattack.constraints.semantics import BERTScore, WordEmbeddingDistance
    from textattack.goal_functions import UntargetedClassification
    from textattack.search_methods import GreedyWordSwapWIR
    from textattack.transformations import WordSwapEmbedding

    transformation = WordSwapEmbedding(max_candidates=50)

    # TextFooler stopword list (verbatim from original paper implementation)
    stopwords = set(
        [
            "a",
            "about",
            "above",
            "across",
            "after",
            "afterwards",
            "again",
            "against",
            "ain",
            "all",
            "almost",
            "alone",
            "along",
            "already",
            "also",
            "although",
            "am",
            "among",
            "amongst",
            "an",
            "and",
            "another",
            "any",
            "anyhow",
            "anyone",
            "anything",
            "anyway",
            "anywhere",
            "are",
            "aren",
            "aren't",
            "around",
            "as",
            "at",
            "back",
            "been",
            "before",
            "beforehand",
            "behind",
            "being",
            "below",
            "beside",
            "besides",
            "between",
            "beyond",
            "both",
            "but",
            "by",
            "can",
            "cannot",
            "could",
            "couldn",
            "couldn't",
            "d",
            "didn",
            "didn't",
            "doesn",
            "doesn't",
            "don",
            "don't",
            "down",
            "due",
            "during",
            "either",
            "else",
            "elsewhere",
            "empty",
            "enough",
            "even",
            "ever",
            "everyone",
            "everything",
            "everywhere",
            "except",
            "first",
            "for",
            "former",
            "formerly",
            "from",
            "hadn",
            "hadn't",
            "hasn",
            "hasn't",
            "haven",
            "haven't",
            "he",
            "hence",
            "her",
            "here",
            "hereafter",
            "hereby",
            "herein",
            "hereupon",
            "hers",
            "herself",
            "him",
            "himself",
            "his",
            "how",
            "however",
            "hundred",
            "i",
            "if",
            "in",
            "indeed",
            "into",
            "is",
            "isn",
            "isn't",
            "it",
            "it's",
            "its",
            "itself",
            "just",
            "latter",
            "latterly",
            "least",
            "ll",
            "may",
            "me",
            "meanwhile",
            "mightn",
            "mightn't",
            "mine",
            "more",
            "moreover",
            "most",
            "mostly",
            "must",
            "mustn",
            "mustn't",
            "my",
            "myself",
            "namely",
            "needn",
            "needn't",
            "neither",
            "never",
            "nevertheless",
            "next",
            "no",
            "nobody",
            "none",
            "noone",
            "nor",
            "not",
            "nothing",
            "now",
            "nowhere",
            "o",
            "of",
            "off",
            "on",
            "once",
            "one",
            "only",
            "onto",
            "or",
            "other",
            "others",
            "otherwise",
            "our",
            "ours",
            "ourselves",
            "out",
            "over",
            "per",
            "please",
            "s",
            "same",
            "shan",
            "shan't",
            "she",
            "she's",
            "should've",
            "shouldn",
            "shouldn't",
            "somehow",
            "something",
            "sometime",
            "somewhere",
            "such",
            "t",
            "than",
            "that",
            "that'll",
            "the",
            "their",
            "theirs",
            "them",
            "themselves",
            "then",
            "thence",
            "there",
            "thereafter",
            "thereby",
            "therefore",
            "therein",
            "thereupon",
            "these",
            "they",
            "this",
            "those",
            "through",
            "throughout",
            "thru",
            "thus",
            "to",
            "too",
            "toward",
            "towards",
            "under",
            "unless",
            "until",
            "up",
            "upon",
            "used",
            "ve",
            "was",
            "wasn",
            "wasn't",
            "we",
            "were",
            "weren",
            "weren't",
            "what",
            "whatever",
            "when",
            "whence",
            "whenever",
            "where",
            "whereafter",
            "whereas",
            "whereby",
            "wherein",
            "whereupon",
            "wherever",
            "whether",
            "which",
            "while",
            "whither",
            "who",
            "whoever",
            "whole",
            "whom",
            "whose",
            "why",
            "with",
            "within",
            "without",
            "won",
            "won't",
            "would",
            "wouldn",
            "wouldn't",
            "y",
            "yet",
            "you",
            "you'd",
            "you'll",
            "you're",
            "you've",
            "your",
            "yours",
            "yourself",
            "yourselves",
        ]
    )

    constraints = [
        RepeatModification(),
        StopwordModification(stopwords=stopwords),
        WordEmbeddingDistance(min_cos_sim=0.5),
        PartOfSpeech(allow_verb_noun_swap=True),
        # BERTScore replaces USE: threshold 0.75 f1 is approximately equivalent
        # to the angular similarity threshold of 0.840845057 used in TextFooler.
        # Lower value acknowledges BERTScore and USE operate on different scales.
        BERTScore(
            min_bert_score=0.75,
            model_name="bert-base-uncased",
            score_type="f1",
            compare_against_original=True,
        ),
    ]

    goal_function = UntargetedClassification(model_wrapper)
    search_method = GreedyWordSwapWIR(wir_method="delete")

    return Attack(goal_function, constraints, transformation, search_method)


# ---------------------------------------------------------------------------
# Wilson 95% confidence interval
# ---------------------------------------------------------------------------


def wilson_ci_95(successes: int, total: int) -> tuple[float, float]:
    """Wilson score interval for a proportion at 95% confidence.

    From: Wilson (1927), "Probable inference, the law of succession, and
    statistical inference." JASA 22(158):209-212.
    """
    if total == 0:
        return (0.0, 0.0)
    p_hat = successes / total
    n = total
    z = _Z_95
    center = (p_hat + z * z / (2 * n)) / (1 + z * z / n)
    margin = z * ((p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) ** 0.5) / (1 + z * z / n)
    return (max(0.0, center - margin), min(1.0, center + margin))


# ---------------------------------------------------------------------------
# Core experiment runner
# ---------------------------------------------------------------------------


def run_attack(
    attack: Any,
    attack_name: str,
    dataset: list[tuple[str, int]],
    model_wrapper: MiniLMOnnxWrapper,
    deberta_pipe: Any,
    deberta_id2label: dict[int, str],
    limit: int | None = None,
) -> dict[str, Any]:
    """Run a single attack recipe against the dataset and score transfers.

    Returns a dict matching the 'pwws' or 'textfooler' schema in the output spec.
    """
    from textattack import AttackArgs, Attacker
    from textattack.attack_results import (
        FailedAttackResult,
        SkippedAttackResult,
        SuccessfulAttackResult,
    )
    from textattack.datasets import Dataset as TADataset

    samples = dataset[:limit] if limit is not None else dataset
    ta_dataset = TADataset(samples)

    attack_success_count = 0
    attack_fail_count = 0
    attack_skip_count = 0
    transfer_count = 0
    adversarial_examples: list[dict[str, Any]] = []

    # Raw scoring helper (bypasses classify() thresholds)
    def raw_score(text: str) -> float:
        inputs = model_wrapper.tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=256,
            padding="max_length",
        )
        logits = model_wrapper.model._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )[0][0]
        exp_l = np.exp(logits - logits.max())
        probs = exp_l / exp_l.sum()
        return float(probs[1])

    attack_args = AttackArgs(
        num_examples=len(samples),
        disable_stdout=True,
        silent=True,
    )
    attacker = Attacker(attack, ta_dataset, attack_args)

    t_start = time.time()
    for idx, result in enumerate(attacker.attack_dataset()):
        elapsed = time.time() - t_start
        print(
            f"\r{attack_name}: {idx + 1}/{len(samples)} samples | "
            f"{attack_success_count} successful | {elapsed:.0f}s elapsed",
            end="",
            file=sys.stderr,
        )

        if isinstance(result, SuccessfulAttackResult):
            attack_success_count += 1
            original_text = result.original_result.attacked_text.text
            adversarial_text = result.perturbed_result.attacked_text.text

            # Score the adversarial example against DeBERTa proxy
            deberta_result = score_deberta(deberta_pipe, deberta_id2label, adversarial_text)
            # Transfer = DeBERTa fails to detect injection in the adversarial text
            transferred = not deberta_result["is_injection"]
            if transferred:
                transfer_count += 1

            adversarial_examples.append(
                {
                    "original_text": original_text,
                    "adversarial_text": adversarial_text,
                    "minilm_original_score": raw_score(original_text),
                    "minilm_adversarial_score": raw_score(adversarial_text),
                    "deberta_label": deberta_result["label"],
                    "deberta_score": round(deberta_result["score"], 4),
                    "transferred": transferred,
                }
            )

        elif isinstance(result, FailedAttackResult):
            attack_fail_count += 1
        elif isinstance(result, SkippedAttackResult):
            attack_skip_count += 1

    print(file=sys.stderr)  # newline after progress line

    total_adversarial = attack_success_count
    ci_low, ci_high = wilson_ci_95(transfer_count, total_adversarial)

    return {
        "attack_success_count": attack_success_count,
        "attack_fail_count": attack_fail_count,
        "attack_skip_count": attack_skip_count,
        "adversarial_examples": adversarial_examples,
        "transfer_count": transfer_count,
        "transfer_rate": (
            round(transfer_count / total_adversarial, 4) if total_adversarial > 0 else 0.0
        ),
        "transfer_rate_ci_95": [round(ci_low, 4), round(ci_high, 4)],
    }


# ---------------------------------------------------------------------------
# Dataset construction
# ---------------------------------------------------------------------------


def build_dataset(
    corpus_path: Path,
    classifier: MiniSemanticClassifier,
    limit: int | None = None,
) -> tuple[list[tuple[str, int]], list[dict[str, Any]], int]:
    """Load malicious corpus and pre-filter samples MiniLM already misses.

    Returns (dataset, per_sample_metadata, skip_count).
    per_sample_metadata contains sample id/category for per_sample_results assembly.
    """

    def raw_score(text: str) -> float:
        inputs = classifier._tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=256,
            padding="max_length",
        )
        logits = classifier._session.run(
            None,
            {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            },
        )[0][0]
        exp_l = np.exp(logits - logits.max())
        probs = exp_l / exp_l.sum()
        return float(probs[1])

    with open(corpus_path) as f:
        corpus = json.load(f)

    if limit is not None:
        corpus = corpus[:limit]

    dataset: list[tuple[str, int]] = []
    metadata: list[dict[str, Any]] = []
    skip_count = 0

    print("Pre-filtering corpus (MiniLM raw score > 0.5 required)...", file=sys.stderr)
    for sample in corpus:
        score = raw_score(sample["payload"])
        if score <= 0.5:
            skip_count += 1
            print(
                f"  Skipping {sample['id']} ({sample['category']}): score={score:.3f}",
                file=sys.stderr,
            )
            continue
        dataset.append((sample["payload"], 1))  # label 1 = malicious
        metadata.append(
            {
                "sample_id": sample["id"],
                "category": sample["category"],
                "minilm_original_score": round(score, 4),
            }
        )

    print(
        f"Dataset: {len(dataset)} samples to attack ({skip_count} pre-misclassified, skipped)",
        file=sys.stderr,
    )
    return dataset, metadata, skip_count


# ---------------------------------------------------------------------------
# Per-sample results assembly
# ---------------------------------------------------------------------------


def assemble_per_sample_with_metadata(
    corpus_path: Path,
    attack_results: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Match adversarial examples back to corpus metadata by original text."""
    with open(corpus_path) as f:
        corpus = json.load(f)
    text_to_meta: dict[str, dict[str, Any]] = {
        s["payload"]: {"sample_id": s["id"], "category": s["category"]} for s in corpus
    }

    per_sample: list[dict[str, Any]] = []
    for attack_name, results in attack_results.items():
        if results is None:
            continue
        for example in results.get("adversarial_examples", []):
            meta = text_to_meta.get(example["original_text"], {})
            per_sample.append(
                {
                    "sample_id": meta.get("sample_id", "unknown"),
                    "category": meta.get("category", "unknown"),
                    "attack_method": attack_name,
                    "original_text": example["original_text"],
                    "adversarial_text": example["adversarial_text"],
                    "minilm_original_score": example["minilm_original_score"],
                    "minilm_adversarial_score": example["minilm_adversarial_score"],
                    "deberta_label": example["deberta_label"],
                    "deberta_score": example["deberta_score"],
                    "transferred": example["transferred"],
                }
            )

    return per_sample


# ---------------------------------------------------------------------------
# Gate decision
# ---------------------------------------------------------------------------

GATE_THRESHOLD = 0.40


def make_gate_decision(
    attack_results: dict[str, dict[str, Any] | None],
) -> tuple[str, dict[str, Any], str]:
    """Compute combined transfer rate and gate decision.

    Returns (gate_decision, combined_stats, gate_note).
    Gate decision: 'proceed' if transfer_rate <= 0.40, else 'pivot'.
    """
    total_adversarial = 0
    total_transferred = 0
    for results in attack_results.values():
        if results is None:
            continue
        total_adversarial += results["attack_success_count"]
        total_transferred += results["transfer_count"]

    if total_adversarial == 0:
        rate = 0.0
        ci = (0.0, 0.0)
        gate = "insufficient_data"
        note = "No adversarial examples generated — cannot evaluate gate"
    else:
        rate = total_transferred / total_adversarial
        ci = wilson_ci_95(total_transferred, total_adversarial)
        gate = "pivot" if rate > GATE_THRESHOLD else "proceed"
        direction = "above" if rate > GATE_THRESHOLD else "below"
        note = (
            f"Transfer rate {rate:.1%} [95% CI: {ci[0]:.1%}–{ci[1]:.1%}] "
            f"is {direction} the {GATE_THRESHOLD:.0%} threshold"
        )

    combined: dict[str, Any] = {
        "total_adversarial": total_adversarial,
        "total_transferred": total_transferred,
        "transfer_rate": round(rate, 4),
        "transfer_rate_ci_95": [round(ci[0], 4), round(ci[1], 4)],
    }
    return gate, combined, note


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CloneGuard transferability gate experiment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Process only first N corpus samples (for dry-run/testing)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run 5 samples with PWWS only, print JSON to stdout, do not write file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="PATH",
        help="Override output path (default: docs/results/transfer-experiment-YYYY-MM-DD.json)",
    )
    parser.add_argument(
        "--pwws-only",
        action="store_true",
        help="Skip TextFooler, run PWWS only (use if BERTScore issues arise)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    dry_run: bool = args.dry_run
    limit: int | None = args.limit
    pwws_only: bool = args.pwws_only or dry_run  # dry-run implies PWWS only

    if dry_run and limit is None:
        limit = 5

    # Determine output path
    if dry_run:
        output_path = None
    else:
        today = date.today().isoformat()
        default_output = RESULTS_DIR / f"transfer-experiment-{today}.json"
        output_path = Path(args.output) if args.output else default_output

    print("=" * 60, file=sys.stderr)
    print("CloneGuard Transferability Gate Experiment", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Corpus:      {MALICIOUS_CORPUS}", file=sys.stderr)
    print(f"  Limit:       {limit if limit else 'all'}", file=sys.stderr)
    print(f"  Mode:        {'dry-run (PWWS only, stdout)' if dry_run else 'full'}", file=sys.stderr)
    print(f"  PWWS only:   {pwws_only}", file=sys.stderr)
    if output_path:
        print(f"  Output:      {output_path}", file=sys.stderr)
    print(file=sys.stderr)

    # Load MiniLM classifier
    print("Loading MiniLM ONNX classifier...", file=sys.stderr)
    classifier = MiniSemanticClassifier()
    if not classifier.available:
        print(
            "ERROR: MiniLM ONNX model not available. Run scripts/fetch_model.py first.",
            file=sys.stderr,
        )
        sys.exit(1)
    print("MiniLM loaded.", file=sys.stderr)

    # Load DeBERTa proxy
    print(f"Loading DeBERTa proxy ({_DEBERTA_MODEL_ID})...", file=sys.stderr)
    deberta_pipe, deberta_id2label = load_deberta_pipeline()
    print("DeBERTa loaded.", file=sys.stderr)

    # Build TextAttack model wrapper
    model_wrapper = MiniLMOnnxWrapper(classifier)

    # Build dataset
    dataset, metadata, skip_count = build_dataset(MALICIOUS_CORPUS, classifier, limit=limit)

    if not dataset:
        print("ERROR: No samples to attack after pre-filtering.", file=sys.stderr)
        sys.exit(1)

    # Run attacks
    attack_results: dict[str, dict[str, Any] | None] = {}

    # --- PWWS ---
    print("\nBuilding PWWS attack...", file=sys.stderr)
    from textattack.attack_recipes import PWWSRen2019

    pwws_attack = PWWSRen2019.build(model_wrapper)
    print("Running PWWS...", file=sys.stderr)
    attack_results["pwws"] = run_attack(
        attack=pwws_attack,
        attack_name="PWWS",
        dataset=dataset,
        model_wrapper=model_wrapper,
        deberta_pipe=deberta_pipe,
        deberta_id2label=deberta_id2label,
    )
    print(
        f"PWWS complete: {attack_results['pwws']['attack_success_count']} adversarial examples, "
        f"{attack_results['pwws']['transfer_count']} transferred",
        file=sys.stderr,
    )

    # --- TextFooler-BERTScore ---
    if not pwws_only:
        print("\nBuilding TextFooler-BERTScore attack...", file=sys.stderr)
        try:
            tf_attack = build_textfooler_bertscore(model_wrapper)
            print("Running TextFooler-BERTScore...", file=sys.stderr)
            attack_results["textfooler"] = run_attack(
                attack=tf_attack,
                attack_name="TextFooler-BERTScore",
                dataset=dataset,
                model_wrapper=model_wrapper,
                deberta_pipe=deberta_pipe,
                deberta_id2label=deberta_id2label,
            )
            print(
                f"TextFooler complete: {attack_results['textfooler']['attack_success_count']} adversarial examples, "  # noqa: E501
                f"{attack_results['textfooler']['transfer_count']} transferred",
                file=sys.stderr,
            )
        except Exception as exc:
            print(
                f"TextFooler-BERTScore failed: {exc}. Continuing with PWWS results only.",
                file=sys.stderr,
            )
            attack_results["textfooler"] = None
    else:
        attack_results["textfooler"] = None

    # Gate decision
    gate, combined, gate_note = make_gate_decision(attack_results)

    # Per-sample results
    per_sample_results = assemble_per_sample_with_metadata(MALICIOUS_CORPUS, attack_results)

    # Build output document
    output_doc: dict[str, Any] = {
        "experiment": "transferability-gate",
        "date": date.today().isoformat(),
        "methodology": {
            "attack_target": "MiniLM-L6-v2 ONNX (CloneGuard Tier 1.5)",
            "attack_recipes": [k for k, v in attack_results.items() if v is not None],
            "transfer_target": _DEBERTA_MODEL_ID,
            "corpus": str(MALICIOUS_CORPUS.relative_to(_REPO_ROOT)),
            "corpus_size": 185,
            "samples_attacked": len(dataset),
            "samples_skipped_pre_misclassified": skip_count,
            "deberta_id2label": {str(k): v for k, v in deberta_id2label.items()},
        },
        "results": {
            "pwws": attack_results["pwws"],
            "textfooler": attack_results["textfooler"],
            "combined": combined,
        },
        "gate_decision": gate,
        "gate_threshold": GATE_THRESHOLD,
        "gate_note": gate_note,
        "limitations": [
            "ProtectAI DeBERTa is not trained on the CloneGuard dataset — proxy only",
            (
                "Low transfer rate indicates architectural diversity but does not "
                "guarantee fine-tuned ensemble effectiveness"
            ),
            (
                "TextFooler uses BERTScore constraint instead of Universal Sentence "
                "Encoder — semantically approximate, not identical"
            ),
            (
                "Experiment conducted on held-out adversarial corpus, "
                "not on organic in-the-wild samples"
            ),
            (
                "MiniLM pre-filter removes samples already evading detection — "
                "results apply only to detectable samples"
            ),
        ],
        "per_sample_results": per_sample_results,
    }

    output_json = json.dumps(output_doc, indent=2, ensure_ascii=False)

    if dry_run:
        # Dry-run: print to stdout only
        print(output_json)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output_json)
            f.write("\n")
        print(f"\nResults written to: {output_path}", file=sys.stderr)
        print(f"Gate decision: {gate.upper()} — {gate_note}", file=sys.stderr)


if __name__ == "__main__":
    main()
