#!/usr/bin/env python3
# Run with: .venv-transfer/bin/python scripts/generate_pwws_augmentation.py
"""Generate PWWS adversarial examples from the malicious corpus for augmentation.

Produces JSONL with provenance metadata for each successful adversarial example.
Each output line: {"text": ..., "label": 1, "provenance": {"round": N, "method": "pwws", "original_id": ...}}

Run in .venv-transfer/ environment (TextAttack lives there).
Use .venv for training scripts.

Usage
-----
  .venv-transfer/bin/python scripts/generate_pwws_augmentation.py --round 1
  .venv-transfer/bin/python scripts/generate_pwws_augmentation.py \\
    --round 2 --corpus data/benchmark/malicious_corpus.json \\
    --output data/training/pwws_adversarial_r2.jsonl --limit 20
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_PATH = str(_REPO_ROOT / "src" / "cloneguard" / "model" / "mini_semantic.onnx")
_DEFAULT_CORPUS = str(_REPO_ROOT / "data" / "benchmark" / "malicious_corpus.json")


def _default_output(round_number: int) -> str:
    return str(_REPO_ROOT / "data" / "training" / f"pwws_adversarial_r{round_number}.jsonl")


# ---------------------------------------------------------------------------
# Record building and validation
# ---------------------------------------------------------------------------


def build_augmentation_record(
    perturbed_text: str,
    round_number: int,
    original_id: str,
) -> dict[str, Any]:
    """Build a single JSONL augmentation record with provenance metadata.

    Args:
        perturbed_text: The adversarially perturbed text.
        round_number: The augmentation round number (1, 2, 3, ...).
        original_id: The corpus sample ID that was attacked.

    Returns:
        dict with keys: text, label, provenance.
    """
    return {
        "text": perturbed_text,
        "label": 1,  # always malicious — these are injection attempts, just paraphrased
        "provenance": {
            "round": round_number,
            "method": "pwws",
            "original_id": original_id,
        },
    }


def validate_augmentation_record(record: dict[str, Any]) -> dict[str, Any]:
    """Validate an augmentation record has all required fields.

    Args:
        record: dict to validate.

    Returns:
        The same record if valid.

    Raises:
        ValueError: If any required field is missing or invalid.
    """
    if "text" not in record or not record["text"]:
        raise ValueError("record.text must be a non-empty string")
    if record.get("label") != 1:
        raise ValueError("record.label must be 1 (malicious)")
    prov = record.get("provenance")
    if not prov:
        raise ValueError("record.provenance must be present")
    for key in ("round", "method", "original_id"):
        if key not in prov:
            raise ValueError(f"record.provenance.{key} required")
    return record


def is_successful_attack(original: str, perturbed: str) -> bool:
    """Return True iff perturbed text differs meaningfully from original.

    Strips trailing/leading whitespace before comparison to avoid treating
    whitespace-only differences as successful attacks.

    Args:
        original: The original (unmodified) text.
        perturbed: The text produced by the attack.

    Returns:
        True if the attack produced a genuinely different text.
    """
    if not perturbed:
        return False
    original_stripped = original.strip()
    perturbed_stripped = perturbed.strip()
    return perturbed_stripped != original_stripped


def write_jsonl_records(records: list[dict[str, Any]], output_path: Path) -> None:
    """Write a list of augmentation records to a JSONL file.

    Each record is written as a single JSON line (no trailing comma).
    Overwrites the file if it exists.

    Args:
        records: List of validated augmentation record dicts.
        output_path: Destination path for the JSONL file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False))
            f.write("\n")


# ---------------------------------------------------------------------------
# MiniLMOnnxWrapper (copied from scripts/transfer_experiment.py)
# Copied intentionally — this script runs in .venv-transfer, not .venv.
# Different venv constraints prevent shared import. Keep in sync manually.
# ---------------------------------------------------------------------------


class MiniLMOnnxWrapper:
    """TextAttack ModelWrapper wrapping the MiniLM ONNX classifier.

    Implements the __call__ interface expected by TextAttack attack recipes:
    input: list[str], output: np.ndarray of shape [batch, 2]
      col 0 = P(benign/SAFE), col 1 = P(malicious)

    References:
    - Original pattern from scripts/transfer_experiment.py
    """

    def __init__(self, session, tokenizer) -> None:
        # TextAttack ModelWrapper protocol requires self.model attribute
        self.model = session  # expose session as .model for protocol compliance
        self.tokenizer = tokenizer
        self._session = session

    def __call__(self, text_inputs: list[str]) -> np.ndarray:
        results = []
        for text in text_inputs:
            inputs = self.tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=256,
                padding="max_length",
            )
            logits = self._session.run(
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
# Raw scoring helper (bypasses classify() thresholds)
# ---------------------------------------------------------------------------


def raw_score(session, tokenizer, text: str) -> float:
    """Score a text sample via raw ONNX logits, bypassing thresholds.

    Returns p(malicious) as a float in [0, 1].
    """
    inputs = tokenizer(
        text,
        return_tensors="np",
        truncation=True,
        max_length=256,
        padding="max_length",
    )
    logits = session.run(
        None,
        {
            "input_ids": inputs["input_ids"],
            "attention_mask": inputs["attention_mask"],
        },
    )[0][0]
    exp_l = np.exp(logits - logits.max())
    probs = exp_l / exp_l.sum()
    return float(probs[1])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the PWWS augmentation generation script.

    Args:
        argv: Argument list (defaults to sys.argv[1:] if None).

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Generate PWWS adversarial examples for augmentation training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--round",
        type=int,
        required=True,
        metavar="N",
        help="Augmentation round number (written to provenance metadata)",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=_DEFAULT_MODEL_PATH,
        metavar="PATH",
        help=f"Path to MiniLM ONNX model (default: {_DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=_DEFAULT_CORPUS,
        metavar="PATH",
        help=f"Path to malicious corpus JSON (default: {_DEFAULT_CORPUS})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="PATH",
        help="Output JSONL path (default: data/training/pwws_adversarial_rN.jsonl)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Process only first N corpus samples (for testing)",
    )
    parser.add_argument(
        "--time-limit",
        type=int,
        default=90,
        metavar="MINUTES",
        help="Maximum wall-clock time for attack generation (default: 90 minutes)",
    )
    args = parser.parse_args(argv)

    # Set default output based on round number if not specified
    if args.output is None:
        args.output = _default_output(args.round)

    return args


# ---------------------------------------------------------------------------
# Main — requires TextAttack (.venv-transfer)
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    import onnxruntime as ort
    from textattack import AttackArgs, Attacker
    from textattack.attack_recipes import PWWSRen2019
    from textattack.attack_results import SkippedAttackResult, SuccessfulAttackResult
    from textattack.datasets import Dataset as TADataset
    from transformers import AutoTokenizer

    round_number: int = args.round
    model_path = Path(args.model_path)
    corpus_path = Path(args.corpus)
    output_path = Path(args.output)
    limit: int | None = args.limit
    time_limit_seconds = args.time_limit * 60

    print("=" * 60, file=sys.stderr)
    print(f"CloneGuard PWWS Augmentation — Round {round_number}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Model:       {model_path}", file=sys.stderr)
    print(f"  Corpus:      {corpus_path}", file=sys.stderr)
    print(f"  Output:      {output_path}", file=sys.stderr)
    print(f"  Limit:       {limit if limit else 'all'}", file=sys.stderr)
    print(f"  Time limit:  {args.time_limit} minutes", file=sys.stderr)
    print(file=sys.stderr)

    if not model_path.exists():
        print(f"ERROR: ONNX model not found: {model_path}", file=sys.stderr)
        print("  Run scripts/fetch_model.py to download the model.", file=sys.stderr)
        sys.exit(1)

    if not corpus_path.exists():
        print(f"ERROR: Corpus not found: {corpus_path}", file=sys.stderr)
        sys.exit(1)

    # Load ONNX model + tokenizer
    print("Loading MiniLM ONNX model...", file=sys.stderr)
    session = ort.InferenceSession(str(model_path))
    tokenizer = AutoTokenizer.from_pretrained(
        str(model_path.parent),
        local_files_only=True,
    )
    print("  Loaded.", file=sys.stderr)

    model_wrapper = MiniLMOnnxWrapper(session, tokenizer)

    # Load corpus
    with open(corpus_path) as f:
        corpus = json.load(f)

    if limit is not None:
        corpus = corpus[:limit]

    # Pre-filter: only attack samples where MiniLM already detects them (score > 0.5)
    # Rationale: attacking samples the model already misses adds no hardening value
    print(
        "Pre-filtering corpus (MiniLM raw score > 0.5 required)...",
        file=sys.stderr,
    )
    filtered_samples: list[tuple[str, int]] = []
    sample_ids: list[str] = []
    skip_count = 0

    for sample in corpus:
        score = raw_score(session, tokenizer, sample["payload"])
        if score <= 0.5:
            skip_count += 1
            print(
                f"  Skipping {sample['id']} ({sample.get('category', '?')}): score={score:.3f}",
                file=sys.stderr,
            )
            continue
        filtered_samples.append((sample["payload"], 1))  # label 1 = malicious
        sample_ids.append(sample["id"])

    print(
        f"Dataset: {len(filtered_samples)} samples to attack "
        f"({skip_count} pre-misclassified, skipped)",
        file=sys.stderr,
    )

    if not filtered_samples:
        print("ERROR: No samples to attack after pre-filtering.", file=sys.stderr)
        sys.exit(1)

    # Build payload ID lookup: text → corpus sample ID
    text_to_id: dict[str, str] = {
        text: sid for (text, _), sid in zip(filtered_samples, sample_ids)
    }

    # Build TextAttack dataset and attack
    ta_dataset = TADataset(filtered_samples)
    attack = PWWSRen2019.build(model_wrapper)

    attack_args = AttackArgs(
        num_examples=len(filtered_samples),
        disable_stdout=True,
        silent=True,
    )
    attacker = Attacker(attack, ta_dataset, attack_args)

    records: list[dict[str, Any]] = []
    attack_success_count = 0
    attack_fail_count = 0
    attack_skip_count = 0

    t_start = time.time()
    print(f"\nRunning PWWS on {len(filtered_samples)} samples...", file=sys.stderr)

    for idx, result in enumerate(attacker.attack_dataset()):
        elapsed = time.time() - t_start

        print(
            f"\r  {idx + 1}/{len(filtered_samples)} samples | "
            f"{attack_success_count} successful | {elapsed:.0f}s elapsed",
            end="",
            file=sys.stderr,
        )

        if elapsed > time_limit_seconds:
            print(
                f"\n  Time limit ({args.time_limit} min) reached. Stopping.",
                file=sys.stderr,
            )
            break

        if isinstance(result, SuccessfulAttackResult):
            attack_success_count += 1
            original_text = result.original_result.attacked_text.text
            adversarial_text = result.perturbed_result.attacked_text.text

            if not is_successful_attack(original_text, adversarial_text):
                continue  # guard: only write genuinely different texts

            original_id = text_to_id.get(original_text, f"unknown-{idx}")
            record = build_augmentation_record(adversarial_text, round_number, original_id)
            records.append(record)
        else:
            if hasattr(result, "perturbed_result"):
                attack_fail_count += 1
            else:
                attack_skip_count += 1

    print(file=sys.stderr)  # newline after progress line

    # Write output
    write_jsonl_records(records, output_path)

    total_attacked = len(filtered_samples)
    asr = attack_success_count / total_attacked if total_attacked > 0 else 0.0

    print(f"\n{'=' * 60}", file=sys.stderr)
    print(f"Round {round_number} PWWS Summary", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)
    print(f"  Total attacked:    {total_attacked}", file=sys.stderr)
    print(f"  Successful:        {attack_success_count}", file=sys.stderr)
    print(f"  Failed:            {attack_fail_count}", file=sys.stderr)
    print(f"  Skipped:           {attack_skip_count}", file=sys.stderr)
    print(f"  ASR:               {asr:.1%}", file=sys.stderr)
    print(f"  Records written:   {len(records)}", file=sys.stderr)
    print(f"  Output:            {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
