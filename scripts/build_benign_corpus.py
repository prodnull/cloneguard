#!/usr/bin/env python3
"""Assemble a benign corpus for the adversarial robustness benchmark.

Searches GitHub for repos containing agent instruction files (CLAUDE.md,
.cursorrules, etc.), clones them into a temp directory, extracts content
into a structured JSON corpus, then deletes the clones.

The corpus is used to measure false positive rates in CloneGuard's
prompt injection detection tiers.

Usage:
    python scripts/build_benign_corpus.py                  # Full run
    python scripts/build_benign_corpus.py --max-repos 10   # Quick test
    python scripts/build_benign_corpus.py --report-only    # Gap analysis on existing corpus
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, "src")

# ─── Constants ────────────────────────────────────────────────────────────

CORPUS_PATH = Path("data/benchmark/benign_corpus.json")
MAX_FILE_SIZE = 50 * 1024  # 50 KB
MIN_SAMPLES_PER_TYPE = 20

# Agent instruction file markers — repos must contain at least one.
AGENT_MARKERS = [
    "CLAUDE.md",
    ".cursorrules",
    ".github/copilot-instructions.md",
    "GEMINI.md",
]

# Search queries designed to find repos with agent instruction files.
# Each query targets a different ecosystem to diversify the corpus.
SEARCH_QUERIES: list[dict[str, str]] = [
    # AI/ML projects
    {"query": "CLAUDE.md language:python stars:>100", "label": "ai-py"},
    {"query": "CLAUDE.md language:typescript stars:>100", "label": "ai-ts"},
    {"query": ".cursorrules in:path stars:>100", "label": "cursor"},
    {"query": "copilot-instructions in:path stars:>100", "label": "copilot"},
    {"query": "GEMINI.md in:path stars:>100", "label": "gemini"},
    # Developer tools
    {"query": "CLAUDE.md topic:developer-tools stars:>50", "label": "devtools"},
    {"query": ".cursorrules topic:cli stars:>50", "label": "cli-cursor"},
    # Web frameworks
    {"query": "CLAUDE.md topic:web stars:>100", "label": "web"},
    {"query": ".cursorrules topic:react stars:>100", "label": "react"},
    {"query": ".cursorrules topic:nextjs stars:>50", "label": "nextjs"},
    # Security tooling
    {"query": "CLAUDE.md topic:security stars:>50", "label": "security"},
    {"query": ".cursorrules topic:security stars:>50", "label": "sec-cursor"},
]

# ─── File extraction rules ────────────────────────────────────────────────

# Maps glob patterns to (content_type, scan_mode).
EXTRACTION_RULES: list[tuple[str, str, str]] = [
    # Agent instruction files → STRICT
    ("CLAUDE.md", "agent_instructions", "STRICT"),
    (".cursorrules", "agent_instructions", "STRICT"),
    (".github/copilot-instructions.md", "agent_instructions", "STRICT"),
    ("GEMINI.md", "agent_instructions", "STRICT"),
    # Documentation → STANDARD
    ("README.md", "readme", "STANDARD"),
    ("CONTRIBUTING.md", "readme", "STANDARD"),
    ("SECURITY.md", "security_doc", "STANDARD"),
    # Config/build files → STANDARD
    ("package.json", "config", "STANDARD"),
    ("Makefile", "build_script", "STANDARD"),
    ("pyproject.toml", "config", "STANDARD"),
    ("setup.py", "config", "STANDARD"),
    # Workflows → STANDARD
    (".github/workflows/*.yml", "workflow", "STANDARD"),
    (".github/workflows/*.yaml", "workflow", "STANDARD"),
    # Env config → STANDARD
    (".env.example", "env_config", "STANDARD"),
    (".env.sample", "env_config", "STANDARD"),
]

# Test file glob patterns → LENIENT
TEST_GLOBS: list[str] = [
    "**/test_*.py",
    "**/*_test.go",
    "**/*.test.ts",
    "**/*.test.js",
    "**/*.spec.ts",
    "**/*.spec.js",
]


@dataclass
class CorpusSample:
    """A single benign sample for the benchmark corpus."""

    id: str
    content_type: str
    scan_mode: str
    text: str
    source_repo: str
    provenance: str = "real"


@dataclass
class ExtractionStats:
    """Track extraction statistics for reporting."""

    repos_searched: int = 0
    repos_cloned: int = 0
    repos_skipped: int = 0
    files_extracted: int = 0
    files_skipped_size: int = 0
    files_skipped_binary: int = 0
    errors: list[str] = field(default_factory=list)


# ─── Helpers ──────────────────────────────────────────────────────────────


def run_gh(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run a gh CLI command, returning the result."""
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def is_binary(path: Path) -> bool:
    """Heuristic: file is binary if first 8KB contain null bytes."""
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def discover_repos(max_repos: int) -> list[str]:
    """Search GitHub for qualifying repos using gh CLI.

    Returns deduplicated list of 'owner/repo' strings, up to max_repos.
    """
    seen: set[str] = set()
    repos: list[str] = []

    for sq in SEARCH_QUERIES:
        if len(repos) >= max_repos:
            break

        query = sq["query"]
        label = sq["label"]
        limit = min(10, max_repos - len(repos))

        print(f"  Searching [{label}]: {query} (limit={limit})")

        result = run_gh([
            "search", "repos",
            query,
            "--limit", str(limit),
            "--json", "fullName,stargazersCount,updatedAt",
            "--sort", "stars",
            "--order", "desc",
        ], timeout=60)

        if result.returncode != 0:
            msg = f"gh search failed for [{label}]: {result.stderr.strip()}"
            print(f"    WARN: {msg}")
            continue

        try:
            results = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"    WARN: Invalid JSON from gh search [{label}]")
            continue

        for repo in results:
            full_name: str = repo["fullName"]
            if full_name in seen:
                continue
            seen.add(full_name)
            repos.append(full_name)
            stars = repo.get("stargazersCount", "?")
            print(f"    Found: {full_name} ({stars} stars)")

            if len(repos) >= max_repos:
                break

    print(f"\nDiscovered {len(repos)} unique repos")
    return repos


def clone_repo(repo: str, target_dir: Path) -> Path | None:
    """Shallow-clone a repo into target_dir. Returns clone path or None on failure."""
    clone_path = target_dir / repo.replace("/", "_")
    result = run_gh([
        "repo", "clone", repo, str(clone_path),
        "--", "--depth=1", "--single-branch",
    ], timeout=120)

    if result.returncode != 0:
        return None
    return clone_path


def extract_files(
    repo_path: Path,
    repo_name: str,
    stats: ExtractionStats,
    id_counters: Counter[str],
) -> list[CorpusSample]:
    """Extract qualifying files from a cloned repo."""
    samples: list[CorpusSample] = []

    # Fixed-path rules
    for pattern, content_type, scan_mode in EXTRACTION_RULES:
        if "*" in pattern:
            # Glob pattern
            matches = sorted(repo_path.glob(pattern))
        else:
            # Exact path
            candidate = repo_path / pattern
            matches = [candidate] if candidate.is_file() else []

        for fpath in matches:
            sample = _try_extract(fpath, repo_name, content_type, scan_mode, stats, id_counters)
            if sample is not None:
                samples.append(sample)

    # Test files (glob patterns, LENIENT)
    for glob_pat in TEST_GLOBS:
        for fpath in sorted(repo_path.glob(glob_pat))[:5]:  # Cap per-glob to avoid huge test suites
            sample = _try_extract(fpath, repo_name, "test_file", "LENIENT", stats, id_counters)
            if sample is not None:
                samples.append(sample)

    return samples


def _try_extract(
    fpath: Path,
    repo_name: str,
    content_type: str,
    scan_mode: str,
    stats: ExtractionStats,
    id_counters: Counter[str],
) -> CorpusSample | None:
    """Attempt to read a file and create a CorpusSample. Returns None on skip."""
    if not fpath.is_file():
        return None

    try:
        size = fpath.stat().st_size
    except OSError:
        return None

    if size > MAX_FILE_SIZE:
        stats.files_skipped_size += 1
        return None

    if is_binary(fpath):
        stats.files_skipped_binary += 1
        return None

    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Skip empty files
    if not text.strip():
        return None

    count = id_counters[content_type]
    id_counters[content_type] += 1
    sample_id = f"benign-{content_type.replace('_', '-')}-{count:03d}"

    stats.files_extracted += 1
    return CorpusSample(
        id=sample_id,
        content_type=content_type,
        scan_mode=scan_mode,
        text=text,
        source_repo=repo_name,
    )


# ─── Main pipeline ───────────────────────────────────────────────────────


def build_corpus(max_repos: int) -> list[dict[str, str]]:
    """Full pipeline: discover → clone → extract → cleanup."""
    stats = ExtractionStats()
    id_counters: Counter[str] = Counter()
    all_samples: list[CorpusSample] = []

    print("=" * 70)
    print("Phase 1: Discovering repos via gh search")
    print("=" * 70)
    repos = discover_repos(max_repos)
    stats.repos_searched = len(repos)

    if not repos:
        print("ERROR: No repos found. Check gh auth and network.", file=sys.stderr)
        sys.exit(1)

    print()
    print("=" * 70)
    print("Phase 2: Cloning and extracting content")
    print("=" * 70)

    tmpdir = Path(tempfile.mkdtemp(prefix="cloneguard-benign-"))
    print(f"Temp directory: {tmpdir}\n")

    try:
        for i, repo in enumerate(repos, 1):
            print(f"[{i}/{len(repos)}] {repo}")

            clone_path = clone_repo(repo, tmpdir)
            if clone_path is None:
                print("  SKIP: clone failed")
                stats.repos_skipped += 1
                continue

            stats.repos_cloned += 1
            samples = extract_files(clone_path, repo, stats, id_counters)
            all_samples.extend(samples)
            print(f"  Extracted {len(samples)} files")

            # Delete clone immediately to save disk
            shutil.rmtree(clone_path, ignore_errors=True)
    finally:
        # Ensure temp dir is cleaned up
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"\nCleaned up temp directory: {tmpdir}")

    print()
    print("=" * 70)
    print("Phase 3: Writing corpus")
    print("=" * 70)

    corpus = [asdict(s) for s in all_samples]

    CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CORPUS_PATH.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
    print(f"Wrote {len(corpus)} samples to {CORPUS_PATH}")

    # Stats summary
    print(f"\n{'─' * 50}")
    print(f"Repos searched:        {stats.repos_searched}")
    print(f"Repos cloned:          {stats.repos_cloned}")
    print(f"Repos skipped:         {stats.repos_skipped}")
    print(f"Files extracted:       {stats.files_extracted}")
    print(f"Files skipped (size):  {stats.files_skipped_size}")
    print(f"Files skipped (bin):   {stats.files_skipped_binary}")

    if stats.errors:
        print(f"\nErrors ({len(stats.errors)}):")
        for err in stats.errors:
            print(f"  - {err}")

    return corpus


def report_gaps(corpus: list[dict[str, str]]) -> None:
    """Analyze corpus for content type coverage gaps."""
    print()
    print("=" * 70)
    print("Gap Analysis")
    print("=" * 70)

    type_counts: Counter[str] = Counter()
    mode_counts: Counter[str] = Counter()
    repo_counts: Counter[str] = Counter()

    for sample in corpus:
        type_counts[sample["content_type"]] += 1
        mode_counts[sample["scan_mode"]] += 1
        repo_counts[sample["source_repo"]] += 1

    # All expected content types
    expected_types = {
        "agent_instructions", "readme", "config", "build_script",
        "workflow", "env_config", "test_file", "security_doc",
    }

    print(f"\nTotal samples: {len(corpus)}")
    print(f"Unique repos:  {len(repo_counts)}")

    print(f"\nBy content type (threshold: {MIN_SAMPLES_PER_TYPE}):")
    gaps: list[str] = []
    for ctype in sorted(expected_types):
        count = type_counts.get(ctype, 0)
        status = "OK" if count >= MIN_SAMPLES_PER_TYPE else "NEEDS FILL"
        marker = "  " if count >= MIN_SAMPLES_PER_TYPE else ">>"
        print(f"  {marker} {ctype:<25s} {count:>4d}  [{status}]")
        if count < MIN_SAMPLES_PER_TYPE:
            gaps.append(ctype)

    # Check for unexpected types in corpus
    unexpected = set(type_counts.keys()) - expected_types
    if unexpected:
        print(f"\n  Unexpected types in corpus: {', '.join(sorted(unexpected))}")

    print("\nBy scan mode:")
    for mode in ["STRICT", "STANDARD", "LENIENT"]:
        print(f"  {mode:<12s} {mode_counts.get(mode, 0):>4d}")

    if gaps:
        deficit = sum(max(0, MIN_SAMPLES_PER_TYPE - type_counts.get(g, 0)) for g in gaps)
        print(f"\n{'!' * 50}")
        print(f"GAPS DETECTED: {len(gaps)} content types below threshold")
        print(f"Types needing synthetic fill: {', '.join(gaps)}")
        print(f"Minimum samples needed: {deficit}")
        print(f"{'!' * 50}")
    else:
        print("\nAll content types meet the minimum sample threshold.")


# ─── CLI ──────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build benign corpus for adversarial robustness benchmark",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=30,
        help="Maximum number of repos to clone (default: 30)",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only run gap analysis on existing corpus (no cloning)",
    )
    args = parser.parse_args()

    if args.report_only:
        if not CORPUS_PATH.exists():
            print(f"ERROR: No corpus found at {CORPUS_PATH}", file=sys.stderr)
            print("Run without --report-only to build the corpus first.", file=sys.stderr)
            sys.exit(1)
        corpus = json.loads(CORPUS_PATH.read_text())
        report_gaps(corpus)
        return

    corpus = build_corpus(args.max_repos)
    report_gaps(corpus)


if __name__ == "__main__":
    main()
