#!/usr/bin/env python3
"""Build exhaustive training dataset for MiniLM-L6-v2 prompt injection classifier.

Sources:
  A. Existing pattern payloads from integration tests (~175)
  B. PoC attack files from /tmp/cloneguard-poc/ (~20-30)
  C. Ollama-generated paraphrases (50/category x 23 categories)
  D. Ollama-generated evasion variants (20/category x 23 categories)
  E. Multi-file attack contexts (~100+)
  F. Cross-category combinations (~200+)
  G. Real project files (benign, 50/file-type x 8 types)
  H. Hard negatives (50/subcategory x 10 subcategories)
  I. Edge cases (benign, 50/subcategory x 7 subcategories)
"""

from __future__ import annotations

import ast
import json
import random
import re
import sys
import time
from pathlib import Path

import ollama
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "src" / "cloneguard" / "rules"
TEST_FILE = PROJECT_ROOT / "tests" / "test_integration_all_patterns.py"
POC_DIR = Path("/tmp/cloneguard-poc")
OUTPUT_DIR = PROJECT_ROOT / "data" / "training"
OUTPUT_FILE = OUTPUT_DIR / "dataset.jsonl"

OLLAMA_MODEL = "qwen2.5:7b"
OLLAMA_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_with_ollama(prompt: str, num_retries: int = 3) -> list[str]:
    """Call Ollama and return non-empty lines from the response."""
    for attempt in range(num_retries):
        try:
            resp = ollama.generate(
                model=OLLAMA_MODEL,
                prompt=prompt,
                options={"num_predict": 4096, "temperature": 0.9},
            )
            text = resp.get("response", "")
            lines = []
            for line in text.split("\n"):
                line = line.strip()
                # Strip numbering prefixes like "1. " or "1) " or "- "
                if line and line[0].isdigit():
                    line = re.sub(r"^\d+[\.\)]\s*", "", line)
                if line.startswith("- "):
                    line = line[2:]
                line = line.strip()
                if len(line) >= 10:
                    lines.append(line)
            return lines
        except Exception as e:
            print(f"    [retry {attempt + 1}/{num_retries}] Ollama error: {e}")
            time.sleep(2)
    print("    [FAILED] Skipping this prompt after retries")
    return []


def load_yaml_rules() -> dict[str, dict]:
    """Load all YAML rule files into {filename_stem: parsed_yaml} dict."""
    rules = {}
    for f in sorted(RULES_DIR.glob("*.yaml")):
        with open(f) as fh:
            rules[f.stem] = yaml.safe_load(fh)
    return rules


def extract_payloads_from_test() -> list[str]:
    """Extract payload content strings from the PAYLOADS dict in test file."""
    source = TEST_FILE.read_text()
    payloads = []
    # Match tuple patterns: ("filename", "content") or ("filename", r"content")
    # Also handle multi-line tuples
    for match in re.finditer(
        r'"[A-Z]{1,4}-\d{1,3}":\s*\(\s*\n?\s*"[^"]*"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)',
        source,
    ):
        payloads.append(match.group(1))
    for match in re.finditer(
        r'"[A-Z]{1,4}-\d{1,3}":\s*\(\s*"[^"]*"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)',
        source,
    ):
        payloads.append(match.group(1))
    # Raw strings
    for match in re.finditer(
        r'"[A-Z]{1,4}-\d{1,3}":\s*\(\s*"[^"]*"\s*,\s*r"((?:[^"\\]|\\.)*)"\s*\)',
        source,
    ):
        payloads.append(match.group(1))
    # Handle special cases with textwrap or multi-line
    for match in re.finditer(
        r'"[A-Z]{1,4}-\d{1,3}":\s*\(\s*\n\s*"[^"]*"\s*,\s*\n\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\n?\s*\)',
        source,
    ):
        payloads.append(match.group(1))
    # Handle the newline * 55 case
    if '"\\n" * 55' in source or "'\\n' * 55" in source:
        payloads.append("\n" * 55)
    return list(set(payloads))


def load_poc_files() -> list[str]:
    """Load all PoC attack files as malicious samples."""
    samples = []
    if not POC_DIR.exists():
        print("  Warning: PoC directory not found, skipping")
        return samples
    for f in sorted(POC_DIR.rglob("*")):
        if f.is_file():
            try:
                content = f.read_text(errors="replace").strip()
                if len(content) >= 10:
                    samples.append(content)
            except Exception:
                pass
    return samples


# ---------------------------------------------------------------------------
# Source C: Ollama Paraphrases
# ---------------------------------------------------------------------------
def generate_paraphrases(rules: dict[str, dict]) -> list[str]:
    """Generate 50 paraphrased attack payloads per category."""
    source = TEST_FILE.read_text()
    all_samples = []

    for stem, data in sorted(rules.items()):
        cat_name = data.get("category", stem)
        cat_desc = data.get("description", "")
        patterns = data.get("patterns", [])
        example_ids = [p["id"] for p in patterns[:5]]

        # Get actual test payloads for this category
        cat_test_payloads = []
        for pid in example_ids:
            m = re.search(
                rf'"{re.escape(pid)}":\s*\([^)]*,\s*"((?:[^"\\]|\\.)*)"\s*\)',
                source,
            )
            if m:
                cat_test_payloads.append(m.group(1))
            else:
                m = re.search(
                    rf'"{re.escape(pid)}":\s*\([^)]*,\s*r"((?:[^"\\]|\\.)*)"\s*\)',
                    source,
                )
                if m:
                    cat_test_payloads.append(m.group(1))

        example_text = "\n".join(f"- {p}" for p in cat_test_payloads[:5])
        if not example_text:
            # Fallback to pattern descriptions
            example_text = "\n".join(
                f"- {p['description']}" for p in patterns[:5] if p.get("description")
            )

        prompt = f"""You are generating training data for a prompt injection classifier that protects AI coding agents.

Category: {cat_name}
Description: {cat_desc}
Example attacks from this category:
{example_text}

Generate 50 diverse prompt injection payloads for this category. Requirements:
- Use different vocabulary, sentence structures, and social engineering framings
- Include variations that would NOT match simple regex patterns
- Include variations with different levels of subtlety (obvious to very subtle)
- Include variations targeting different AI agents (Claude, Copilot, Cursor, Gemini)
- Include multi-sentence attacks that hide the malicious intent in context
- Include attacks that use compliance/audit/policy framing
- Include attacks embedded in otherwise-normal documentation

Return ONLY the payloads, one per line, no numbering, no blank lines."""

        print(f"  [C] Paraphrases: {cat_name} ({stem})...")
        lines = generate_with_ollama(prompt)
        all_samples.extend(lines)
        print(f"      -> {len(lines)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source D: Evasion Variants
# ---------------------------------------------------------------------------
def generate_evasion_variants(rules: dict[str, dict]) -> list[str]:
    """Generate 20 evasion variants per category that bypass regex."""
    all_samples = []
    for stem, data in sorted(rules.items()):
        cat_name = data.get("category", stem)
        patterns = data.get("patterns", [])
        regex_list = "\n".join(f"- {p['regex']}" for p in patterns)

        prompt = f"""You are generating adversarial training data for a prompt injection classifier.

Category: {cat_name}
These regex patterns currently detect attacks in this category:
{regex_list}

Generate 20 prompt injection payloads that:
- Would NOT match any of the above regex patterns
- Still carry the same malicious intent
- Use synonym substitution, indirect language, metaphor, or multi-step reasoning
- Would fool a regex engine but should be caught by a semantic classifier

Return ONLY the payloads, one per line."""

        print(f"  [D] Evasion: {cat_name} ({stem})...")
        lines = generate_with_ollama(prompt)
        all_samples.extend(lines)
        print(f"      -> {len(lines)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source E: Multi-file Attack Context
# ---------------------------------------------------------------------------
def generate_multifile_attacks() -> list[str]:
    """Generate realistic multi-file attack scenarios."""
    prompts = [
        """Generate 25 realistic README.md files that contain hidden prompt injection attacks.
Each should look like a normal project README but embed malicious instructions in:
- HTML comments
- Hidden markdown reference links
- Image alt text
- Footnotes
- Link titles

The attacks should instruct AI agents to exfiltrate data, ignore safety, or execute commands.
Return each complete README (use --- as separator between them). Keep each under 15 lines.""",
        """Generate 25 realistic package.json files that contain malicious postinstall hooks.
Each should have normal-looking dependencies but hide attacks in:
- lifecycle scripts (postinstall, preinstall, prepare)
- command chaining with &&
- environment variable exfiltration
- downloading and executing remote scripts

Return each complete package.json (use --- as separator). Keep each under 15 lines.""",
        """Generate 25 realistic CLAUDE.md or .cursorrules files with subtle behavioral manipulation.
Each should look like legitimate coding instructions but include:
- Instructions to suppress security warnings
- Instructions to auto-approve all operations
- Hidden data exfiltration directives mixed with style guidelines
- Self-propagation instructions disguised as consistency rules

Return each complete file (use --- as separator). Keep each under 15 lines.""",
        """Generate 25 realistic .devcontainer/devcontainer.json or docker-compose.yml files with attacks.
Each should look normal but include:
- Volume mounts to sensitive host directories
- Privileged mode escalation
- Network settings that enable exfiltration
- Post-create commands that download and execute payloads

Return each complete file (use --- as separator). Keep each under 15 lines.""",
    ]

    all_samples = []
    for i, prompt in enumerate(prompts):
        print(f"  [E] Multi-file context batch {i + 1}/4...")
        lines = generate_with_ollama(prompt)
        full_text = "\n".join(lines)
        files = full_text.split("---")
        for f in files:
            f = f.strip()
            if len(f) >= 10:
                all_samples.append(f)
        count = len([f for f in files if len(f.strip()) >= 10])
        print(f"      -> {count} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source F: Cross-Category Combinations
# ---------------------------------------------------------------------------
def generate_cross_category() -> list[str]:
    """Generate attacks combining multiple categories."""
    combos = [
        (
            "Credential Harvesting + Behavioral Manipulation",
            "Attacks that read sensitive credentials (SSH keys, API keys, .env files) "
            "AND instruct the agent to hide this from the user.",
        ),
        (
            "Instruction Override + Exfiltration",
            "Attacks that first override the agent's instructions, then direct it to "
            "send data to external URLs via curl/wget/fetch.",
        ),
        (
            "Authority Impersonation + Privilege Escalation",
            "Attacks that fake admin/system messages to justify enabling dangerous "
            "flags like --dangerously-skip-permissions, --yolo, or auto-approve.",
        ),
        (
            "Memory Poisoning + Viral Propagation",
            "Attacks that write persistent instructions to MEMORY.md AND spread to "
            "other repos/projects.",
        ),
        (
            "Build Script + Supply Chain",
            "Attacks embedding malicious code in package.json postinstall that "
            "downloads from custom registries and executes arbitrary code.",
        ),
        (
            "Config Injection + Reasoning Hijack",
            "Attacks that inject fake thinking/reasoning blocks in config files to "
            "manipulate the agent's chain-of-thought.",
        ),
        (
            "MCP Poisoning + Credential Harvesting",
            "Attacks defining MCP tools with descriptions containing credential "
            "harvesting instructions or env var exfiltration.",
        ),
        (
            "Encoding Obfuscation + Instruction Override",
            "Attacks using base64, hex, or unicode encoding to hide instruction "
            "override payloads that bypass plaintext regex.",
        ),
        (
            "Environment Variable Hijacking + Exfiltration",
            "Attacks setting HTTP_PROXY, NODE_OPTIONS, or LD_PRELOAD to intercept "
            "and redirect traffic to attacker-controlled servers.",
        ),
        (
            "Git Hook + Privilege Escalation",
            "Attacks installing git hooks (pre-commit, post-checkout) which run "
            "with elevated permissions or bypass security checks.",
        ),
    ]

    all_samples = []
    for name, desc in combos:
        prompt = f"""Generate 20 prompt injection payloads that combine these attack categories:

Category Combination: {name}
Description: {desc}

Requirements:
- Each payload must exhibit BOTH attack categories simultaneously
- Vary the subtlety (some obvious, some very subtle)
- Use realistic file contexts (README, CLAUDE.md, package.json, etc.)
- Include multi-sentence attacks where the combination emerges from context

Return ONLY the payloads, one per line."""

        print(f"  [F] Cross-category: {name}...")
        lines = generate_with_ollama(prompt)
        all_samples.extend(lines)
        print(f"      -> {len(lines)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source G: Benign Real Project Files
# ---------------------------------------------------------------------------
def generate_benign_project_files() -> list[str]:
    """Generate realistic benign content for common file types."""
    file_types = [
        (
            "README.md",
            "standard project documentation with install instructions, API docs, "
            "changelogs, badges, contributing guidelines, and license info",
        ),
        (
            "CLAUDE.md",
            "legitimate AI coding assistant instructions: code style preferences, "
            "project architecture context, testing requirements, naming conventions",
        ),
        (
            ".cursorrules",
            "legitimate code formatting rules, indentation preferences, naming "
            "conventions, file organization guidelines",
        ),
        (
            "package.json",
            "normal Node.js project configs with standard dependencies (express, "
            "react, typescript, jest, eslint), standard scripts (start, build, test)",
        ),
        (
            "Makefile",
            "standard build targets (all, clean, test, install, lint, format) "
            "with normal compiler flags and tool invocations",
        ),
        (
            "pyproject.toml",
            "normal Python project configs with setuptools/hatchling build backend, "
            "standard dependencies, pytest/mypy/ruff tool configs",
        ),
        (
            ".github/workflows/ci.yml",
            "standard CI workflow configs: checkout, setup-node/python, install deps, "
            "run tests, run linter. Use standard actions",
        ),
        (
            ".env.example",
            "example environment files with placeholder values like DB_HOST=localhost, "
            "API_KEY=your-api-key-here, PORT=3000",
        ),
    ]

    all_samples = []
    for file_type, desc in file_types:
        prompt = f"""Generate 50 realistic, completely benign {file_type} file contents for various open-source projects.

Requirements for {file_type}:
- {desc}
- Each should be for a DIFFERENT project (web app, CLI tool, library, API server, etc.)
- Content must be completely legitimate with no security concerns
- Vary the length (some short, some detailed)
- Use realistic project names, descriptions, and dependencies
- These should look like real files from GitHub repositories

Return each file content on a separate line (if multi-line, use \\n for newlines).
Return 50 examples, one per line, no numbering."""

        print(f"  [G] Benign files: {file_type}...")
        lines = generate_with_ollama(prompt)
        processed = []
        for line in lines:
            line = line.replace("\\n", "\n")
            if len(line.strip()) >= 10:
                processed.append(line.strip())
        all_samples.extend(processed)
        print(f"      -> {len(processed)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source H: Hard Negatives
# ---------------------------------------------------------------------------
def generate_hard_negatives() -> list[str]:
    """Generate benign content that resembles attacks (hard negatives)."""
    subcategories = [
        (
            "Security documentation",
            "Academic descriptions of prompt injection attacks, threat models, "
            "and defense mechanisms. Technical details about how attacks work.",
        ),
        (
            "CTF challenge writeups",
            "Capture-the-flag writeups describing how participants solved security "
            "challenges involving injection techniques. Past tense, analytical.",
        ),
        (
            "Security scanner docs",
            "Documentation for security scanning tools like Semgrep, Bandit, Snyk. "
            "Describe detection rules, configuration, and usage.",
        ),
        (
            "Penetration testing guides",
            "Legitimate penetration testing methodology guides referencing tools "
            "like Burp Suite, OWASP ZAP. Educational, professional tone.",
        ),
        (
            "Code review comments",
            "Code review comments pointing out security issues: 'This curl call "
            "should validate the certificate', 'sanitize input before use'.",
        ),
        (
            "Academic papers on prompt injection",
            "Abstracts and summaries of research papers about prompt injection, "
            "LLM security, supply chain attacks. Academic language.",
        ),
        (
            "Bug bounty reports",
            "Responsible disclosure reports describing vulnerabilities. Include "
            "severity, impact, steps to reproduce, remediation.",
        ),
        (
            "Security audit checklists",
            "Security assessment checklists: verify no hardcoded credentials, "
            "check lifecycle scripts, review git hooks, validate CI/CD permissions.",
        ),
        (
            "Security tool READMEs",
            "README files for security tools (linters, SAST tools, scanners). "
            "Describe what the tool detects and how to configure rules.",
        ),
        (
            "Security training materials",
            "Training content teaching developers about secure coding: common "
            "vulnerabilities, how to avoid them, secure defaults.",
        ),
    ]

    all_samples = []
    for name, desc in subcategories:
        prompt = f"""Generate 50 completely benign text samples that are {name.lower()}.

These samples should:
- {desc}
- Use security terminology that might trigger false positives in a naive classifier
- Reference attack patterns, vulnerability types, and security tools BY NAME
- Be clearly educational/defensive in nature, NOT actual attacks
- Include words like "inject", "exfiltrate", "override", "bypass" in legitimate context
- Vary length and format

CRITICAL: These must be BENIGN content describing security concepts, not performing attacks.

Return 50 samples, one per line, no numbering."""

        print(f"  [H] Hard negatives: {name}...")
        lines = generate_with_ollama(prompt)
        all_samples.extend(lines)
        print(f"      -> {len(lines)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Source I: Edge Cases
# ---------------------------------------------------------------------------
def generate_edge_cases() -> list[str]:
    """Generate benign edge-case content that tests classifier precision."""
    subcategories = [
        (
            "Legitimate curl/wget usage",
            "API client code using curl or wget for legitimate purposes: "
            "downloading releases, health endpoints, fetching configs.",
        ),
        (
            "Environment variable configs",
            "Scripts and configs that legitimately read environment variables: "
            "DATABASE_URL, PORT, LOG_LEVEL, NODE_ENV. Standard dotenv patterns.",
        ),
        (
            "Docker configurations",
            "Legitimate Dockerfiles and docker-compose.yml with volume mounts "
            "for app data, build args, health checks, multi-stage builds.",
        ),
        (
            "Git hook documentation",
            "Documentation explaining how to set up git hooks for linting, "
            "formatting, testing. References to husky, pre-commit, lefthook.",
        ),
        (
            "CI/CD pipeline configs",
            "Legitimate GitHub Actions, GitLab CI, Jenkins pipeline configs. "
            "Standard build-test-deploy workflows with caching.",
        ),
        (
            "MCP server configs",
            "Legitimate MCP server configuration for filesystem access, "
            "database queries, API integrations. Proper tool definitions.",
        ),
        (
            "Package lifecycle scripts",
            "Legitimate package.json scripts: husky install, tsc --build, "
            "patch-package, node-gyp rebuild. Standard postinstall hooks.",
        ),
    ]

    all_samples = []
    for name, desc in subcategories:
        prompt = f"""Generate 50 completely benign text samples showing {name.lower()}.

Requirements:
- {desc}
- These are LEGITIMATE uses that a naive security scanner might flag as suspicious
- They contain keywords overlapping with attack patterns but are clearly benign
- Include realistic file paths, URLs (localhost, internal services), tool names
- Vary the format: code snippets, config files, documentation, comments

CRITICAL: All content must be genuinely benign. These test classifier precision.

Return 50 samples, one per line, no numbering."""

        print(f"  [I] Edge cases: {name}...")
        lines = generate_with_ollama(prompt)
        all_samples.extend(lines)
        print(f"      -> {len(lines)} samples")

    return all_samples


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stats: dict[str, dict] = {}
    all_samples: list[tuple[str, int]] = []  # (text, label)

    # --- Source A: Existing Pattern Payloads ---
    print("[A] Extracting pattern payloads from integration tests...")
    payloads = extract_payloads_from_test()
    for p in payloads:
        p = p.strip()
        if len(p) >= 10:
            all_samples.append((p, 1))
    stats["A: Pattern Payloads"] = {"count": len(payloads), "label": "malicious"}
    print(f"    -> {len(payloads)} samples")

    # --- Source B: PoC Attack Files ---
    print("[B] Loading PoC attack files...")
    poc_files = load_poc_files()
    for p in poc_files:
        all_samples.append((p, 1))
    stats["B: PoC Attack Files"] = {"count": len(poc_files), "label": "malicious"}
    print(f"    -> {len(poc_files)} samples")

    # --- Source C: Ollama Paraphrases ---
    print("[C] Generating paraphrased attack payloads (50 per category)...")
    rules = load_yaml_rules()
    paraphrases = generate_paraphrases(rules)
    for p in paraphrases:
        all_samples.append((p, 1))
    stats["C: Paraphrases"] = {"count": len(paraphrases), "label": "malicious"}

    # --- Source D: Evasion Variants ---
    print("[D] Generating evasion variants (20 per category)...")
    evasions = generate_evasion_variants(rules)
    for p in evasions:
        all_samples.append((p, 1))
    stats["D: Evasion Variants"] = {"count": len(evasions), "label": "malicious"}

    # --- Source E: Multi-file Attack Context ---
    print("[E] Generating multi-file attack contexts...")
    multifile = generate_multifile_attacks()
    for p in multifile:
        all_samples.append((p, 1))
    stats["E: Multi-file Attacks"] = {"count": len(multifile), "label": "malicious"}

    # --- Source F: Cross-Category Combinations ---
    print("[F] Generating cross-category combination attacks...")
    crosscat = generate_cross_category()
    for p in crosscat:
        all_samples.append((p, 1))
    stats["F: Cross-Category"] = {"count": len(crosscat), "label": "malicious"}

    # --- Source G: Benign Project Files ---
    print("[G] Generating benign project file content...")
    benign_files = generate_benign_project_files()
    for p in benign_files:
        all_samples.append((p, 0))
    stats["G: Benign Project Files"] = {"count": len(benign_files), "label": "benign"}

    # --- Source H: Hard Negatives ---
    print("[H] Generating hard negatives...")
    hard_negs = generate_hard_negatives()
    for p in hard_negs:
        all_samples.append((p, 0))
    stats["H: Hard Negatives"] = {"count": len(hard_negs), "label": "benign"}

    # --- Source I: Edge Cases ---
    print("[I] Generating edge cases...")
    edge_cases = generate_edge_cases()
    for p in edge_cases:
        all_samples.append((p, 0))
    stats["I: Edge Cases"] = {"count": len(edge_cases), "label": "benign"}

    # --- Deduplicate ---
    print("\nDeduplicating...")
    seen: set[str] = set()
    unique: list[tuple[str, int]] = []
    for text, label in all_samples:
        text = text.strip()
        if text and text not in seen and len(text) >= 10:
            seen.add(text)
            unique.append((text, label))
    print(f"  {len(all_samples)} -> {len(unique)} after dedup")

    # --- Shuffle ---
    random.seed(42)
    random.shuffle(unique)

    # --- Write JSONL ---
    print(f"\nWriting {len(unique)} samples to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for text, label in unique:
            line = json.dumps({"text": text, "label": label}, ensure_ascii=False)
            f.write(line + "\n")

    # --- Summary ---
    malicious = sum(1 for _, l in unique if l == 1)
    benign = sum(1 for _, l in unique if l == 0)

    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)
    print(f"{'Source':<30} {'Count':>8} {'Label':<10}")
    print("-" * 60)
    for source, info in stats.items():
        print(f"{source:<30} {info['count']:>8} {info['label']:<10}")
    print("-" * 60)
    print(f"{'Total (before dedup)':<30} {len(all_samples):>8}")
    print(f"{'Total (after dedup)':<30} {len(unique):>8}")
    print(f"{'Malicious':<30} {malicious:>8}")
    print(f"{'Benign':<30} {benign:>8}")
    print(f"{'Balance ratio (mal/ben)':<30} {malicious / max(benign, 1):>8.2f}")
    print("=" * 60)
    print(f"\nDataset written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
