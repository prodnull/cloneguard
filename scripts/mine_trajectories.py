#!/usr/bin/env python3
"""Mine tool-call sequences from trajectory datasets for benign baseline analysis.

Extracts action sequences from:
  - SWE-smith (tool split) — JSON messages with tool_calls
  - SWE-smith (xml/ticks splits) — XML-embedded function calls in content
  - Nebius SWE-agent — text-based commands in code blocks
  - OpenHands — OpenAI function-calling format

Classifies each action into canonical types:
  file_read, file_write, file_edit, bash_command, bash_read (cat/grep/find),
  bash_write (echo/tee/cp/mv), bash_build (pip/npm/make/pytest),
  bash_network (curl/wget), web_request, search, mcp_call, think, finish, other

Computes unigram, bigram, trigram frequencies.
Validates CloneGuard SEQ rules against benign distributions.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

from datasets import load_dataset

PROJ_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJ_ROOT / "data" / "trajectories"
OUT_DIR = DATA_DIR / "analysis"


# ── Action Classification ──────────────────────────────────────────────

BASH_READ_PATTERNS = re.compile(
    r"^\s*(cat|head|tail|less|more|wc|file|stat|ls|dir|find|locate|grep|rg|ag|ack|"
    r"tree|du|df|readlink|realpath|sha256sum|md5sum|sha1sum|xxd|hexdump|od)\b",
    re.IGNORECASE,
)
BASH_WRITE_PATTERNS = re.compile(
    r"^\s*(echo\s.*>|printf\s.*>|tee|cp|mv|mkdir|touch|chmod|chown|chgrp|ln\s|"
    r"rm\s|rmdir|install\s|rsync)\b",
    re.IGNORECASE,
)
BASH_BUILD_PATTERNS = re.compile(
    r"^\s*(pip|pip3|uv\s+pip|python\s+-m\s+pip|npm|npx|yarn|pnpm|bun|"
    r"cargo|go\s+(build|test|run|install)|make|cmake|mvn|gradle|"
    r"pytest|python\s+-m\s+pytest|unittest|nosetests|"
    r"ruff|mypy|pylint|flake8|black|isort|prettier|eslint|"
    r"python\s+setup\.py|python\s+-m\s+build|"
    r"docker\s+(build|compose)|"
    r"apt|apt-get|brew|conda)\b",
    re.IGNORECASE,
)
BASH_NETWORK_PATTERNS = re.compile(
    r"^\s*(curl|wget|fetch|http|ssh|scp|sftp|rsync\s+.*:|"
    r"git\s+(clone|fetch|pull|push)|"
    r"nc|ncat|netcat|nmap|ping|dig|nslookup|host)\b",
    re.IGNORECASE,
)

# ── Sensitive File Patterns ────────────────────────────────────────────
# Aligned with CloneGuard _SENSITIVE_FILE_PATTERNS but tightened to reduce FPs
# from source-code files (tokens.py, password.py, secretsmanager/models.py).

# Patterns specific enough for substring matching (low FP risk)
_SENSITIVE_EXACT_SUBSTRINGS = (
    ".env",           # dotenv files
    ".ssh/",          # SSH directory
    "id_rsa",         # SSH keys
    "id_ed25519",     # SSH keys
    "id_ecdsa",       # SSH keys
    ".aws/",          # AWS credentials
    ".azure/",        # Azure credentials
    ".kube/",         # Kubernetes config
    ".docker/config", # Docker auth
    ".netrc",         # network credentials
    ".pgpass",        # PostgreSQL passwords
    "kubeconfig",     # Kubernetes config
    "service_account", # GCP service accounts
    "serviceaccount",  # GCP service accounts
    "private_key",    # private key files
    "private-key",    # private key files
    "api_key",        # API key files
    "apikey",         # API key files
    "keyfile",        # key files
    "keystore",       # Java keystores
    "application_default_credentials",  # GCP ADC
    "auth.json",      # auth config
    ".gnupg/",        # GPG directory
    ".npmrc",         # npm auth
    ".pypirc",        # PyPI auth
)

# Extension-based patterns — only match as file extensions
_SENSITIVE_EXTENSIONS = (".pem", ".p12", ".pfx")

# Ambiguous terms — only match as standalone filenames/dirnames, not in source code
# Excludes: tokens.py, tokenizer.py, password.py, credentials.py, secrets.py, etc.
_SENSITIVE_BASENAME_RE = re.compile(
    r"(?:^|/)\.?(?:secrets?|credentials?|passwords?)"
    r"(?:\.(json|yaml|yml|txt|dat|conf|cfg|xml|toml|ini|properties))?$",
    re.IGNORECASE,
)

# .key — only as file extension, not substring of "keyboard.py" etc.
_KEY_EXT_RE = re.compile(r"\.key$", re.IGNORECASE)


def is_sensitive_path(path: str) -> bool:
    """Check if a file path matches tightened sensitive patterns."""
    fp = path.lower()

    # Exact substring matches (already specific enough)
    if any(p in fp for p in _SENSITIVE_EXACT_SUBSTRINGS):
        return True

    # Extension-based matches
    if any(fp.endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
        return True

    # .key as extension only
    if _KEY_EXT_RE.search(fp):
        return True

    # Ambiguous terms — match basename only, exclude source code extensions
    basename = fp.rsplit("/", 1)[-1] if "/" in fp else fp
    if _SENSITIVE_BASENAME_RE.search(basename):
        # Exclude common source code file extensions
        if not re.search(
            r"\.(py|js|ts|jsx|tsx|rb|go|rs|java|kt|cs|cpp|c|h|swift|php|scala)$",
            basename,
        ):
            return True

    return False


# SWE-agent built-in command patterns
SWEAGENT_COMMANDS = {
    "open": "file_read",
    "scroll_up": "file_read",
    "scroll_down": "file_read",
    "goto": "file_read",
    "search_file": "search",
    "search_dir": "search",
    "find_file": "search",
    "find": "search",
    "edit": "file_edit",
    "create": "file_write",
    "submit": "finish",
}

TOOL_NAME_MAP = {
    "bash": "bash_command",
    "execute_bash": "bash_command",
    "str_replace_editor": "file_edit",
    "str_replace": "file_edit",
    "view": "file_read",
    "think": "think",
    "finish": "finish",
    "task_tracker": "other",
}


def classify_bash_command(cmd: str) -> str:
    """Sub-classify a bash command string."""
    cmd = cmd.strip()
    if not cmd:
        return "bash_command"
    for line in cmd.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            cmd = line
            break
    if BASH_NETWORK_PATTERNS.match(cmd):
        return "bash_network"
    if BASH_BUILD_PATTERNS.match(cmd):
        return "bash_build"
    if BASH_WRITE_PATTERNS.match(cmd):
        return "bash_write"
    if BASH_READ_PATTERNS.match(cmd):
        return "bash_read"
    return "bash_command"


def classify_file_op(tool_name: str, args: dict | str) -> str:
    """Classify a file operation tool call."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return TOOL_NAME_MAP.get(tool_name, "other")
    if not isinstance(args, dict):
        return TOOL_NAME_MAP.get(tool_name, "other")
    cmd = args.get("command", "")
    if cmd == "view":
        return "file_read"
    if cmd in ("str_replace", "insert"):
        return "file_edit"
    if cmd == "create":
        return "file_write"
    return TOOL_NAME_MAP.get(tool_name, "other")


def extract_file_paths(tool_name: str, args: dict | str) -> list[str]:
    """Extract file paths from tool call arguments."""
    paths = []
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return paths
    if isinstance(args, dict):
        for key in ("path", "file", "file_path", "filename"):
            if key in args and isinstance(args[key], str):
                paths.append(args[key])
        cmd = args.get("command", "")
        if isinstance(cmd, str) and tool_name in ("bash", "execute_bash"):
            m = re.search(r"\b(cat|head|tail|less)\s+([^\s|>;]+)", cmd)
            if m:
                paths.append(m.group(2))
    return paths


# ── XML Function Call Parser ───────────────────────────────────────────

# Matches <function=tool_name> blocks in SWE-smith xml/ticks splits
_XML_FUNC_RE = re.compile(
    r"<function=(\w+)>(.*?)</function>",
    re.DOTALL,
)
_XML_PARAM_RE = re.compile(
    r"<parameter=(\w+)>(.*?)</parameter>",
    re.DOTALL,
)


def _parse_xml_function_calls(content: str) -> list[tuple[str, dict]]:
    """Extract (tool_name, args_dict) from XML-embedded function calls."""
    calls = []
    for m in _XML_FUNC_RE.finditer(content):
        tool_name = m.group(1)
        body = m.group(2)
        args = {}
        for pm in _XML_PARAM_RE.finditer(body):
            args[pm.group(1)] = pm.group(2)
        calls.append((tool_name, args))
    return calls


# ── Dataset Parsers ────────────────────────────────────────────────────

def _classify_tool_call(name: str, args: dict) -> tuple[str, list[str]]:
    """Classify a tool call and extract paths. Shared across parsers."""
    if name in ("bash", "execute_bash"):
        cmd = args.get("command", "")
        action_type = classify_bash_command(cmd)
        paths = extract_file_paths(name, args)
    elif name in ("str_replace_editor",):
        action_type = classify_file_op(name, args)
        paths = extract_file_paths(name, args)
    elif name == "think":
        action_type = "think"
        paths = []
    elif name == "finish":
        action_type = "finish"
        paths = []
    else:
        action_type = TOOL_NAME_MAP.get(name, "other")
        paths = extract_file_paths(name, args)
    return action_type, paths


def parse_swesmith_tool(row: dict) -> list[dict]:
    """Parse SWE-smith tool split — explicit tool_calls in assistant messages."""
    actions = []
    messages_str = row.get("messages", "")
    try:
        messages = json.loads(messages_str)
    except (json.JSONDecodeError, TypeError):
        return actions

    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        tool_calls = msg.get("tool_calls") or []
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            args_raw = fn.get("arguments", "")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except (json.JSONDecodeError, TypeError):
                args = {}
            if not isinstance(args, dict):
                args = {}

            action_type, paths = _classify_tool_call(name, args)
            sensitive = any(is_sensitive_path(p) for p in paths)
            actions.append({
                "type": action_type,
                "tool": name,
                "sensitive": sensitive,
                "paths": paths,
            })
    return actions


def parse_swesmith_xml(row: dict) -> list[dict]:
    """Parse SWE-smith xml split — XML-embedded function calls in content."""
    actions = []
    messages_str = row.get("messages", "")
    try:
        messages = json.loads(messages_str)
    except (json.JSONDecodeError, TypeError):
        return actions

    for msg in messages:
        if msg.get("role") != "assistant":
            continue

        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                part.get("text", "") for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        if not isinstance(content, str):
            continue

        xml_calls = _parse_xml_function_calls(content)
        for name, args in xml_calls:
            action_type, paths = _classify_tool_call(name, args)
            sensitive = any(is_sensitive_path(p) for p in paths)
            actions.append({
                "type": action_type,
                "tool": name,
                "sensitive": sensitive,
                "paths": paths,
            })
    return actions


# Regex for ticks-format commands: ```\ntool_name [args]\n```
_TICKS_CMD_RE = re.compile(r"```\s*\n?(.*?)\n?```", re.DOTALL)


def parse_swesmith_ticks(row: dict) -> list[dict]:
    """Parse SWE-smith ticks split — backtick-embedded tool commands in content.

    Format: ```\\nstr_replace_editor view /path --flag value\\n```
    or: ```\\nfind /testbed -name "file.py"\\n```
    """
    actions = []
    messages_str = row.get("messages", "")
    try:
        messages = json.loads(messages_str)
    except (json.JSONDecodeError, TypeError):
        return actions

    for msg in messages:
        if msg.get("role") != "assistant":
            continue

        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                part.get("text", "") for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        if not isinstance(content, str):
            continue

        for m in _TICKS_CMD_RE.finditer(content):
            cmd_text = m.group(1).strip()
            if not cmd_text:
                continue

            parts = cmd_text.split()
            first_word = parts[0] if parts else ""

            # Check if first word is a known tool name
            if first_word in ("str_replace_editor", "str_replace"):
                # Format: str_replace_editor view /path [--flags]
                sub_cmd = parts[1] if len(parts) > 1 else ""
                path = parts[2] if len(parts) > 2 else ""
                args = {"command": sub_cmd, "path": path}
                action_type, paths = _classify_tool_call("str_replace_editor", args)
            elif first_word == "bash":
                # Format: bash command_text (less common)
                actual_cmd = " ".join(parts[1:]) if len(parts) > 1 else ""
                args = {"command": actual_cmd}
                action_type, paths = _classify_tool_call("bash", args)
            else:
                # Bare command — treat as bash
                args = {"command": cmd_text}
                action_type = classify_bash_command(cmd_text)
                paths = extract_file_paths("bash", args)

            sensitive = any(is_sensitive_path(p) for p in paths)
            actions.append({
                "type": action_type,
                "tool": first_word,
                "sensitive": sensitive,
                "paths": paths,
            })
    return actions


def parse_sweagent(row: dict) -> list[dict]:
    """Parse Nebius SWE-agent — text-based commands in code blocks."""
    actions = []
    trajectory = row.get("trajectory", [])

    for step in trajectory:
        if step.get("role") != "ai":
            continue
        text = step.get("text", "")
        if not text:
            continue

        code_blocks = re.findall(r"```\s*\n?(.*?)\n?```", text, re.DOTALL)
        if not code_blocks:
            code_blocks = re.findall(r"```([^`]+)```", text)

        for block in code_blocks:
            cmd = block.strip()
            if not cmd:
                continue
            first_word = cmd.split()[0] if cmd.split() else ""
            if first_word in SWEAGENT_COMMANDS:
                action_type = SWEAGENT_COMMANDS[first_word]
                parts = cmd.split(maxsplit=1)
                paths = [parts[1].strip().split()[0]] if len(parts) > 1 else []
            else:
                action_type = classify_bash_command(cmd)
                paths = []
                m = re.search(r"\b(cat|head|tail|less|vim|nano)\s+([^\s|>;]+)", cmd)
                if m:
                    paths.append(m.group(2))

            sensitive = any(is_sensitive_path(p) for p in paths)
            actions.append({
                "type": action_type,
                "tool": first_word,
                "sensitive": sensitive,
                "paths": paths,
            })
    return actions


def parse_openhands(row: dict) -> list[dict]:
    """Parse OpenHands — OpenAI function-calling format."""
    actions = []
    trajectory = row.get("trajectory", [])

    for step in trajectory:
        if step.get("role") != "assistant":
            continue
        tool_calls = step.get("tool_calls")
        if not tool_calls:
            continue

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            args_raw = fn.get("arguments", "")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except (json.JSONDecodeError, TypeError):
                args = {}
            if not isinstance(args, dict):
                args = {}

            action_type, paths = _classify_tool_call(name, args)
            sensitive = any(is_sensitive_path(p) for p in paths)
            actions.append({
                "type": action_type,
                "tool": name,
                "sensitive": sensitive,
                "paths": paths,
            })
    return actions


# ── N-gram Analysis ────────────────────────────────────────────────────

def extract_ngrams(sequence: list[str], n: int) -> list[tuple[str, ...]]:
    return [tuple(sequence[i : i + n]) for i in range(len(sequence) - n + 1)]


# Config-like path patterns (SEQ-005)
_CONFIG_PATTERNS = re.compile(
    r"(\.vscode/|\.claude/|\.cursor/|\.continue/|\.windsurf/|\.gemini/|"
    r"mcp.*\.json|\.npmrc|\.pypirc|\.cargo/config|\.gitconfig|\.git/config)",
    re.IGNORECASE,
)


def analyze_dataset(
    name: str,
    parquet_path: str,
    parser_fn,
) -> dict:
    """Analyze a single dataset and return statistics."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {name}")
    print(f"  Loading {parquet_path}...")

    ds = load_dataset("parquet", data_files=parquet_path, split="train")
    total = len(ds)
    print(f"  {total} trajectories")

    unigrams: Counter = Counter()
    bigrams: Counter = Counter()
    trigrams: Counter = Counter()
    sensitive_actions: Counter = Counter()
    traj_lengths: list[int] = []

    seq_001_count = 0
    seq_004_count = 0
    seq_005_count = 0
    sensitive_read_total = 0
    config_write_total = 0

    errors = 0
    for i, row in enumerate(ds):
        if i % 10000 == 0 and i > 0:
            print(f"  processed {i}/{total}...")

        try:
            actions = parser_fn(row)
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  [error] row {i}: {e}")
            continue

        if not actions:
            continue

        types = [a["type"] for a in actions]
        traj_lengths.append(len(types))

        for t in types:
            unigrams[t] += 1

        for bg in extract_ngrams(types, 2):
            bigrams[bg] += 1
        for tg in extract_ngrams(types, 3):
            trigrams[tg] += 1

        # Sensitive action tracking
        for j, a in enumerate(actions):
            if a["sensitive"]:
                sensitive_actions[a["type"]] += 1

                if a["type"] in ("file_read", "bash_read"):
                    sensitive_read_total += 1
                    # SEQ-001: sensitive_read → network anywhere later in session
                    for k in range(j + 1, len(actions)):
                        if actions[k]["type"] in ("bash_network", "web_request"):
                            seq_001_count += 1
                            break

            # SEQ-005: config write → build
            if a["type"] in ("file_write", "file_edit"):
                for p in a.get("paths", []):
                    if _CONFIG_PATTERNS.search(p):
                        config_write_total += 1
                        for k in range(j + 1, len(actions)):
                            if actions[k]["type"] == "bash_build":
                                seq_005_count += 1
                                break

        # SEQ-004: file_write/edit → bash_build (within 10 steps)
        for j, a in enumerate(actions):
            if a["type"] in ("file_write", "file_edit"):
                for k in range(j + 1, min(j + 10, len(actions))):
                    if actions[k]["type"] == "bash_build":
                        seq_004_count += 1
                        break

    avg_len = sum(traj_lengths) / len(traj_lengths) if traj_lengths else 0
    total_actions = sum(unigrams.values())

    result = {
        "name": name,
        "total_trajectories": total,
        "parsed_trajectories": len(traj_lengths),
        "parse_errors": errors,
        "total_actions": total_actions,
        "avg_trajectory_length": round(avg_len, 1),
        "unigrams": dict(unigrams.most_common()),
        "top_bigrams": dict(bigrams.most_common(50)),
        "top_trigrams": dict(trigrams.most_common(30)),
        "sensitive_actions": dict(sensitive_actions.most_common()),
        "seq_rule_matches": {
            "seq_001_sensitive_read_then_network": seq_001_count,
            "seq_004_file_edit_then_build": seq_004_count,
            "seq_005_config_write_then_build": seq_005_count,
            "sensitive_read_total": sensitive_read_total,
            "config_write_total": config_write_total,
        },
    }

    print(f"\n  Parsed: {len(traj_lengths)}/{total} trajectories ({errors} errors)")
    print(f"  Total actions: {total_actions}")
    print(f"  Avg trajectory length: {avg_len:.1f} actions")
    print(f"\n  Action type distribution:")
    for action_type, count in unigrams.most_common():
        pct = count / total_actions * 100 if total_actions else 0
        print(f"    {action_type:20s}: {count:>8d} ({pct:5.1f}%)")
    print(f"\n  Top 20 bigrams:")
    for bg, count in bigrams.most_common(20):
        pct = count / sum(bigrams.values()) * 100 if bigrams else 0
        print(f"    {str(bg):55s}: {count:>8d} ({pct:5.2f}%)")
    print(f"\n  Sensitive file accesses: {sum(sensitive_actions.values())}")
    for st, count in sensitive_actions.most_common():
        print(f"    {st:20s}: {count}")
    print(f"\n  SEQ rule matches in benign data:")
    print(f"    SEQ-001 (sensitive_read → network):  {seq_001_count}")
    print(f"    SEQ-004 (file_edit → build):         {seq_004_count}")
    print(f"    SEQ-005 (config_write → build):      {seq_005_count}")
    print(f"    Total sensitive reads:               {sensitive_read_total}")
    print(f"    Total config writes:                 {config_write_total}")

    return result


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    all_results = {}

    datasets = [
        ("swesmith_tool", "SWE-smith (tool)", "swe-smith/tool.parquet", parse_swesmith_tool),
        ("swesmith_xml", "SWE-smith (xml)", "swe-smith/xml.parquet", parse_swesmith_xml),
        ("swesmith_ticks", "SWE-smith (ticks)", "swe-smith/ticks.parquet", parse_swesmith_ticks),
        ("nebius_sweagent", "Nebius SWE-agent", "nebius-sweagent/train.parquet", parse_sweagent),
        ("openhands", "OpenHands", "openhands/train.parquet", parse_openhands),
    ]

    for ds_key, ds_name, ds_file, parser in datasets:
        parquet_path = DATA_DIR / ds_file
        if parquet_path.exists():
            all_results[ds_key] = analyze_dataset(ds_name, str(parquet_path), parser)

    # Save results
    out_file = OUT_DIR / "trajectory_analysis.json"
    with open(out_file, "w") as f:
        serializable = {}
        for ds_name, result in all_results.items():
            r = dict(result)
            r["top_bigrams"] = {str(k): v for k, v in result["top_bigrams"].items()}
            r["top_trigrams"] = {str(k): v for k, v in result["top_trigrams"].items()}
            serializable[ds_name] = r
        json.dump(serializable, f, indent=2)
    print(f"\n\nResults saved to {out_file}")

    # Cross-dataset summary
    print("\n" + "=" * 60)
    print("CROSS-DATASET SUMMARY")
    print("=" * 60)

    total_traj = sum(r["parsed_trajectories"] for r in all_results.values())
    total_actions = sum(r["total_actions"] for r in all_results.values())
    total_sensitive = sum(
        sum(r["sensitive_actions"].values()) for r in all_results.values()
    )
    total_seq001 = sum(
        r["seq_rule_matches"]["seq_001_sensitive_read_then_network"]
        for r in all_results.values()
    )
    total_seq004 = sum(
        r["seq_rule_matches"]["seq_004_file_edit_then_build"]
        for r in all_results.values()
    )
    total_seq005 = sum(
        r["seq_rule_matches"]["seq_005_config_write_then_build"]
        for r in all_results.values()
    )
    total_sensitive_reads = sum(
        r["seq_rule_matches"]["sensitive_read_total"]
        for r in all_results.values()
    )
    total_config_writes = sum(
        r["seq_rule_matches"]["config_write_total"]
        for r in all_results.values()
    )

    print(f"Total trajectories analyzed: {total_traj}")
    print(f"Total actions extracted: {total_actions}")
    print(f"Total sensitive file accesses: {total_sensitive}")
    print()
    print("SEQ Rule FPR Estimates (benign data, tightened patterns):")
    print(f"  SEQ-001 (sensitive_read → network):")
    print(f"    Matches: {total_seq001} / {total_traj} trajectories")
    if total_traj:
        print(f"    FPR: {total_seq001 / total_traj * 100:.4f}%")
    print(f"  SEQ-004 (file_edit → build):")
    print(f"    Matches: {total_seq004} / {total_traj} trajectories")
    if total_traj:
        print(f"    FPR: {total_seq004 / total_traj * 100:.2f}%")
    print(f"  SEQ-005 (config_write → build):")
    print(f"    Matches: {total_seq005} / {total_traj} trajectories")
    if total_traj:
        print(f"    FPR: {total_seq005 / total_traj * 100:.4f}%")
    print(f"\n  Context:")
    print(f"    Sensitive reads across all data: {total_sensitive_reads}")
    print(f"    Config writes across all data:   {total_config_writes}")


if __name__ == "__main__":
    main()
