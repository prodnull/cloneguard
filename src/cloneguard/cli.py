"""CloneGuard CLI — Layer 0 wrapper for the claude command.

Pre-scans repository files for prompt injection before launching the agent.
Cannot be disabled by repository content because it runs before the agent starts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from cloneguard import __version__
from cloneguard.scanner import RepoScanner

# Default global claude config directory.
GLOBAL_CLAUDE_DIR = Path.home() / ".claude"

# Hook configuration template injected by `cloneguard init`.
_HOOK_CONFIG = {
    "hooks": {
        "InstructionsLoaded": [
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": "cloneguard hook-check --event InstructionsLoaded",
                    }
                ],
            }
        ],
        "PreToolUse": [
            {
                "matcher": "Bash|Edit|Write|NotebookEdit",
                "hooks": [
                    {
                        "type": "command",
                        "command": "cloneguard hook-check --event PreToolUse",
                    }
                ],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": "cloneguard hook-check --event PostToolUse",
                    }
                ],
            }
        ],
    }
}


def detect_yolo_mode(argv: list[str]) -> bool:
    """Return True if --dangerously-skip-permissions is present in argv."""
    return "--dangerously-skip-permissions" in argv


def parse_args(argv: list[str] | None = None) -> tuple[argparse.Namespace, list[str]]:
    """Parse CLI arguments, returning (namespace, remaining_args_for_claude)."""
    parser = argparse.ArgumentParser(
        prog="cloneguard",
        description=f"CloneGuard v{__version__} — Prompt injection defense for AI coding agents",
    )
    parser.add_argument("--version", action="version", version=f"CloneGuard v{__version__}")
    parser.add_argument(
        "--bypass",
        action="store_true",
        help="Skip pre-scan and launch claude directly (NOT RECOMMENDED)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # cloneguard scan [path]
    scan_parser = subparsers.add_parser("scan", help="Standalone repository scan")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to repository (default: current directory)",
    )
    scan_parser.add_argument(
        "--tier2",
        action="store_true",
        help="Enable semantic classification (mini ONNX model, falls back to Ollama)",
    )
    scan_parser.add_argument(
        "--tier2-model",
        default=None,
        help="Force specific Ollama model for Tier 2 (skips mini model)",
    )
    scan_parser.add_argument(
        "--cache",
        action="store_true",
        help="Enable trust cache (skip re-scanning unchanged files)",
    )
    scan_parser.add_argument(
        "--sarif",
        action="store_true",
        help="Output results in SARIF 2.1.0 format (D-08)",
    )

    # cloneguard setup
    subparsers.add_parser(
        "setup",
        help="Full onboarding: install hooks + shell alias in one step",
    )

    # cloneguard allow <file> [--reason ...]
    allow_parser = subparsers.add_parser(
        "allow",
        help="Allowlist a file by content hash (suppresses false positives)",
    )
    allow_parser.add_argument("file", help="File to allowlist")
    allow_parser.add_argument(
        "--reason", default="", help="Reason for allowlisting (informational)"
    )

    # cloneguard list
    subparsers.add_parser("list", help="List allowlisted files")

    # cloneguard remove <file|hash>
    remove_parser = subparsers.add_parser("remove", help="Remove a file or hash from the allowlist")
    remove_parser.add_argument("target", help="File path or content hash to remove")

    # cloneguard init
    init_parser = subparsers.add_parser("init", help="Install hook configuration")
    scope_group = init_parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument("--project", action="store_true", help="Write project-level config")
    scope_group.add_argument(
        "--global", dest="global_scope", action="store_true", help="Write global config"
    )
    init_parser.add_argument(
        "--trust-cache", action="store_true", help="Set up trust cache directory"
    )

    # cloneguard check-hooks
    subparsers.add_parser(
        "check-hooks",
        help="Verify hook configuration integrity (CVE-2025-59536 defense, D-13)",
    )

    # cloneguard hook-check --event <EventName>
    # Called by Claude Code hook configuration. Reads JSON from stdin,
    # dispatches to the appropriate hook handler in hooks.py.
    hook_parser = subparsers.add_parser(
        "hook-check", help="Hook handler entry point (called by agent hook config)"
    )
    hook_parser.add_argument(
        "--event",
        required=True,
        help="Hook event name (InstructionsLoaded, PreToolUse, PostToolUse)",
    )

    return parser.parse_known_args(argv)


def handle_bypass(remaining_args: list[str]) -> None:
    """Print warning and exec claude without scanning."""
    print(
        "WARNING: CloneGuard bypassed — no pre-scan protection active.",
        file=sys.stderr,
    )
    os.execvp("claude", ["claude"] + remaining_args)


def handle_scan(
    path_str: str,
    tier2: bool = False,
    tier2_model: str | None = None,
    cache: bool = False,
    sarif: bool = False,
) -> int:
    """Run standalone scan and return exit code.

    When --sarif is set or CLONEGUARD_SARIF_OUTPUT env var is set, SARIF 2.1.0
    output is produced (D-08). --sarif writes to stdout; env var writes to file
    while human-readable report still goes to stdout.
    """
    repo_path = Path(path_str).resolve()
    scanner = RepoScanner(tier2=tier2, tier2_model=tier2_model, cache=cache)
    report = scanner.scan(repo_path)

    sarif_output_path = os.environ.get("CLONEGUARD_SARIF_OUTPUT", "")
    emit_sarif = sarif or bool(sarif_output_path)

    if emit_sarif:
        from cloneguard.audit.sarif import SARIFEmitter, _build_rules_from_patterns
        from cloneguard.detection.patterns import PatternEngine

        # Convert ScanReport file results to SARIF-compatible dicts
        scan_results = _scan_report_to_sarif_dicts(report)
        engine = PatternEngine()
        rules = _build_rules_from_patterns(engine)
        emitter = SARIFEmitter()
        sarif_json = emitter.emit_json(scan_results, rules=rules)

        if sarif_output_path:
            # Write SARIF to file, human report to stdout
            Path(sarif_output_path).write_text(sarif_json + "\n", encoding="utf-8")
            color = sys.stdout.isatty()
            print(report.format(color=color))
        else:
            # --sarif flag: SARIF to stdout
            print(sarif_json)
    else:
        color = sys.stdout.isatty()
        print(report.format(color=color))

    return report.exit_code


def _scan_report_to_sarif_dicts(report: Any) -> list[dict[str, Any]]:
    """Convert a ScanReport's FileResults to SARIF-compatible result dicts."""
    results: list[dict[str, Any]] = []
    for fr in report.file_results:
        # Each issue string in FileResult represents a detection
        for issue in fr.issues:
            # Parse issue strings to extract structured data
            # Issues are formatted as "[SEVERITY] description" in the report
            severity = "medium"
            verdict = "detected"
            if "BLOCKED" in str(fr.status.value):
                verdict = "detected"
            elif "WARNING" in str(fr.status.value):
                verdict = "suspicious"
            elif "CLEAN" in str(fr.status.value):
                verdict = "clean"

            results.append({
                "verdict": verdict,
                "severity": severity,
                "rule_id": "PATTERN",
                "file_path": fr.path,
                "line_number": 1,
                "matched_text": issue,
                "message": issue,
            })
    return results


def handle_init(
    scope: str,
    repo_path: Path | None = None,
    trust_cache: bool = False,
) -> None:
    """Write hook configuration to settings.json."""
    if scope == "global":
        target_dir = GLOBAL_CLAUDE_DIR
    else:
        target_dir = (repo_path or Path.cwd()) / ".claude"

    target_dir.mkdir(parents=True, exist_ok=True)
    settings_path = target_dir / "settings.json"

    # Merge with existing settings if present
    existing: dict[str, Any] = {}
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    existing.update(_HOOK_CONFIG)
    settings_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote hook config to {settings_path}")

    if trust_cache:
        cache_dir = target_dir / "trust-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created trust cache at {cache_dir}")


def _detect_shell_rc() -> Path | None:
    """Detect the user's shell RC file."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()
    if "zsh" in shell:
        return home / ".zshrc"
    if "bash" in shell:
        # Prefer .bashrc on Linux, .bash_profile on macOS
        bashrc = home / ".bashrc"
        bash_profile = home / ".bash_profile"
        if sys.platform == "darwin" and bash_profile.exists():
            return bash_profile
        return bashrc
    if "fish" in shell:
        return home / ".config" / "fish" / "config.fish"
    return None


def _alias_line(shell_rc: Path) -> str:
    """Return the appropriate alias line for the detected shell."""
    if "fish" in str(shell_rc):
        return 'alias claude "cloneguard"'
    return "alias claude='cloneguard'"


def handle_setup() -> None:
    """Full onboarding: global hooks + shell alias in one step."""
    print(f"CloneGuard v{__version__} — Setup\n")

    # Step 1: Install global hooks
    print("Step 1: Installing global hooks...")
    handle_init(scope="global", trust_cache=True)
    print()

    # Step 2: Shell alias
    print("Step 2: Shell alias")
    shell_rc = _detect_shell_rc()
    if shell_rc is None:
        print("  Could not detect shell. Add this alias manually:")
        print("    alias claude='cloneguard'")
        print()
    else:
        alias = _alias_line(shell_rc)
        # Check if alias already exists
        existing = ""
        if shell_rc.exists():
            existing = shell_rc.read_text(encoding="utf-8")

        if "alias claude=" in existing or 'alias claude "' in existing:
            print(f"  Alias already present in {shell_rc}")
        elif sys.stdin.isatty():
            print(f"  Add to {shell_rc}:")
            print(f"    {alias}")
            try:
                answer = input("  OK? [Y/n] ")
            except (EOFError, KeyboardInterrupt):
                answer = "n"
            if answer.strip().lower() != "n":
                marker = "\n# CloneGuard — prompt injection defense\n"
                with open(shell_rc, "a", encoding="utf-8") as f:
                    f.write(f"{marker}{alias}\n")
                print(f"  Written to {shell_rc}")
            else:
                print("  Skipped. Add manually when ready.")
        else:
            print(f"  Non-interactive — add this to {shell_rc}:")
            print(f"    {alias}")

    # Step 3: Summary
    print()
    print("Done. To activate:")
    if shell_rc:
        print(f"  source {shell_rc}")
    print()
    print("Then just use 'claude' as normal — CloneGuard protects automatically.")
    print("  Layer 0: Pre-execution scan (runs before agent starts)")
    print("  Layer 1: InstructionsLoaded hook (scans CLAUDE.md)")
    print("  Layer 2: PostToolUse hook (scans all tool output)")
    print("  Layer 3: PreToolUse hook (gates writes + build scripts)")


def handle_allow(file: str, reason: str) -> None:
    """Add a file to the allowlist by content hash.

    Requires an interactive terminal. Refuses in non-interactive mode
    to prevent AI agents from silently allowlisting malicious files.
    """
    from cloneguard.allowlist import Allowlist

    if not sys.stdin.isatty():
        print(
            "REFUSED: 'cloneguard allow' requires an interactive terminal.\n"
            "An AI agent cannot allowlist files — only a human can.",
            file=sys.stderr,
        )
        sys.exit(1)

    path = Path(file).resolve()
    if not path.is_file():
        print(f"Error: {file} is not a file.", file=sys.stderr)
        sys.exit(1)

    print(f"Allowlist {path.name}?")
    print(f"  Hash will be computed from current content ({path.stat().st_size} bytes).")
    if reason:
        print(f"  Reason: {reason}")
    try:
        answer = input("Confirm? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() != "y":
        print("Cancelled.")
        sys.exit(0)

    h = Allowlist().add(path, reason=reason)
    print(f"Allowlisted {path.name} [{h[:12]}]")


def handle_list() -> None:
    """List all allowlisted files."""
    from cloneguard.allowlist import Allowlist

    entries = Allowlist().list_entries()
    if not entries:
        print("Allowlist is empty.")
        return
    for e in entries:
        short_hash = e.content_hash[:12]
        reason_str = f"  ({e.reason})" if e.reason else ""
        print(f"  {short_hash}  {e.path_hint}{reason_str}")


def handle_remove(target: str) -> None:
    """Remove a file or hash from the allowlist.

    Requires an interactive terminal for the same reason as allow.
    """
    if not sys.stdin.isatty():
        print(
            "REFUSED: 'cloneguard remove' requires an interactive terminal.",
            file=sys.stderr,
        )
        sys.exit(1)

    from cloneguard.allowlist import Allowlist

    if Allowlist().remove(target):
        print(f"Removed from allowlist: {target}")
    else:
        print(f"Not found in allowlist: {target}", file=sys.stderr)
        sys.exit(1)


def handle_wrap(remaining_args: list[str]) -> None:
    """Pre-scan then launch claude with remaining args."""
    repo_path = Path.cwd().resolve()
    yolo = detect_yolo_mode(remaining_args)

    if yolo:
        print(
            "YOLO mode detected — CloneGuard enforcing stricter scanning",
            file=sys.stderr,
        )

    scanner = RepoScanner(yolo_mode=yolo, tier2=True, cache=True)
    report = scanner.scan(repo_path)
    color = sys.stderr.isatty()
    print(report.format(color=color), file=sys.stderr)

    if report.exit_code == 2:
        print("\nBLOCKED: Critical issues found. Refusing to launch claude.", file=sys.stderr)
        sys.exit(2)
    elif report.exit_code == 1:
        # Prompt user
        if sys.stdin.isatty():
            try:
                answer = input("\nIssues found. Proceed? [y/N] ")
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer.strip().lower() != "y":
                print("Aborted.", file=sys.stderr)
                sys.exit(1)
        else:
            # Non-interactive: refuse on warnings
            print("\nNon-interactive mode — refusing to proceed with warnings.", file=sys.stderr)
            sys.exit(1)

    # Launch claude
    os.execvp("claude", ["claude"] + remaining_args)


def main(argv: list[str] | None = None) -> None:
    """Entry point for the cloneguard CLI."""
    args, remaining = parse_args(argv)

    if args.bypass:
        handle_bypass(remaining)
        return  # unreachable after execvp, but satisfies type checker

    if args.command == "scan":
        code = handle_scan(
            args.path,
            tier2=args.tier2 or bool(args.tier2_model),
            tier2_model=args.tier2_model,
            cache=args.cache,
            sarif=args.sarif,
        )
        sys.exit(code)

    if args.command == "allow":
        handle_allow(args.file, args.reason)
        return

    if args.command == "list":
        handle_list()
        return

    if args.command == "remove":
        handle_remove(args.target)
        return

    if args.command == "setup":
        handle_setup()
        return

    if args.command == "init":
        scope = "global" if args.global_scope else "project"
        handle_init(scope=scope, trust_cache=args.trust_cache)
        return

    if args.command == "check-hooks":
        from cloneguard.integrity import check_hook_integrity

        warnings = check_hook_integrity()
        if warnings:
            for w in warnings:
                print(f"WARNING: {w}", file=sys.stderr)
            sys.exit(1)
        else:
            print("Hook configuration OK.")
        return

    if args.command == "hook-check":
        # Lightweight startup integrity check (once per process, D-13)
        if not os.environ.get("_CLONEGUARD_INTEGRITY_CHECKED"):
            import logging as _logging

            _logger = _logging.getLogger("cloneguard.integrity")
            try:
                from cloneguard.integrity import check_hook_integrity

                integrity_warnings = check_hook_integrity()
                for w in integrity_warnings:
                    _logger.warning("Hook integrity: %s", w)
            except Exception:
                pass  # Never block hook execution on integrity check failure
            os.environ["_CLONEGUARD_INTEGRITY_CHECKED"] = "1"

        from cloneguard.hooks import main as hooks_main

        hooks_main()
        return

    # Default: wrap claude
    handle_wrap(remaining)


if __name__ == "__main__":
    main()
