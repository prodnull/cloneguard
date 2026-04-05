# Codebase Structure

**Analysis Date:** 2026-04-05

## Directory Layout

```
cloneguard/
├── src/cloneguard/                 # Main package source
│   ├── __init__.py                 # Version declaration
│   ├── cli.py                      # CLI entry point (Layer 0 wrapper, subcommands)
│   ├── hooks.py                    # Hook handlers (Layers 1-3)
│   ├── patterns.py                 # Tier 1: PatternEngine + ScanMode/Verdict enums
│   ├── scanner.py                  # Layer 0: RepoScanner orchestrator
│   ├── mini_semantic.py            # Tier 1.5: ONNX MiniLM classifier
│   ├── semantic.py                 # Tier 2: Ollama LLM classifier
│   ├── monitor.py                  # Sequence rule monitoring (SEQ-001 to SEQ-006)
│   ├── allowlist.py                # User-local allowlist for false positives
│   ├── sequence_allowlist.py       # User-local allowlist for sequence rules
│   ├── trust_cache.py              # File-hash trust cache (amortize Tier 2 cost)
│   ├── mahalanobis.py              # OOD detection for mini semantic
│   ├── env_scanner.py              # Scan .env files for dangerous vars
│   ├── settings_scanner.py         # Scan .claude/settings.json for hook injection
│   ├── devcontainer_scanner.py     # Scan devcontainer.json for dangerous images/mounts
│   ├── mcp_plugin.py               # MCP protocol integration (future)
│   └── rules/                      # 25 YAML pattern rule files
│       ├── authority_impersonation.yaml
│       ├── behavioral_manipulation.yaml
│       ├── build_script_attacks.yaml
│       ├── cicd_poisoning.yaml
│       ├── config_file_injection.yaml
│       ├── credential_harvesting.yaml
│       ├── dangerous_agent_flags.yaml
│       ├── encoding_obfuscation.yaml
│       ├── env_var_hijacking.yaml
│       ├── exfiltration.yaml
│       ├── git_hook_exploitation.yaml
│       ├── hidden_instructions.yaml
│       ├── instruction_override.yaml
│       ├── lateral_movement.yaml
│       ├── malware_execution.yaml
│       ├── privilege_escalation.yaml
│       ├── process_substitution.yaml
│       ├── prompt_extraction.yaml
│       ├── regex_dos.yaml
│       ├── return_oriented_programming.yaml
│       ├── source_control_attacks.yaml
│       ├── symlink_attacks.yaml
│       ├── unsafe_deserialization.yaml
│       ├── url_redirection.yaml
│       └── webfetch_attacks.yaml
│   └── model/                      # Tier 1.5 model artifacts
│       ├── mini_semantic.onnx      # 87MB ONNX model (shipped with package)
│       ├── mahalanobis_params.npz  # Anomaly detection parameters
│       ├── config.json             # Tokenizer config
│       ├── vocab.txt               # Tokenizer vocabulary
│       └── tokenizer.json          # Fast tokenizer
│
├── tests/                          # Test suite (1,321 passing)
│   ├── __init__.py
│   ├── conftest.py                 # Pytest fixtures + helpers
│   ├── test_cli.py                 # CLI subcommands
│   ├── test_hooks.py               # Hook handlers (L1-3) — includes CircuitBreakerProof
│   ├── test_patterns.py            # PatternEngine + YAML rules
│   ├── test_monitor.py             # Sequence rule enforcement
│   ├── test_mini_semantic.py       # Tier 1.5 classifier
│   ├── test_semantic.py            # Tier 2 Ollama integration
│   ├── test_allowlist.py           # Allowlist mechanics
│   ├── test_env_scanner.py         # .env scanning
│   ├── test_devcontainer_scanner.py # devcontainer.json scanning
│   ├── test_settings_scanner.py    # .claude/settings.json scanning
│   ├── test_integration_all_patterns.py # Full pattern coverage
│   ├── test_evasion_resistance.py  # Adversarial robustness
│   ├── test_full_pattern_coverage.py # Rule enumeration
│   ├── test_monitor_enforcement.py # SEQ enforcement gates
│   ├── test_monitor_nyquist.py     # Frequency rule (SEQ-003)
│   ├── test_adversarial_sequences.py # Multi-event exfil patterns
│   ├── test_docker_integration.py  # Docker/devcontainer attacks
│   ├── test_trust_cache.py         # Cache invalidation
│   ├── test_adaptive_benchmark.py  # Adaptive red team eval
│   └── fixtures/                   # Test data
│       ├── benign_code/
│       ├── malicious_payloads/
│       ├── false_positive_samples/
│       └── edge_cases/
│
├── scripts/                        # Research and development scripts
│   ├── pentest/
│   │   ├── generate_attacks.py    # Adversarial payload generation
│   │   ├── phase2b_iterative_claude.py # Iterative refinement loop
│   │   ├── eval_auto_classifier.py # Claude Code classifier evaluation
│   │   └── check_regex.py         # Pattern validation
│   └── [training/mining scripts]
│
├── pyproject.toml                  # Package metadata, dependencies, build config
├── README.md                       # User-facing overview
├── docs/                           # Documentation (gitignored internal subdirs)
│   ├── USAGE.md                    # End-to-end usage guide
│   ├── SECURITY.md                 # Threat model, validation
│   ├── TESTING-AND-VALIDATION.md  # Independent reproduction
│   ├── MINI-SEMANTIC-MODEL.md     # Tier 1.5 architecture
│   ├── ADAPTIVE-RED-TEAM.md       # Methodology + results
│   └── papers/
│       ├── adaptive-red-team-arxiv-draft.md
│       └── latex/main.pdf
│
└── data/                           # Research datasets (gitignored)
    ├── benchmark/                  # Evaluation benchmarks
    ├── pentest/                    # Red team payloads + results
    ├── training/                   # MiniLM training data
    ├── redteam/                    # Arena + tool results
    └── trajectories/               # Agent trajectory mining (208K+ benign)
```

## Directory Purposes

**`src/cloneguard/`:**
- Purpose: Python package source — Layer 0/1/2/3 implementations, all pattern rules
- Contains: 16 .py modules, 25 YAML rule files, model artifacts
- Key files: `cli.py` (CLI entry), `hooks.py` (hook handlers), `scanner.py` (orchestration), `patterns.py` (Tier 1)

**`src/cloneguard/rules/`:**
- Purpose: 25 category-specific YAML pattern rule files (204 total patterns)
- Categories: authority_impersonation, behavioral_manipulation, build_script_attacks, cicd_poisoning, encoding_obfuscation, exfiltration, git_hook_exploitation, etc.
- Format: `category.yaml` with `patterns[]` array, each pattern has id, regex, severity, description
- Used by: PatternEngine._load_rule_file() at init time

**`src/cloneguard/model/`:**
- Purpose: Tier 1.5 model artifacts shipped with package (no external downloads)
- Contains: 87MB ONNX model, Mahalanobis parameters, tokenizer vocab
- Generated: Scripts in scripts/ (not committed; pre-built artifacts shipped)
- Loaded: Lazily by MiniSemanticClassifier._try_load()

**`tests/`:**
- Purpose: Full test suite (1,321 passing tests)
- Coverage: CLI, hooks, patterns (rule by rule), semantic classifiers, allowlist, sequence rules, integration scenarios, adversarial robustness
- Fixtures: Benign code samples, malicious payloads, false-positive samples, edge cases
- CI: Run via pytest with coverage tracking

**`scripts/pentest/`:**
- Purpose: Research and adversarial evaluation harnesses
- Key scripts: `generate_attacks.py` (adaptive payload generation), `phase2b_iterative_claude.py` (iterative refinement), `eval_auto_classifier.py` (Claude Code classifier evaluation)
- Note: Not shipped with package; used for research only

**`docs/`:**
- Purpose: User documentation and research papers
- Public: `USAGE.md`, `SECURITY.md`, `TESTING-AND-VALIDATION.md` (tracked)
- Internal (gitignored): `papers/`, `research/`, `plans/`, `results/`

**`data/`:**
- Purpose: Evaluation datasets and research artifacts (gitignored)
- Contents: Benchmark files (benign_eval_500.json, benign_eval_751.json), pentest results, trajectory mining (208,127 trajectories from SWE-smith/Nebius/OpenHands)

## Key File Locations

**Entry Points:**
- `src/cloneguard/cli.py::main()`: CLI wrapper (Layer 0, subcommands)
- `src/cloneguard/hooks.py::main()`: Hook handler (Layers 1-3)
- `src/cloneguard/scanner.py::RepoScanner.scan()`: Layer 0 orchestrator

**Configuration:**
- `pyproject.toml`: Package metadata, dependencies (pyyaml, optional: onnxruntime, transformers, ollama)
- Hook config template: `src/cloneguard/cli.py::_HOOK_CONFIG` (injected into settings.json)

**Core Logic:**
- Pattern scanning: `src/cloneguard/patterns.py::PatternEngine` (regex, 25 YAML rules)
- Tier 1.5 semantic: `src/cloneguard/mini_semantic.py::MiniSemanticClassifier` (ONNX)
- Tier 2 semantic: `src/cloneguard/semantic.py::SemanticClassifier` (Ollama)
- Sequence rules: `src/cloneguard/monitor.py::ToolCallMonitor` (SEQ-001 to SEQ-006)
- Repository scan: `src/cloneguard/scanner.py::RepoScanner` (orchestrator for Layer 0)

**Testing:**
- Integration tests: `tests/test_integration_all_patterns.py` (all 204 patterns)
- Hook tests: `tests/test_hooks.py` (L1-3 handlers, including CircuitBreakerProof)
- Sequence tests: `tests/test_monitor_enforcement.py` (SEQ enforcement gates)
- Evasion tests: `tests/test_evasion_resistance.py` (adversarial robustness)

## Naming Conventions

**Files:**
- Core modules: lowercase_with_underscores.py (e.g., `pattern_engine.py`, `mini_semantic.py`)
- Tests: `test_<module>.py` (e.g., `test_patterns.py`)
- Rule files: lowercase_with_underscores.yaml (e.g., `authority_impersonation.yaml`)
- Configuration: UPPERCASE.json or UPPERCASE.toml (e.g., `pyproject.toml`, `settings.json`)

**Directories:**
- Package root: src/cloneguard/
- Tests: tests/
- Rules: src/cloneguard/rules/
- Scripts: scripts/
- Documentation: docs/
- Data: data/

**Classes:**
- PascalCase: PatternEngine, MiniSemanticClassifier, RepoScanner, ToolCallMonitor
- Enums: PascalCase (Severity, Verdict, ScanMode, Status)
- Dataclasses: PascalCase (ScanResult, PatternMatch, SemanticResult, SemanticFinding)

**Functions:**
- Module-level public: snake_case (e.g., `detect_yolo_mode()`, `handle_scan()`)
- Module-level private (underscore prefix): snake_case (e.g., `_content_hash()`, `_normalize_path()`)
- Methods: snake_case (e.g., `engine.scan()`, `classifier.classify()`)

**Pattern/Rule IDs:**
- Format: `<CATEGORY>-<NUMBER>` (e.g., `EX-001` for exfiltration, `AU-001` for authority_impersonation)
- Sequence rules: `SEQ-<NUMBER>` (SEQ-001 to SEQ-006)

## Where to Add New Code

**New Prompt Injection Pattern:**
1. Create/edit YAML rule file: `src/cloneguard/rules/<category>.yaml`
2. Add pattern dict to `patterns[]`: id, regex, severity, description, false_positive_hint
3. Test with integration test: `tests/test_integration_all_patterns.py`
4. (Optional) Add specific test case: `tests/test_patterns.py`

**New Layer 1.5 Classifier Feature:**
- Implementation: `src/cloneguard/mini_semantic.py::MiniSemanticClassifier`
- Related: `src/cloneguard/mahalanobis.py` (anomaly detection)
- Tests: `tests/test_mini_semantic.py`

**New Sequence Rule (SEQ-NNN):**
1. Add rule logic: `src/cloneguard/monitor.py::ToolCallMonitor.check_enforcement()`
2. Define sensitive file patterns or tool keywords in constants at module top
3. Add test: `tests/test_monitor_enforcement.py` or new file `tests/test_monitor_<name>.py`
4. Document enforcement/advisory mode in monitor.py docstring

**New CLI Subcommand:**
1. Add argparse subparser: `src/cloneguard/cli.py::parse_args()` (add to subparsers)
2. Add handler function: `src/cloneguard/cli.py::handle_<command>()`
3. Add dispatch: `src/cloneguard/cli.py::main()` (add to if/elif chain)
4. Test: `tests/test_cli.py`

**New Hook Layer or Event:**
- Implementation: `src/cloneguard/hooks.py` (add handler or extend existing)
- Related: May require changes to `src/cloneguard/monitor.py` (sequence event recording)
- Tests: `tests/test_hooks.py`

**New Layer 0 Scanner (e.g., for .x-config files):**
1. Create module: `src/cloneguard/<domain>_scanner.py` (e.g., `npm_scanner.py`)
2. Implement ScanResult + ScanFinding pattern (see `env_scanner.py` for example)
3. Integrate: `src/cloneguard/scanner.py::RepoScanner.scan()` (add call to new scanner)
4. Test: `tests/test_<domain>_scanner.py`

## Special Directories

**`.planning/codebase/`:**
- Purpose: Generated codebase mapping documents (this directory)
- Files: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md
- Generated: Not committed; created by GSD mapping tool

**`~/.cloneguard/` (User Home):**
- Purpose: User-local allowlists and caches (outside repo, never committed)
- Contents:
  - `allowlist.json`: Content-hash keyed false positive suppressions
  - `sequence_allowlist.json`: Domain/path whitelists for SEQ rule escapes
  - `trust-cache.json`: File-hash cache of scanned files (Layer 0 Tier 2 amortization)
- Access: Loaded/saved by Allowlist, SequenceAllowlist, TrustCache classes
- Permissions: Only human can approve entries (CLI guards on --no-tty)

**`.claude/` (Project or Global):**
- Purpose: Per-project or global Claude Code configuration
- Hook config: Injected by `cloneguard init --project|--global` as `hooks` section in settings.json
- Not created by CloneGuard; modified in-place by handler

---

*Structure analysis: 2026-04-05*
