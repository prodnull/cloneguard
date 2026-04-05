# CloneGuard — Project Rules

## Gitignored Directories Are Sacred

**NEVER `git add -f` files from gitignored directories without explicit user approval.** This includes `docs/publications/`, `docs/plans/`, `docs/research/`, `docs/results/`, `docs/correspondence/`, `docs/sub-agents/`. These directories are gitignored for a reason — drafts, internal notes, and unpublished work must not leak to the public repo. Ask before publishing. No exceptions.

<!-- GSD:project-start source:PROJECT.md -->
## Project

**CloneGuard v2: Universal Agentic Defense**

CloneGuard evolves from a coding-agent prompt injection scanner into a universal agentic defense layer — the independent trust boundary between any AI agent and any execution environment. It detects, constrains, and audits tool calls across agent platforms from a position the agent itself cannot compromise.

**Core Value:** The only vendor-neutral, sandbox-agnostic defense layer that fuses pattern + semantic + behavioral signals to detect prompt injection, then enforces adaptive constraints — not just allow/block but allow-but-constrain — across any agent type.

### Constraints

- **Tech stack**: Python 3.11+, ONNX Runtime for inference, no external service dependencies for core detection
- **Performance**: <20ms per hook invocation for Tier 0+1.5, <370ms full repo scan
- **Backward compatibility**: NoopAdapter must preserve current v0.5.0 exit-code behavior exactly
- **Security**: Layer 0 runs BEFORE agent — position must remain uncompromisable by repo content
- **Packaging**: Must support `uv tool install` / `pipx` standalone binary
- **Open-core split**: Core detection + basic adapters open source; enterprise features (fleet mgmt, compliance exports, SIEM integrations) proprietary
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.11+ (3.11, 3.12, 3.13 tested)
## Runtime
- Python 3.11, 3.12, 3.13 (minimum: 3.11)
- uv (setup orchestration, lockfile management)
- pip (transitive, used via uv)
## Frameworks & Core Libraries
- PyYAML >=6.0 - Pattern file parsing (YAML rules in `src/cloneguard/rules/`)
- onnxruntime >=1.17 - Tier 1.5 semantic inference (ONNX Runtime, CPU execution provider)
- transformers >=4.36 - Tokenizer for mini semantic classifier (loads from `src/cloneguard/model/`)
- numpy >=1.26 - Numerical operations for Mahalanobis anomaly detection
- ollama >=0.4 - Tier 2 fallback semantic classification via local Ollama service
- mcp-gateway - MCP plugin system (not shipped, optional for MCP server deployment)
## Build & Development
- hatchling (build backend)
- setuptools (transitive)
- pytest >=8.0 - Test runner
- pytest-cov >=6.0 - Coverage reporting
- ruff >=0.8 - Linting and formatting (strict: E, F, I, N, W, UP rules)
- mypy >=1.13 - Static type checking (strict mode enabled)
- types-PyYAML >=6.0 - Type stubs for PyYAML
## ML Model Assets
- **mini_semantic.onnx** (90.8 MB) - Fine-tuned sentence-transformers/all-MiniLM-L6-v2 for prompt injection detection
- **mahalanobis_params.npz** (2.4 MB) - Pre-fitted Mahalanobis detector parameters
- Location: `src/cloneguard/model/`
- Files: `tokenizer.json` (712 KB), `vocab.txt` (232 KB), `tokenizer_config.json`, `special_tokens_map.json`
- Source: all-MiniLM-L6-v2 tokenizer (WordPiece, 256-token max length)
## Pattern Rules
- 25 YAML rule files in `src/cloneguard/rules/`
- 204+ total patterns (as of commit 5ccfccd)
- Categories: instruction override, credential harvesting, encoding evasion, behavioral manipulation, exfiltration, privilege escalation, CI/CD poisoning, and more
- `authority_impersonation.yaml` - Fake [SYSTEM] messages, vendor impersonation
- `exfiltration.yaml` - env var, API key, credential harvesting patterns
- `instruction_override.yaml` - Ignore previous instructions, prompt override attempts
## Configuration
- `HF_TOKEN` - (CI only) Hugging Face token for model artifact fetching
- `CLONEGUARD_REVIEW_LOG` - Optional path to low-confidence classification review log (JSONL)
- `CLONEGUARD_REVIEW_THRESHOLD` - Confidence threshold for review logging (default: 0.98)
- Threshold overrides for each ScanMode (e.g., `CLONEGUARD_THRESHOLD_STRICT_SUSPICIOUS`)
- `~/.claude/settings.json` - Global hook configuration (installed by `cloneguard init --global`)
- `.claude/settings.json` - Project-level hook configuration (installed by `cloneguard init --project`)
- `InstructionsLoaded` - Scan CLAUDE.md when loaded
- `PreToolUse` - Gate writes, builds, config changes
- `PostToolUse` - Scan all tool output
## Platform Requirements
- macOS 10.15+ or Linux (tested on ubuntu-latest and macos-latest)
- Python 3.11+ development environment
- uv package manager (modern Python workflow)
- Linux (ubuntu-latest primary CI target) or macOS
- Python 3.11+ runtime
- For Tier 1.5: 87 MB disk space for ONNX model + 2.4 MB for Mahalanobis params
- For Tier 2: Local Ollama service (if enabled)
- AI coding agents: Claude Code, Gemini CLI, Codex CLI, Cursor, GitHub Copilot
- CI/CD pipelines (Docker container integration tested via `tests/integration/`)
- MCP Gateway plugin system (optional)
- Standalone CLI tool (no agent required for `cloneguard scan`)
## Packaging
- Source: `src/cloneguard/`
- ONNX model artifact: `src/cloneguard/model/mini_semantic.onnx` (verified in release CI)
- Entry point: `cloneguard = cloneguard.cli:main`
- Published to PyPI (when available)
- GitHub Releases include `.whl` with embedded ONNX model
- Optional extras: `[mini]` (ONNX runtime + dependencies), `[semantic]` (Ollama), `[all]` (both)
## Testing Infrastructure
- Python 3.11, 3.12, 3.13 on ubuntu-latest (CI job: `test`)
- macOS latest (CI job: `test-macos`)
- Docker integration tests (CI job: `integration`)
- Ollama-based Tier 2 tests (CI job: `test-tier2`)
- pytest with coverage tracking (target: 85%+)
- Test markers: `@pytest.mark.ollama` for Tier 2-specific tests
- Security-specific tests: `tests/test_security_vectors.py`
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Lowercase snake_case for module files: `patterns.py`, `monitor.py`, `semantic.py`
- Underscore prefix for private modules: `_strict_basenames` (constants), internal helpers
- Test files follow `test_*.py` naming convention
- snake_case for all function names (public and private)
- Prefix with `_` for private/internal functions: `_get_engine()`, `_detect_mode()`
- Descriptive names indicating purpose: `record_event()`, `check_enforcement()`, `classify()`
- snake_case for all variables: `session_id`, `tool_input`, `malicious_threshold`
- ALL_CAPS for module-level constants: `_MAX_SESSION_EVENTS`, `_SAFE_HOSTS`, `_STRICT_BASENAMES`
- Type-annotated throughout: `session_id: str`, `events: list[dict]`
- PascalCase for class names: `PatternEngine`, `ToolCallMonitor`, `SemanticClassifier`
- PascalCase for Enum names: `Severity`, `Verdict`, `ScanMode`, `SemanticVerdict`
- Type hints use modern Python 3.11+ syntax: `dict[str, Any]`, `list[PatternMatch]`, `Path | None`
## Code Style
- Ruff with line-length 100 (configured in `pyproject.toml`)
- `from __future__ import annotations` at module top for forward-compatible type hints
- Docstrings: module-level at top in triple quotes, with description of purpose and design
- Ruff rules: `["E", "F", "I", "N", "W", "UP"]` (style, undefined, imports, naming, whitespace, upgrades)
- mypy strict mode enforced: `python_version = "3.11"` + `strict = true`
- Import sort via Ruff: groups from `__future__`, stdlib, third-party, local
- Try-except blocks surround external dependencies that may fail to import: `from cloneguard.mini_semantic import MiniSemanticClassifier`
- Pass silently on ImportError for optional dependencies; return `None` or `False`
- Broad `except Exception` only in subprocess/network contexts where failure must not propagate
- Never raise from `record_event()` functions (safety constraint: monitor failure blocks agents)
## Import Organization
- No aliases used; absolute imports from `cloneguard.*` package
- All relative paths via `pathlib.Path` (no string paths)
## Comments & Documentation
- All modules begin with a docstring describing purpose, design, and key constraints
- Examples: `hooks.py` explains the three layer defense architecture and TOCTOU hardening
- `monitor.py` documents the "NEVER raises" and "never blocks" contract
- Arguments documented with type hints in signature, not in docstring
- Complex functions include examples: `_detect_mode_for_tier15()` shows signal precedence
- Design rationale documented inline: "STRICT > STANDARD > LENIENT ordinal for max() comparison"
- Used for non-obvious algorithmic choices: "Signal precedence (highest wins; content markers can only upgrade, never downgrade)"
- NOT used for obvious code (e.g., no comment before `return result`)
- Locked/frozen behavior marked: `# LOCKED — see Phase 5 CONTEXT.md. Do not modify.`
- Triple-quoted strings for module docstrings
- Concise, one-sentence descriptions for function purpose
- Design constraints documented in docstring when relevant
## Function Design
- Most functions 20-50 lines; helpers can be 5-10 lines
- Complex orchestration (e.g., `RepoScanner.scan()`) reaches 100+ lines but stays focused on flow
- Type-hinted: `def scan(self, content: str, source_path: str) -> ScanResult:`
- Use dataclasses for complex parameter collections: `ScanResult`, `PatternMatch`, `ToolEvent`
- No positional-only or keyword-only markers (rely on clear naming)
- Dataclass returns for structured data: `ScanResult`, `SemanticFinding`, `EnforcementVerdict`
- Tuples for simple pairs: `tuple[int, str]` (exit code, output)
- Optional returns use `| None`: `def _get_mini_classifier() -> Any | None:`
## Module Design
- No `__all__` list; all public names are those without leading underscore
- Module-level singletons loaded once per process: `_engine: PatternEngine | None = None`
- Lazy initialization via sentinel functions: `_get_engine()`, `_get_mini_classifier()`
- Frozen dataclasses for immutable rule definitions: `@dataclass(frozen=True) class _CompiledRule:`
- Standard dataclasses for mutable collections: `@dataclass class ScanResult:`
- Field defaults via `field(default_factory=...)` for mutable defaults: `matches: list[PatternMatch] = field(default_factory=list)`
## Error Handling
- Specific exceptions at API boundary, broad catches for internal robustness
- JSON decoding failures handled by returning empty collections: `except json.JSONDecodeError: return []`
- Missing optional imports return `None` or `False` rather than raising
- Uses Python `logging` module: `logger = logging.getLogger(__name__)`
- INFO level for major events; DEBUG for noise; ERROR for recoverable failures
- Never logs secrets (content hashes are safe; file paths are safe)
- Hook handlers return `0` (pass), `1` (warning), `2` (block)
- CLI uses `2` for BLOCKED, `1` for WARNING, `0` for CLEAN
## Type Hints
- 100% type annotation: all function signatures, variable assignments, return types
- Modern syntax: `str | None` not `Optional[str]`; `list[X]` not `List[X]`
- Imports from `typing` only for `TYPE_CHECKING` and `Any`
## Enums
- Inherit from `Enum` directly
- Use `.value` to get string representation: `severity.value == "critical"`
- String values for comparison: `CRITICAL = "critical"` not `CRITICAL = 1`
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- **Four defense layers** (0-3) running at different execution stages in Claude Code agent lifecycle
- **Three-tier detection** (Tier 1 regex, Tier 1.5 mini-ONNX, Tier 2 Ollama) with graceful degradation
- **Pre-execution + in-process** — cannot be bypassed by repository content
- **Session-scoped trust** — content hashes cached within agent session to avoid re-scanning
- **TOCTOU-safe** — all decisions bind to content in stdin JSON, never re-read from disk
## Layers
- Purpose: Repository-wide scan before agent starts; cannot be disabled by repo content
- Location: `src/cloneguard/scanner.py` (RepoScanner)
- Contains: Multi-tier pattern + semantic scanning, file prioritization, Tier 2 LLM orchestration
- Depends on: PatternEngine, SemanticClassifier (Ollama), Allowlist, TrustCache
- Used by: CLI wrapper (`cli.py::handle_wrap`)
- Purpose: Scan agent instruction files (CLAUDE.md, .cursorrules) on load
- Location: `src/cloneguard/hooks.py::handle_instructions_loaded`
- Contains: Strict-mode scanning with Tier 1.5 semantic fallback, session trust caching
- Depends on: PatternEngine, MiniSemanticClassifier
- Used by: Claude Code hook protocol (JSON stdin)
- Purpose: Scan all tool output (Bash stderr, file reads) for injected patterns
- Location: `src/cloneguard/hooks.py::handle_post_tool_use`
- Contains: Output scanning, event logging to monitor, severity-based blocking
- Depends on: PatternEngine, ToolCallMonitor
- Used by: Claude Code hook protocol (called after each tool execution)
- Purpose: Protect config paths, gate build commands, scan writes to sensitive files
- Location: `src/cloneguard/hooks.py::handle_pre_tool_use`
- Contains: Protected-path list, sensitive-target list, write-content scanning, build-command warnings, sequence enforcement
- Depends on: PatternEngine, MiniSemanticClassifier, SequenceAllowlist, ToolCallMonitor
- Used by: Claude Code hook protocol (called before tool execution)
## Data Flow
## State Management
- In-memory dict: path → SHA-256 content hash
- Reset on process startup (each agent session)
- Populated by InstructionsLoaded approval
- Checked before re-scanning same file in same session
- Prevents redundant Tier 1.5 classification within session
- Content-hash keyed: SHA-256 → AllowlistEntry (path_hint, reason, timestamp)
- Persistent across sessions (user acknowledges false positive once)
- Checked in Layer 0 before pattern scan
- Cannot be modified by agents (CLI guard: requires -tty in `cloneguard allow`)
- Escape hatch for SEQ-001/002 (domain-level) and SEQ-005 (path-level)
- Domain entries: rule_id + lowercase domain → approved exfil destination
- Path entries: rule_id + SHA-256(normalized path) → approved config write
- Used by monitor.check_enforcement() to skip blocking
- File path → TrustEntry (content_hash, scanned_at, tier2_clean, scanner_version)
- Amortizes Tier 2 cost: skip re-scan if file hash unchanged
- Version-keyed: stale entries discarded on scanner upgrade
- Optional: only used if `--cache` flag or Layer 0 tier2=True
## Key Abstractions
- Purpose: Fast regex-based detection across 25 YAML rule files
- Location: `src/cloneguard/patterns.py`
- Pattern files: `src/cloneguard/rules/*.yaml` (authority_impersonation, behavioral_manipulation, encoding_obfuscation, etc.)
- Scan modes: STRICT (agent configs), STANDARD (source code), LENIENT (tests/fixtures)
- Returns: `ScanResult(verdict, matches[], scan_time_ms)` — fast (<50ms typical)
- Purpose: ONNX-based MiniLM-L6-v2 semantic classifier for false-positive reduction
- Location: `src/cloneguard/mini_semantic.py`
- Model: `src/cloneguard/model/mini_semantic.onnx` (~87MB, shipped with package)
- Approach: Sliding-window classification (16 chunks max, 256 tokens/window, 50% stride)
- Scoring: Mahalanobis anomaly detection (OOD distance from benign embeddings)
- Thresholds: Per-ScanMode (STRICT: 0.5/0.8, STANDARD: 0.65/0.88, LENIENT: 0.75/0.92)
- Graceful degradation: returns None if ONNX/transformers unavailable; falls through to Tier 2
- Purpose: LLM-based classification via local Ollama instance (no external API calls)
- Location: `src/cloneguard/semantic.py`
- Model: qwen2.5:7b (default, ~4.5GB); can override with `--tier2-model`
- Prompt: System message establishes injection definitions; expects `VERDICT|CONFIDENCE|REASON`
- Batch size: 3 files per prompt (amortizes model initialization)
- Graceful degradation: returns ERROR findings if Ollama unavailable
- Purpose: Behavioral sequence detection (exfil + lateral move patterns)
- Location: `src/cloneguard/monitor.py`
- Ring buffer: Max 50 events per session, FIFO eviction
- Rules: 6 sequence rules (SEQ-001 to SEQ-006); 3 enforce (001, 002, 005), 3 advisory (003, 004, 006)
- Enforcement window: 10 recent events (lookback)
- Sensitive file detection: path substring matching (credential files, .env, .ssh, .aws, etc.)
- Returns: `EnforcementVerdict` for blocking, or None to allow
- Purpose: Coordinate all four sub-scanners (patterns, settings, env, devcontainer) + Tier 2
- Location: `src/cloneguard/scanner.py`
- File priority: High (CLAUDE.md, .cursorrules), Medium (README, Makefile, docker-compose.yml)
- Phases: Collect → Tier 1 → Tier 1.5 → Tier 2 (optional) → Report
- Report: `ScanReport(file_results[], exit_code, active_tiers)`
- Purpose: User-managed list of known false positives (content-hash keyed)
- Location: `src/cloneguard/allowlist.py`
- Storage: `~/.cloneguard/allowlist.json`
- Checked before Tier 1 scan in Layer 0, and before Tier 1.5 in hooks
- Human-only: CLI guard prevents agents from adding entries
- Purpose: User-approved destinations/paths for bypassing SEQ-001/002/005
- Location: `src/cloneguard/sequence_allowlist.py`
- Domain allowlist (SEQ-001/002): lowercase domain string
- Path allowlist (SEQ-005): SHA-256 of normalized path
- Human-only: CLI must provide explicit `sequence-allow` command
## Entry Points
- Location: `src/cloneguard/cli.py::main()`
- Triggers: User runs `cloneguard [args]` or aliased `claude`
- Responsibilities:
- Location: `src/cloneguard/hooks.py::main()`
- Triggers: Claude Code hook protocol calls `cloneguard hook-check --event <EventName>`
- Responsibilities:
- `cloneguard scan [path]`: Layer 0 standalone scan
- `cloneguard setup`: Full onboarding (global hooks + shell alias)
- `cloneguard init --global|--project`: Install hook config to settings.json
- `cloneguard allow <file>`: Add file to allowlist (human-only, requires -tty)
- `cloneguard list`: Show allowlisted files
- `cloneguard remove <hash>`: Remove entry (human-only)
- `cloneguard sequence-allow <rule-id> <domain|path>`: Approve sequence rule bypass (human-only)
## Error Handling
- **Tier 1 (PatternEngine):** Synchronous, always returns ScanResult. Fails open only on regex compilation errors (logged, rule skipped).
- **Tier 1.5 (MiniSemanticClassifier):** Lazy-loaded; missing ONNX/transformers returns None (graceful degradation). Model load failures logged, classification skipped.
- **Tier 2 (SemanticClassifier):** Ollama unavailable returns SemanticResult(available=False). Client errors logged.
- **Allowlist/Cache:** Load failures logged; fallback to empty state (conservative: scan all files).
- **Hooks:** All external calls wrapped in try/except to prevent hook exceptions from breaking agent. Monitor failures logged, enforcement continues.
- **Monitor:** record_event() never raises; exceptions logged only. check_enforcement() returns None on error (allow).
## Cross-Cutting Concerns
- No stdout writes except hook responses and CLI user-facing output
- All diagnostic info logged via Python logging module (captured in agent logs)
- Log levels: DEBUG (model loads, cache hits), WARNING (scanner degradation, pattern compile errors), ERROR (unexpected failures)
- All regex patterns pre-compiled at engine init; invalid patterns logged and skipped
- All JSON parsing from stdin uses try/except; malformed hooks logged, exit 0 (allow)
- All paths normalized with Path.resolve() to prevent symlink/traversal edge cases
- All content decoded with UTF-8 errors='replace' to handle binary files
- No authentication required — CloneGuard is a local-only tool (Ollama assumed running locally)
- Trust model: Code trust (repo content) vs. Agent trust (approvals). Allowlist/sequence-allow require human confirmation.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, or `.github/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
