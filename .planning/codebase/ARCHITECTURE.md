# Architecture

**Analysis Date:** 2026-04-05

## Pattern Overview

**Overall:** Layered defense-in-depth with static pattern detection (Tier 1), semantic classification (Tier 1.5/2), and behavioral sequence monitoring.

**Key Characteristics:**
- **Four defense layers** (0-3) running at different execution stages in Claude Code agent lifecycle
- **Three-tier detection** (Tier 1 regex, Tier 1.5 mini-ONNX, Tier 2 Ollama) with graceful degradation
- **Pre-execution + in-process** — cannot be bypassed by repository content
- **Session-scoped trust** — content hashes cached within agent session to avoid re-scanning
- **TOCTOU-safe** — all decisions bind to content in stdin JSON, never re-read from disk

## Layers

**Layer 0 (Pre-execution Scan):**
- Purpose: Repository-wide scan before agent starts; cannot be disabled by repo content
- Location: `src/cloneguard/scanner.py` (RepoScanner)
- Contains: Multi-tier pattern + semantic scanning, file prioritization, Tier 2 LLM orchestration
- Depends on: PatternEngine, SemanticClassifier (Ollama), Allowlist, TrustCache
- Used by: CLI wrapper (`cli.py::handle_wrap`)

**Layer 1 (InstructionsLoaded Hook):**
- Purpose: Scan agent instruction files (CLAUDE.md, .cursorrules) on load
- Location: `src/cloneguard/hooks.py::handle_instructions_loaded`
- Contains: Strict-mode scanning with Tier 1.5 semantic fallback, session trust caching
- Depends on: PatternEngine, MiniSemanticClassifier
- Used by: Claude Code hook protocol (JSON stdin)

**Layer 2 (PostToolUse Hook):**
- Purpose: Scan all tool output (Bash stderr, file reads) for injected patterns
- Location: `src/cloneguard/hooks.py::handle_post_tool_use`
- Contains: Output scanning, event logging to monitor, severity-based blocking
- Depends on: PatternEngine, ToolCallMonitor
- Used by: Claude Code hook protocol (called after each tool execution)

**Layer 3 (PreToolUse Hook):**
- Purpose: Protect config paths, gate build commands, scan writes to sensitive files
- Location: `src/cloneguard/hooks.py::handle_pre_tool_use`
- Contains: Protected-path list, sensitive-target list, write-content scanning, build-command warnings, sequence enforcement
- Depends on: PatternEngine, MiniSemanticClassifier, SequenceAllowlist, ToolCallMonitor
- Used by: Claude Code hook protocol (called before tool execution)

## Data Flow

**Layer 0 (Pre-execution):**

1. User runs `cloneguard` or aliased `claude` in repo directory
2. CLI `handle_wrap()` instantiates `RepoScanner` with tier2=True, cache=True
3. RepoScanner collects files by priority: high-priority (CLAUDE.md, .cursorrules), medium-priority (README, Dockerfile)
4. For each file:
   - Check TrustCache (skip if verified clean at this version)
   - Read file content (UTF-8 with fallback)
   - Check Allowlist (skip if content hash approved)
   - Run Tier 1 PatternEngine scan (all 25 YAML rules)
   - If verdict=SUSPICIOUS, pass to Tier 1.5 MiniSemanticClassifier (ONNX-based)
   - If still SUSPICIOUS, pass to Tier 2 SemanticClassifier (Ollama qwen2.5:7b)
5. Report exit code: 2 (BLOCKED), 1 (WARNING), 0 (CLEAN)
6. If issues found + interactive: prompt user. If accepted or non-interactive-clean, exec claude.

**Hooks (Layers 1-3):**

1. Claude Code calls hook endpoint with JSON stdin (hook event + payload)
2. Hooks handler reads stdin, parses JSON
3. Mode detection: path-based (STRICT/STANDARD/LENIENT), content markers override
4. Tier 1: PatternEngine.scan() against all 25 YAML rules
5. If verdict != CLEAN: Try Tier 1.5 MiniSemanticClassifier (inline classification)
6. Session trust check: if content hash already approved in this session, skip re-scan
7. Return exit code: 0 (allow/warn), 2 (block)
8. For Layer 2+3: Record event to ToolCallMonitor for sequence rules (SEQ-001 to SEQ-006)

**Sequence Monitoring (Layer 1.5 Enforcement):**

1. `handle_post_tool_use()` and `handle_pre_tool_use()` call `get_monitor().record_event(data)`
2. Monitor builds ring buffer of recent events (max 50 per session)
3. On PreToolUse, call `check_enforcement(data)` for blocking rules:
   - SEQ-001: Read(sensitive) → WebFetch(external) within 10 events
   - SEQ-002: Read(sensitive) → Bash(curl/wget external) within 10 events
   - SEQ-005: Write(.claude/settings.json, .npmrc, etc.) → blocks unless allowlisted by path hash
4. If rule matches: return EnforcementVerdict, handler prints block reason

## State Management

**Session-Scoped Trust (`_session_trust`):**
- In-memory dict: path → SHA-256 content hash
- Reset on process startup (each agent session)
- Populated by InstructionsLoaded approval
- Checked before re-scanning same file in same session
- Prevents redundant Tier 1.5 classification within session

**User-Local Allowlist (`~/.cloneguard/allowlist.json`):**
- Content-hash keyed: SHA-256 → AllowlistEntry (path_hint, reason, timestamp)
- Persistent across sessions (user acknowledges false positive once)
- Checked in Layer 0 before pattern scan
- Cannot be modified by agents (CLI guard: requires -tty in `cloneguard allow`)

**User-Local Sequence Allowlist (`~/.cloneguard/sequence_allowlist.json`):**
- Escape hatch for SEQ-001/002 (domain-level) and SEQ-005 (path-level)
- Domain entries: rule_id + lowercase domain → approved exfil destination
- Path entries: rule_id + SHA-256(normalized path) → approved config write
- Used by monitor.check_enforcement() to skip blocking

**Trust Cache (`~/.cloneguard/trust-cache.json`):**
- File path → TrustEntry (content_hash, scanned_at, tier2_clean, scanner_version)
- Amortizes Tier 2 cost: skip re-scan if file hash unchanged
- Version-keyed: stale entries discarded on scanner upgrade
- Optional: only used if `--cache` flag or Layer 0 tier2=True

## Key Abstractions

**PatternEngine (Tier 1):**
- Purpose: Fast regex-based detection across 25 YAML rule files
- Location: `src/cloneguard/patterns.py`
- Pattern files: `src/cloneguard/rules/*.yaml` (authority_impersonation, behavioral_manipulation, encoding_obfuscation, etc.)
- Scan modes: STRICT (agent configs), STANDARD (source code), LENIENT (tests/fixtures)
- Returns: `ScanResult(verdict, matches[], scan_time_ms)` — fast (<50ms typical)

**MiniSemanticClassifier (Tier 1.5):**
- Purpose: ONNX-based MiniLM-L6-v2 semantic classifier for false-positive reduction
- Location: `src/cloneguard/mini_semantic.py`
- Model: `src/cloneguard/model/mini_semantic.onnx` (~87MB, shipped with package)
- Approach: Sliding-window classification (16 chunks max, 256 tokens/window, 50% stride)
- Scoring: Mahalanobis anomaly detection (OOD distance from benign embeddings)
- Thresholds: Per-ScanMode (STRICT: 0.5/0.8, STANDARD: 0.65/0.88, LENIENT: 0.75/0.92)
- Graceful degradation: returns None if ONNX/transformers unavailable; falls through to Tier 2

**SemanticClassifier (Tier 2):**
- Purpose: LLM-based classification via local Ollama instance (no external API calls)
- Location: `src/cloneguard/semantic.py`
- Model: qwen2.5:7b (default, ~4.5GB); can override with `--tier2-model`
- Prompt: System message establishes injection definitions; expects `VERDICT|CONFIDENCE|REASON`
- Batch size: 3 files per prompt (amortizes model initialization)
- Graceful degradation: returns ERROR findings if Ollama unavailable

**ToolCallMonitor (Sequence Rules):**
- Purpose: Behavioral sequence detection (exfil + lateral move patterns)
- Location: `src/cloneguard/monitor.py`
- Ring buffer: Max 50 events per session, FIFO eviction
- Rules: 6 sequence rules (SEQ-001 to SEQ-006); 3 enforce (001, 002, 005), 3 advisory (003, 004, 006)
- Enforcement window: 10 recent events (lookback)
- Sensitive file detection: path substring matching (credential files, .env, .ssh, .aws, etc.)
- Returns: `EnforcementVerdict` for blocking, or None to allow

**RepoScanner (Layer 0 Orchestration):**
- Purpose: Coordinate all four sub-scanners (patterns, settings, env, devcontainer) + Tier 2
- Location: `src/cloneguard/scanner.py`
- File priority: High (CLAUDE.md, .cursorrules), Medium (README, Makefile, docker-compose.yml)
- Phases: Collect → Tier 1 → Tier 1.5 → Tier 2 (optional) → Report
- Report: `ScanReport(file_results[], exit_code, active_tiers)`

**Allowlist (False Positive Suppression):**
- Purpose: User-managed list of known false positives (content-hash keyed)
- Location: `src/cloneguard/allowlist.py`
- Storage: `~/.cloneguard/allowlist.json`
- Checked before Tier 1 scan in Layer 0, and before Tier 1.5 in hooks
- Human-only: CLI guard prevents agents from adding entries

**SequenceAllowlist (Sequence Rule Escape Hatch):**
- Purpose: User-approved destinations/paths for bypassing SEQ-001/002/005
- Location: `src/cloneguard/sequence_allowlist.py`
- Domain allowlist (SEQ-001/002): lowercase domain string
- Path allowlist (SEQ-005): SHA-256 of normalized path
- Human-only: CLI must provide explicit `sequence-allow` command

## Entry Points

**CLI Wrapper (`cli.py::main`):**
- Location: `src/cloneguard/cli.py::main()`
- Triggers: User runs `cloneguard [args]` or aliased `claude`
- Responsibilities:
  1. Parse args (scan, setup, init, allow, remove, hook-check, or wrap)
  2. Route to handler (handle_wrap, handle_scan, handle_allow, etc.)
  3. For default (wrap): call handle_wrap() → RepoScanner.scan() → report → exec claude

**Hook Entry Point (`hooks.py::main`):**
- Location: `src/cloneguard/hooks.py::main()`
- Triggers: Claude Code hook protocol calls `cloneguard hook-check --event <EventName>`
- Responsibilities:
  1. Read JSON from stdin (hook payload)
  2. Parse event type (InstructionsLoaded, PreToolUse, PostToolUse)
  3. Dispatch to handler (handle_instructions_loaded, handle_pre_tool_use, handle_post_tool_use)
  4. Return exit code 0 (allow) or 2 (block) to agent

**Subcommand Handlers:**
- `cloneguard scan [path]`: Layer 0 standalone scan
- `cloneguard setup`: Full onboarding (global hooks + shell alias)
- `cloneguard init --global|--project`: Install hook config to settings.json
- `cloneguard allow <file>`: Add file to allowlist (human-only, requires -tty)
- `cloneguard list`: Show allowlisted files
- `cloneguard remove <hash>`: Remove entry (human-only)
- `cloneguard sequence-allow <rule-id> <domain|path>`: Approve sequence rule bypass (human-only)

## Error Handling

**Strategy:** Defensive — never let error handling break the agent pipeline or suppress critical detections.

**Patterns:**

- **Tier 1 (PatternEngine):** Synchronous, always returns ScanResult. Fails open only on regex compilation errors (logged, rule skipped).
- **Tier 1.5 (MiniSemanticClassifier):** Lazy-loaded; missing ONNX/transformers returns None (graceful degradation). Model load failures logged, classification skipped.
- **Tier 2 (SemanticClassifier):** Ollama unavailable returns SemanticResult(available=False). Client errors logged.
- **Allowlist/Cache:** Load failures logged; fallback to empty state (conservative: scan all files).
- **Hooks:** All external calls wrapped in try/except to prevent hook exceptions from breaking agent. Monitor failures logged, enforcement continues.
- **Monitor:** record_event() never raises; exceptions logged only. check_enforcement() returns None on error (allow).

## Cross-Cutting Concerns

**Logging:** 
- No stdout writes except hook responses and CLI user-facing output
- All diagnostic info logged via Python logging module (captured in agent logs)
- Log levels: DEBUG (model loads, cache hits), WARNING (scanner degradation, pattern compile errors), ERROR (unexpected failures)

**Validation:**
- All regex patterns pre-compiled at engine init; invalid patterns logged and skipped
- All JSON parsing from stdin uses try/except; malformed hooks logged, exit 0 (allow)
- All paths normalized with Path.resolve() to prevent symlink/traversal edge cases
- All content decoded with UTF-8 errors='replace' to handle binary files

**Authentication & Trust:**
- No authentication required — CloneGuard is a local-only tool (Ollama assumed running locally)
- Trust model: Code trust (repo content) vs. Agent trust (approvals). Allowlist/sequence-allow require human confirmation.

---

*Architecture analysis: 2026-04-05*
