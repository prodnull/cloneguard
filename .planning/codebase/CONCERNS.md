# Codebase Concerns

**Analysis Date:** 2026-04-05

## Tech Debt

**Hook command hardcoding to "python" (macOS incompatible):**
- Issue: `src/cloneguard/hooks.json` and injected hook config in `src/cloneguard/cli.py` use `"command": "python -m cloneguard.hooks"` which does not exist on macOS (Python is installed as `python3`)
- Files: `src/cloneguard/hooks.json` (line 8, 20, 32), `src/cloneguard/cli.py` (lines 31, 42, 53 in _HOOK_CONFIG)
- Impact: Hooks fail to execute on macOS with "command not found: python". Installation succeeds but hooks silently fail, leaving no Layer 1-3 protection active. Users on macOS get false sense of security.
- Fix approach: Replace hardcoded `"python"` with output from `which python3` or use `sys.executable` at hook-init time to capture the venv/system interpreter path. Store resolved path in hook config during `cloneguard init` to ensure portability across shells and venvs.

**Hook command should not rely on module being in sys.path:**
- Issue: Hook config assumes `cloneguard` module is importable from agent's sys.path. If agent runs in a different venv or Python environment, `python -m cloneguard.hooks` will fail with ModuleNotFoundError.
- Files: `src/cloneguard/hooks.json`, `src/cloneguard/cli.py` (_HOOK_CONFIG)
- Impact: Works in the developer's venv but breaks when cloneguard is installed globally or in a different environment than the agent. Affects installation scenarios like `pip install --user cloneguard` or when Claude Code runs in its own interpreter context.
- Fix approach: At hook-init time, resolve the absolute path to the installed cloneguard package and use full path: `command: "/path/to/venv/bin/python -m cloneguard.hooks"`. Or use the entry point mechanism: `"command": "cloneguard hook-check --event ..."` which relies on console script installation.

**Missing CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md:**
- Issue: Repository lacks standard governance files for open-source projects
- Files: Root directory
- Impact: External contributors have no guidance on security disclosure, development workflow, or code review process. Security issues cannot be reported responsibly; no clear escalation path. CVE coordination is undefined.
- Fix approach: Add `CONTRIBUTING.md` (workflow, testing requirements, PR checklist), `SECURITY.md` (responsible disclosure policy, supported versions, how to report vulnerabilities), `CODE_OF_CONDUCT.md` (expected behavior, enforcement).

**No version pinning or compatibility matrix:**
- Issue: `pyproject.toml` specifies `requires-python = ">=3.11"` and `dependencies = ["pyyaml>=6.0"]` with no upper bounds
- Files: `pyproject.toml` (line 7, 10)
- Impact: Major version upgrades of PyYAML or Python 3.14+ could introduce breaking changes. No guarantee of forward compatibility. No documented support matrix for specific versions.
- Fix approach: Add `python_requires = ">=3.11,<3.15"` and pin PyYAML to tested range: `pyyaml>=6.0,<7.0`. Maintain a support matrix in docs (e.g., "Tested on Python 3.11, 3.12, 3.13").

**ONNX model deployment not automated:**
- Issue: `src/cloneguard/model/mini_semantic.onnx` is gitignored and must be fetched manually via `scripts/fetch_model.py`. Installation via `pip install cloneguard[mini]` succeeds but model is missing, causing runtime fallback to Ollama (Tier 2) or silent degradation.
- Files: `.gitignore` (line 19), `src/cloneguard/mini_semantic.py` (lines 108-110), `scripts/fetch_model.py` (if exists)
- Impact: False impression of Tier 1.5 availability post-install. Users expect full defense stack but get degraded performance. Tests that require the model skip silently (see `tests/test_latency.py` line 40).
- Fix approach: Include ONNX model in wheel distribution via hatchling build artifact (already in `pyproject.toml` line 48 but not fetched at install time). Or provide post-install hook that downloads the model. Document the requirement clearly in README.

**Test data not embedded; complex test setup:**
- Issue: 38 test files with conditional skips based on missing data/models/services (Ollama, Docker, ONNX model)
- Files: `tests/conftest.py` (lines 62-69), individual test files use `pytest.skip()`
- Impact: CI/local dev may have different test coverage. Hard to reproduce failures. New contributors must fetch/build multiple dependencies to run full suite. Test reliability depends on external state.
- Fix approach: Mock external dependencies in tests; embed minimal test data. Use fixtures for model/data initialization with clear failure messages when dependencies are missing.

## Known Bugs

**None formally documented in code.** However, the adaptive red team results documented 7 structural gaps in SEQ rules (behavioral sequence monitoring):

**SEQ rule structural limitations (documented but unfixed):**
- Symptoms: Advanced attackers can bypass specific SEQ rules through indirect execution
- Files: `src/cloneguard/monitor.py` (lines 237-247 in docs/ADAPTIVE-RED-TEAM.md), `tests/` (numerous evasion tests document these)
- Triggers:
  - **SEQ-004 (symlink indirection)**: `ln -s .env /tmp/harmless.txt` — monitor matches path strings, doesn't resolve symlinks
  - **SEQ-005 (bash pipeline)**: `cat .env | base64 && curl` — no Read tool event emitted, monitor requires Read event to set marker
  - **SEQ-006 (cross-session exfil)**: Read in session A, exfil in session B — per-session markers don't persist
  - **SEQ-007 (config write via bash)**: `echo "malicious" >> ~/.config/file` — SEQ-005 checks Write/Edit tool, not bash redirects
  - **SEQ-008 (non-keyword MCP tool)**: `mcp__google__web_search` — SEQ-006 keyword list doesn't include "search"
  - **SEQ-009 (DNS exfiltration)**: `dig` commands — SEQ-002 URL regex requires http(s)://, DNS has no URL
  - **SEQ-010 (localhost relay)**: `curl http://localhost:8080` — treated as safe, attacker's local proxy forwards externally
- Workaround: None. These are design limits of hook-layer monitoring (cannot intercept shell I/O, file redirects, or cross-session state).
- Mitigation: Document clearly in threat model; do not claim protection against these vectors. Recommend defense-in-depth (network isolation, DAC, containers).

## Security Considerations

**Incomplete threat model coverage:**
- Risk: CloneGuard documentation explicitly states "No guarantee of long-term durability" and frames defense as raising attacker cost, not preventing attacks. However, some users may misinterpret detection as blocking.
- Files: `README.md` (line 48), `docs/SECURITY.md`
- Current mitigation: README includes "Not a sandbox" disclaimer; SECURITY.md details evasion vectors. Threat model is documented.
- Recommendations: 
  1. Add visual warnings to CLI output: "⚠ CloneGuard detected a suspicious pattern but did not block execution — review the flagged content."
  2. Clarify in hook error messages that enforcement rules (SEQ-001/002/005) will block, but evasion is possible if attacker bypasses all tiers.
  3. Add telemetry (opt-in) to track false negatives; publish bypass rates quarterly.

**Disputed bypass claims remain in published results:**
- Risk: Three adaptive red team bypasses (adaptive-claude-005, 014, 019) marked as "DISPUTED" rather than "GENUINE" or "FALSE_CLAIM." Cross-examination did not reach consensus. Publishing disputed claims without resolution may undermine confidence in results.
- Files: `docs/ADAPTIVE-RED-TEAM.md` (lines 207-211), data/pentest/transcripts/
- Current mitigation: Results are transparent — verdict is recorded as DISPUTED with deliberation reasoning included. Methodology is sound (adversarial cross-examination).
- Recommendations: 
  1. Conduct additional independent review by external security researcher.
  2. If genuine, patch the evasion; if false, update documentation to explain why reviewers disagreed.
  3. Set clear bar for future verdict assignments: GENUINE requires unanimous consent; DISPUTED with strong consensus (3/3 or 2/2) transitions to GENUINE on repeat testing.

**YOLO mode escalates strictness but doesn't block:**
- Risk: When `--dangerously-skip-permissions` is detected, CloneGuard escalates scan mode from STANDARD to STRICT, but this only changes severity thresholds, not enforcement. Tier 0 misses and Tier 1.5 SUSPICIOUS findings are still warnings, not blocks.
- Files: `src/cloneguard/scanner.py` (scan mode logic), `src/cloneguard/cli.py` (YOLO detection)
- Impact: User runs YOLO mode expecting extra protection but gets the same detection → warning loop.
- Recommendation: In YOLO mode, treat SUSPICIOUS verdicts as MALICIOUS for enforcement rules (SEQ-001/002/005). Document this behavior explicitly.

**Trust cache tampering is theoretically possible:**
- Risk: Trust cache stores file content hashes. If an attacker can predict/brute-force SHA-256 hashes or find file content with pre-computed hash collisions, they could add entries to allowlist their malicious files before writing them.
- Files: `src/cloneguard/trust_cache.py`
- Impact: Extremely low in practice (SHA-256 is cryptographically strong) but architecturally not impossible.
- Recommendation: Use HMAC-SHA256 with a persistent per-system secret (stored in `~/.cloneguard/` only readable by user) to prevent cache forgery.

## Performance Bottlenecks

**Tier 1.5 ONNX inference not parallelized:**
- Problem: Mini semantic model processes files sequentially. For repos with 500+ files, inference can take 5-10 minutes with single-threaded loop.
- Files: `src/cloneguard/mini_semantic.py` (lines 141-180, classify_batch method), `src/cloneguard/scanner.py` (scan loop)
- Cause: ONNX Runtime CPU provider doesn't expose easy multi-threading API; managing thread safety with shared tokenizer is complex.
- Improvement path: (1) Use multiprocessing with process-local ONNX sessions. (2) Batch classify in groups of 32 files to amortize tokenization overhead. (3) Profile with `cProfile` to measure bottleneck.

**Regex compilation happens per-scan:**
- Problem: PatternEngine compiles 204 regex patterns on every `scan()` call. For repos scanned repeatedly, this is wasted CPU.
- Files: `src/cloneguard/patterns.py` (PatternEngine.__init__, lines ~60-80)
- Cause: Patterns are compiled in `__init__`, not at module load time. Scanner creates new PatternEngine per scan.
- Improvement path: Singleton PatternEngine (already done in hooks.py via module-level `_engine`) but not in scanner. Move to module-level singleton in `patterns.py` and reuse.

**File I/O not batched:**
- Problem: Large repos cause repeated small reads (scanning metadata, then content). No buffering strategy.
- Files: `src/cloneguard/scanner.py` (scan method)
- Cause: Scans all files in serial; no prefetching or batch I/O scheduling.
- Improvement path: Batch read 32 files in parallel using `concurrent.futures.ThreadPoolExecutor`, then scan batch.

## Fragile Areas

**Mini semantic model depends on exact ONNX Runtime version:**
- Files: `src/cloneguard/mini_semantic.py` (lines 105-114, _try_load), `pyproject.toml` (line 33: `onnxruntime>=1.17`)
- Why fragile: Model serialization is version-dependent. ONNX Runtime 1.17 may not be compatible with models trained on 1.18+. No version pinning.
- Safe modification: Test model loading against ONNX Runtime versions 1.17, 1.18, 1.19. Pin to `onnxruntime>=1.17,<2.0`. Include version check in `_try_load()`.
- Test coverage: `tests/test_mini_semantic.py` tests classification but not version compatibility.

**PatternEngine.MODE_SPECIFICITY_OVERRIDES is hardcoded:**
- Files: `src/cloneguard/patterns.py` (line ~200, MODE_SPECIFICITY_OVERRIDES dict)
- Why fragile: Patterns that are restricted to STRICT mode (CI-001, CI-004, CI-006, SC-001, MCP-005, LTL-004) are hardcoded in dict. Adding/removing patterns requires code change, not config.
- Safe modification: Move overrides to external YAML config file (e.g., `src/cloneguard/config/mode_overrides.yaml`). Load at init time. Include schema validation.
- Test coverage: `tests/test_patterns.py` tests pattern matching but not mode override logic directly.

**Allowlist and trust cache are user-only readable:**
- Files: `src/cloneguard/allowlist.py`, `src/cloneguard/trust_cache.py` (write logic in ~/.cloneguard/)
- Why fragile: Files are written with default umask, which may be world-readable. If system has other unprivileged users, they could read cached file paths and hashes.
- Safe modification: Explicitly set file permissions to `0o600` (user-only read/write) when creating cache/allowlist files.
- Test coverage: No tests verify file permissions.

**SemanticResult.threshold_override can bypass Tier 1.5:**
- Files: `src/cloneguard/semantic.py` (lines ~100-150, SemanticResult construction)
- Why fragile: Semantic classification has environment variable overrides for thresholds (CLONEGUARD_THRESHOLD_*). If attacker can set env vars before running agent, they could raise MALICIOUS threshold to 0.99, bypassing detection.
- Safe modification: Lock thresholds at hook init time; store in hook state, not env vars. Or verify hook runs with clean environment (no inherit from agent process).
- Test coverage: `tests/test_mini_semantic.py` tests threshold overrides but not in hook context where env vars matter.

## Scaling Limits

**Monitor session buffer has fixed depth:**
- Capacity: `_MAX_SESSION_EVENTS = 50` per session, `_MAX_SESSIONS = 200` total (line 41-42 in monitor.py)
- Limit: Sessions with >50 tool calls lose early events; behavior-based detection becomes stateless. With 200 sessions, LRU eviction starts happening on shared systems where multiple agents run concurrently.
- Scaling path: Make buffer depth configurable. For long-running sessions, consider time-based windows (e.g., events in last 5 minutes) instead of event counts.

**Trust cache grows unbounded:**
- Capacity: `~/.cloneguard/trust-cache.json` stores one entry per unique (repo, file) pair
- Limit: After scanning 1000+ repos, cache file grows to 10+ MB; lookup becomes O(n)
- Scaling path: Implement SQLite cache with indexed lookups. Set size limit (e.g., 100k entries) with LRU eviction. Or use `shelve` module for O(1) access.

**AllowList grows without pruning:**
- Capacity: `~/.cloneguard/allowlist.json` stores content hashes of allowlisted files
- Limit: After allowlisting 500 files, retrieval becomes slow (no indexing)
- Scaling path: Same as trust cache — use SQLite with indexed content_hash.

**Tier 1.5 inference latency on very long files:**
- Problem: Files >100KB take 5+ seconds to classify (sliding window processes all chunks)
- Files: `src/cloneguard/mini_semantic.py` (lines 44-46, _MAX_CHUNKS=16, _WINDOW_SIZE=256)
- Scaling path: Implement early-exit logic: if first 2 chunks yield MALICIOUS verdict with high confidence (>0.95), stop and return MALICIOUS without classifying rest of file. Trade off thoroughness for speed on large files.

## Dependencies at Risk

**PyYAML without pinning:**
- Risk: PyYAML 6.0 has known security issues (CVE-2020-1747, CVE-2020-14343 in older versions, but 6.0 is patched). However, PyYAML 7.0 (if released) could break YAML parsing API.
- Impact: Breaking change in dependency could cause install failures
- Migration plan: Upgrade to safer YAML library if available (e.g., `ruamel.yaml` with sandbox mode), or pin PyYAML to `>=6.0,<7.0`.

**ONNX Runtime CPU provider limited:**
- Risk: ONNX Runtime's CPU provider is slower than GPU. No GPU acceleration available. Alternative: switch to TensorFlow Lite or TorchScript, but adds weight.
- Impact: Inference on large repos is slower than GPU-capable tools
- Migration plan: Investigate GPU support via CUDA provider if Tier 2 ONNX inference becomes bottleneck. Profile first to confirm it's a real problem.

**Transformers library dependency not pinned:**
- Risk: Transformers 4.36+ may introduce breaking changes to tokenizer API or model loading
- Files: `src/cloneguard/mini_semantic.py` (line 106, AutoTokenizer.from_pretrained)
- Impact: Model loading could fail on major version upgrade
- Migration plan: Pin to `transformers>=4.36,<5.0`.

## Missing Critical Features

**No audit log of detection events:**
- Problem: When CloneGuard detects and blocks something, only stderr is logged. No persistent record of what was blocked, when, or why. Organizations cannot comply with audit requirements.
- Blocks: Compliance scenarios (SOC2, PCI-DSS) that require audit trails
- Fix approach: Add optional audit log to `~/.cloneguard/audit.log` (configurable) that records: timestamp, event type (BLOCKED/WARNING/ALLOWED), file path, pattern matched, confidence score. Supports JSON or CSV format.

**No integration with external SIEM:**
- Problem: Audit events cannot be forwarded to Splunk, Datadog, or CloudWatch. All events are local-only.
- Blocks: Enterprise deployments where security teams need centralized visibility
- Fix approach: Add `--audit-endpoint` flag that POSTs events to external HTTP endpoint (with API key auth). Or integrate with syslog.

**No programmatic API for automation:**
- Problem: CloneGuard is CLI-only. Scripts cannot import `cloneguard` and call scan functions directly; only subprocess invocation is available.
- Blocks: Integration into CI/CD pipelines, IDE plugins, or custom tools
- Fix approach: Expose public API via `cloneguard/__init__.py`: `scan(path, tier=1.5) -> ScanReport`. Allow imports like `from cloneguard import scan`.

**No configuration file support:**
- Problem: All settings are CLI flags or environment variables. No `~/.cloneguard/config.yaml` to set defaults
- Blocks: Organizations with standardized settings (e.g., always scan with Tier 2, always enforce SEQ-001)
- Fix approach: Load YAML config from `~/.cloneguard/config.yaml` if present, with CLI overrides.

## Test Coverage Gaps

**Untested: hook-check entry point in real Claude Code environment:**
- What's not tested: The `cloneguard hook-check` command runs JSON marshalling/unmarshalling and interacts with Claude Code's hook protocol (stdin/stdout). No test mocks the full hook invocation.
- Files: `src/cloneguard/hooks.py` (main function, lines 470-500), `tests/test_hooks.py`
- Risk: Hook protocol violations (wrong exit codes, malformed JSON output) could break Claude Code integration silently
- Priority: High — affects production behavior

**Untested: multi-file coordinated attacks:**
- What's not tested: Files are scanned independently. No test verifies detection of attacks where each file is benign in isolation but dangerous when processed together.
- Files: `tests/test_*` (no cross-file analysis test)
- Risk: Attacker could hide attack across multiple files; CloneGuard would allow all
- Priority: Medium — documented limitation but no detection attempt

**Untested: trust cache invalidation on file modification:**
- What's not tested: If a file is allowlisted, then modified by 1 byte, is it re-scanned? No test verifies hash-mismatch handling.
- Files: `src/cloneguard/trust_cache.py`, `tests/test_trust_cache.py`
- Risk: Modified files might skip scan if hash collision occurs (extremely unlikely but not proven impossible)
- Priority: Low — cryptographic risk is minimal

**Untested: Tier 2 Ollama fallback on model unavailability:**
- What's not tested: When Tier 1.5 ONNX fails to load, does fallback to Ollama work correctly? Tests skip if Ollama unavailable.
- Files: `src/cloneguard/semantic.py` (fallback logic), `tests/test_evasion_resistance.py` (skip if no Ollama)
- Risk: Real users without ONNX model may hit untested fallback path
- Priority: Medium — affects degradation mode

**Untested: YOLO mode escallation:**
- What's not tested: `--dangerously-skip-permissions` detection and mode escalation in scanner. No test verifies STANDARD→STRICT transition.
- Files: `src/cloneguard/scanner.py`, `tests/` (no YOLO-specific test)
- Risk: Feature may silently fail; users get no extra protection in YOLO mode
- Priority: Medium — affects unsafe-mode behavior

## Architectural Concerns

**Tier 2 Ollama fallback is slow and external:**
- Issue: If Tier 1.5 ONNX model is missing, system falls back to Ollama LLM, which requires external service and takes 1-5 seconds per file
- Files: `src/cloneguard/semantic.py` (fallback to ollama_classify), `docs/SECURITY.md` (Tier 2 documentation)
- Impact: Users without ONNX model get severely degraded performance; also requires network access and Ollama service running
- Recommendation: Simplify Tier 2: either make ONNX model mandatory (ship in wheel), or provide pre-built fallback (e.g., bundled Ollama container image).

**Monitor.py is 1092 lines — high complexity:**
- Issue: Single file handles all session tracking, rule evaluation, and event marshalling
- Files: `src/cloneguard/monitor.py`
- Impact: Hard to test, maintain, or add new SEQ rules. Line count suggests untangled concerns.
- Recommendation: Refactor into submodules: `monitor/session.py` (SessionManager), `monitor/rules.py` (SEQ-001 through SEQ-006 implementations), `monitor/events.py` (event types).

**Hook invocation happens per tool, not per session:**
- Issue: Each tool call (Read, Write, Bash, etc.) triggers a separate hook invocation. No session state shared across hook calls.
- Files: `src/cloneguard/hooks.py`, `src/cloneguard/monitor.py` (ToolCallMonitor design)
- Impact: Session markers (e.g., "sensitive file was read") are stored globally per process lifetime. If agent runs multiple sessions in same process, markers leak across sessions.
- Recommendation: Integrate session ID into hook protocol; pass session ID in hook payload. ToolCallMonitor already does this (`_session_marker` dict keyed by session ID) but relies on agent providing consistent session ID.

**No support for agent-specific hook variants:**
- Issue: CloneGuard hooks are generic; they don't know whether they're running in Claude Code, Gemini CLI, Cursor, etc. Different agents have different event protocols.
- Files: `src/cloneguard/hooks.py` (assumes Claude Code protocol)
- Impact: Integration with non-Claude-Code agents (Gemini CLI, Cursor) may have subtle protocol incompatibilities.
- Recommendation: Add hook protocol version negotiation; document protocol compatibility matrix.

---

*Concerns audit: 2026-04-05*
