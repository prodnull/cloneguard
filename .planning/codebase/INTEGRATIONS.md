# External Integrations

**Analysis Date:** 2026-04-05

## APIs & External Services

**None Required for Core Operation**

CloneGuard runs entirely offline with no external API dependencies. All detection happens locally:
- Tier 0: Regex patterns compiled at startup
- Tier 1.5: ONNX Runtime inference (bundled model)
- Tier 2: Optional Ollama (local service, self-hosted)

## Data Storage

**Databases:**
- None. CloneGuard is stateless for scanning operations.

**File Storage:**
- Local filesystem only
- Trust cache: `~/.claude/trust-cache/` (optional, local SQLite for file hash caching)
- Allowlist: `~/.claude/cloneguard-allowlist.json` (local JSON file with content hashes)

**Caching:**
- Trust cache: Local SQLite database in `~/.claude/trust-cache/` (optional, controlled by `--cache` flag)
- Allowlist cache: In-memory dict, persisted to JSON at `~/.claude/cloneguard-allowlist.json`
- No remote caching services

## Authentication & Identity

**Auth Provider:**
- None required for operation
- CI only: `HF_TOKEN` (GitHub Actions secret) used to download ONNX model from Hugging Face Hub during build
  - Token stored in GitHub Actions secrets
  - Only needed for `scripts/fetch_model.py` during CI/release builds

## Model Services

**Tier 1.5 - ONNX Inference:**
- Runtime: ONNX Runtime >=1.17
- Execution provider: CPUExecutionProvider (no GPU acceleration)
- No network calls
- Model file: `src/cloneguard/model/mini_semantic.onnx` (bundled, 90.8 MB)

**Tier 2 - Semantic Classification (Optional):**
- Service: Local Ollama (`ollama>=0.4`)
- Default model: `qwen2.5:7b` (or configurable via `--tier2-model`)
- Connection: `http://localhost:11434` (Ollama default)
- Protocol: Ollama Python SDK REST calls
- Implementation: `src/cloneguard/semantic.py:SemanticClassifier`
- Batch size: 3 files per request
- Fallback: If Ollama unavailable, skips Tier 2 (logs warning, continues with Tier 0 + Tier 1.5)

## Hook Integration Points

**AI Coding Agent Integration:**
- Claude Code: Hook protocol via stdin/stdout JSON
  - Events: `InstructionsLoaded`, `PreToolUse`, `PostToolUse`
  - Config file: `~/.claude/settings.json` or `.claude/settings.json`
  - Hook entry point: `cloneguard hook-check --event <EventName>`
  - Reads hook payload from stdin, returns JSON response on stdout

- Supported agents (hook-compatible):
  - Claude Code (tested 3 event types)
  - Gemini CLI v0.30.1+ (11 events)
  - Cursor v2.6.13+ (19+ events)
  - Windsurf v1.108.2+ (12 events)
  - VS Code Copilot v1.109+ preview (8 events)

## MCP Integration (Optional)

**MCP Gateway Plugin:**
- File: `src/cloneguard/mcp_plugin.py`
- Class: `CloneGuardPlugin` (inherits `GuardrailPlugin`)
- Purpose: Scans MCP tool requests and responses for prompt injection
- Severities: CRITICAL/HIGH block, MEDIUM warns, LOW passes
- Optional dependency: `mcp-gateway` (gracefully degrades if unavailable)

## Monitoring & Observability

**Error Tracking:**
- None. CloneGuard logs locally via Python `logging` module.

**Logs:**
- File: `src/cloneguard/monitor.py` — Event stream tracking
- Output: Text-based log lines (not structured logging)
- Levels: DEBUG, INFO, WARNING, ERROR
- Example usage: `logger.warning("Ollama not available — skipping Tier 2 classification")`

**Review Log (Optional):**
- Path: Environment variable `CLONEGUARD_REVIEW_LOG` (optional)
- Format: JSONL (one classification per line)
- Threshold: `CLONEGUARD_REVIEW_THRESHOLD` (default 0.98)
- Purpose: Analyst review of low-confidence SAFE verdicts

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None

## CI/CD & Deployment

**Hosting:**
- GitHub Actions (public CI pipeline)
- Docker (container support via `tests/integration/Dockerfile`)

**CI Pipeline:**
- Jobs: lint, test (matrix 3.11/3.12/3.13), test-macos, test-coverage, integration, test-tier2, security
- Model fetching: `scripts/fetch_model.py` downloads ONNX from Hugging Face Hub (uses `HF_TOKEN`)
- Release: Build wheel with embedded ONNX model (verified size check in `release.yml`)

## Build Artifacts

**ONNX Model Download:**
- Source: Hugging Face Hub (`prodnull/minilm-prompt-injection-classifier`)
- Endpoint: `https://huggingface.co/api/datasets/...` (via Hugging Face SDK)
- Trigger: CI step `Fetch ONNX model` (runs `scripts/fetch_model.py`)
- Artifact location post-build: `src/cloneguard/model/mini_semantic.onnx`

**Dataset Reference (Informational):**
- Hugging Face Dataset: `prodnull/prompt-injection-repo-dataset`
- Used for model training, not loaded at runtime

## Environment Configuration

**Required env vars:**
- None for production operation

**Optional env vars:**
- `CLONEGUARD_REVIEW_LOG=/path/to/review.jsonl` — Enable low-confidence review logging
- `CLONEGUARD_REVIEW_THRESHOLD=0.98` — Classification confidence threshold for review
- `CLONEGUARD_THRESHOLD_{MODE}_{LEVEL}` — Override detection thresholds per ScanMode
  - Example: `CLONEGUARD_THRESHOLD_STRICT_MALICIOUS=0.80`
  - Modes: STRICT, STANDARD, LENIENT
  - Levels: SUSPICIOUS, MALICIOUS

**Secrets location:**
- GitHub Actions: `.github/workflows/ci.yml` `env.HF_TOKEN` (Actions Secret)
- Local: None (CloneGuard does not require credentials for operation)

## No Remote Network Dependencies

CloneGuard operates entirely offline in production:
- No telemetry
- No analytics
- No beacon/checkin calls
- No remote config management
- All detection runs locally on user's machine

---

*Integration audit: 2026-04-05*
