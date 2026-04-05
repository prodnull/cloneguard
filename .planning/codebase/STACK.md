# Technology Stack

**Analysis Date:** 2026-04-05

## Languages

**Primary:**
- Python 3.11+ (3.11, 3.12, 3.13 tested)

## Runtime

**Environment:**
- Python 3.11, 3.12, 3.13 (minimum: 3.11)

**Package Manager:**
- uv (setup orchestration, lockfile management)
- pip (transitive, used via uv)

## Frameworks & Core Libraries

**Core Dependencies:**
- PyYAML >=6.0 - Pattern file parsing (YAML rules in `src/cloneguard/rules/`)

**Optional ML/Detection:**
- onnxruntime >=1.17 - Tier 1.5 semantic inference (ONNX Runtime, CPU execution provider)
- transformers >=4.36 - Tokenizer for mini semantic classifier (loads from `src/cloneguard/model/`)
- numpy >=1.26 - Numerical operations for Mahalanobis anomaly detection
- ollama >=0.4 - Tier 2 fallback semantic classification via local Ollama service

**Optional MCP Integration:**
- mcp-gateway - MCP plugin system (not shipped, optional for MCP server deployment)

## Build & Development

**Build System:**
- hatchling (build backend)
- setuptools (transitive)

**Testing:**
- pytest >=8.0 - Test runner
- pytest-cov >=6.0 - Coverage reporting

**Code Quality:**
- ruff >=0.8 - Linting and formatting (strict: E, F, I, N, W, UP rules)
- mypy >=1.13 - Static type checking (strict mode enabled)
- types-PyYAML >=6.0 - Type stubs for PyYAML

## ML Model Assets

**Bundled:**
- **mini_semantic.onnx** (90.8 MB) - Fine-tuned sentence-transformers/all-MiniLM-L6-v2 for prompt injection detection
  - Location: `src/cloneguard/model/mini_semantic.onnx`
  - Opset 18, dual-output (logits + CLS embedding for anomaly detection)
  - Runs in ONNX Runtime, no external services required

**Auxiliary:**
- **mahalanobis_params.npz** (2.4 MB) - Pre-fitted Mahalanobis detector parameters
  - Location: `src/cloneguard/model/mahalanobis_params.npz`
  - Per-class means and inverse covariances for OOD detection
  - Loaded only if present; graceful degradation if missing

**Tokenizer:**
- Location: `src/cloneguard/model/`
- Files: `tokenizer.json` (712 KB), `vocab.txt` (232 KB), `tokenizer_config.json`, `special_tokens_map.json`
- Source: all-MiniLM-L6-v2 tokenizer (WordPiece, 256-token max length)

## Pattern Rules

**Storage:**
- 25 YAML rule files in `src/cloneguard/rules/`
- 204+ total patterns (as of commit 5ccfccd)
- Categories: instruction override, credential harvesting, encoding evasion, behavioral manipulation, exfiltration, privilege escalation, CI/CD poisoning, and more

**Example rule files:**
- `authority_impersonation.yaml` - Fake [SYSTEM] messages, vendor impersonation
- `exfiltration.yaml` - env var, API key, credential harvesting patterns
- `instruction_override.yaml` - Ignore previous instructions, prompt override attempts

## Configuration

**Environment Variables:**
- `HF_TOKEN` - (CI only) Hugging Face token for model artifact fetching
- `CLONEGUARD_REVIEW_LOG` - Optional path to low-confidence classification review log (JSONL)
- `CLONEGUARD_REVIEW_THRESHOLD` - Confidence threshold for review logging (default: 0.98)
- Threshold overrides for each ScanMode (e.g., `CLONEGUARD_THRESHOLD_STRICT_SUSPICIOUS`)

**Configuration Files:**
- `~/.claude/settings.json` - Global hook configuration (installed by `cloneguard init --global`)
- `.claude/settings.json` - Project-level hook configuration (installed by `cloneguard init --project`)

**Hook Event Types:**
- `InstructionsLoaded` - Scan CLAUDE.md when loaded
- `PreToolUse` - Gate writes, builds, config changes
- `PostToolUse` - Scan all tool output

## Platform Requirements

**Development:**
- macOS 10.15+ or Linux (tested on ubuntu-latest and macos-latest)
- Python 3.11+ development environment
- uv package manager (modern Python workflow)

**Production:**
- Linux (ubuntu-latest primary CI target) or macOS
- Python 3.11+ runtime
- For Tier 1.5: 87 MB disk space for ONNX model + 2.4 MB for Mahalanobis params
- For Tier 2: Local Ollama service (if enabled)

**Deployment Targets:**
- AI coding agents: Claude Code, Gemini CLI, Codex CLI, Cursor, GitHub Copilot
- CI/CD pipelines (Docker container integration tested via `tests/integration/`)
- MCP Gateway plugin system (optional)
- Standalone CLI tool (no agent required for `cloneguard scan`)

## Packaging

**Wheel Contents:**
- Source: `src/cloneguard/`
- ONNX model artifact: `src/cloneguard/model/mini_semantic.onnx` (verified in release CI)
- Entry point: `cloneguard = cloneguard.cli:main`

**Distribution:**
- Published to PyPI (when available)
- GitHub Releases include `.whl` with embedded ONNX model
- Optional extras: `[mini]` (ONNX runtime + dependencies), `[semantic]` (Ollama), `[all]` (both)

## Testing Infrastructure

**Test Matrix:**
- Python 3.11, 3.12, 3.13 on ubuntu-latest (CI job: `test`)
- macOS latest (CI job: `test-macos`)
- Docker integration tests (CI job: `integration`)
- Ollama-based Tier 2 tests (CI job: `test-tier2`)

**Execution:**
- pytest with coverage tracking (target: 85%+)
- Test markers: `@pytest.mark.ollama` for Tier 2-specific tests
- Security-specific tests: `tests/test_security_vectors.py`

---

*Stack analysis: 2026-04-05*
