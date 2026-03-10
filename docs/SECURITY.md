# CloneGuard Security Model

This document describes CloneGuard's threat model, defense architecture, known limitations, and empirical validation results.

## Threat Model

**Attacker goal:** Hijack an AI coding agent (Claude Code, Gemini CLI, Codex CLI, Cursor, Copilot) by injecting prompt injection payloads into repository files the agent will read.

**Attacker capabilities:**
- Full control over repository content (CLAUDE.md, README.md, package.json, .cursorrules, .env, etc.)
- Cannot modify the user's home directory (`~/.cloneguard/`, `~/.claude/`)
- Cannot execute arbitrary code before CloneGuard runs (Layer 0 executes first)

**This threat is real and documented.** See [Real-World Evidence](#real-world-evidence) below.

**What CloneGuard makes harder:**

CloneGuard does not guarantee protection against any attack class. It raises the cost, skill, and risk of discovery required for successful prompt injection by adding detection layers that an attacker must evade:

- Known prompt injection patterns — 193 regex rules across 24 categories force attackers to avoid well-documented techniques
- Semantic prompt injection — bundled ONNX classifier (Tier 1.5, CV F1=95.80%) forces attackers beyond synonym substitution and social engineering rewording
- LLM classification (Tier 2, Ollama fallback) — adds a reasoning-capable detection layer for novel patterns
- HTML comment injection — scanner reads what human reviewers skip, removing a free hiding spot
- Self-propagating agent config files — detection of viral spread patterns (.cursorrules, CLAUDE.md)
- Credential harvesting via natural language — detects framing patterns, not just CLI commands
- Compliance/audit social engineering framing — pattern recognition for authority assertion
- Trust cache poisoning — SHA-256 content hashes in protected directory raise the bar for cache manipulation
- Agent-initiated allowlist manipulation — two-layer block (hook + TTY check) forces the attacker to defeat both
- TOCTOU attacks on scanned content — content bound to stdin, never re-read from disk, closing a race condition window

**What CloneGuard does NOT protect against:**
- Novel prompt injection that evades both Tier 1 regex and Tier 2 LLM
- Subtle insecure code generation instructions (e.g., "use http:// not https://") — requires Tier 2
- Attacks on the agent's runtime after content has been approved
- Traditional code vulnerabilities (XSS, SQLi, logic bugs)
- Supply chain attacks that don't involve prompt injection
- An attacker with access to the user's home directory

## Defense Layers

### Layer 0: Pre-Execution Wrapper

Runs before the agent starts. Scans all high-priority and medium-priority files in the repository. Blocks agent launch if critical issues are found.

**Cannot be disabled by repository content** — executes before the agent reads any files.

### Layer 1: InstructionsLoaded Hook

Scans instruction files (CLAUDE.md, `.claude/rules/*.md`) when the agent loads them. Uses STRICT scan mode — HIGH severity findings result in a hard block (exit 2).

### Layer 2: PostToolUse Hook

Scans all tool output for injection patterns. Catches payloads injected via tool results (e.g., a `cat` command reading a malicious file).

### Layer 3: PreToolUse Hook

Gates dangerous operations before they execute:
- **Protected paths** — blocks writes to `~/.claude/settings.json`, trust stores, and other config files
- **Content-aware write scanning** — scans content being written to sensitive files (package.json, Makefile, CLAUDE.md, etc.)
- **Build command gating** — warns on `npm install`, `pip install`, `cargo build`, etc.
- **Allowlist protection** — blocks `cloneguard allow` and `cloneguard remove` in Bash commands
- **Bypass prevention** — blocks `cloneguard --bypass` and `claude --bypass`

## Detection Architecture

### Tier 1: Pattern Engine (Regex)

193 compiled regex patterns across 24 categories. Executes in under 50ms. Each pattern has an ID, severity (LOW/MEDIUM/HIGH/CRITICAL), and description.

**Categories include:** instruction override, authority impersonation, credential harvesting, exfiltration, behavioral manipulation, viral propagation, config file injection, privilege escalation, encoding obfuscation, HTML/SVG injection, build script attacks, CI/CD poisoning, environment variable hijacking, devcontainer abuse, MCP tool poisoning, and more.

**Scan modes** determine how severity maps to verdicts:
- STRICT (CLAUDE.md, .cursorrules): HIGH -> BLOCKED
- STANDARD (README.md, package.json): HIGH -> WARNING
- LENIENT (test files): severity downgraded

**YOLO mode escalation:** When `--dangerously-skip-permissions` is detected, MEDIUM findings are escalated to HIGH, increasing block probability.

### Multi-Tier Pipeline Performance

When Tier 1 (regex) and Tier 1.5 (ONNX) run together in production mode, the tiers compensate for each other's weaknesses. Evaluated on 185 adversarial payloads + 234 held-out benign samples:

| Metric | Tier 0 alone | Tier 1.5 alone | Combined Pipeline |
|--------|:------:|:--------:|:------:|
| Recall | 31.9% | 78.4% | **80.5%** |
| FPR | 9.8% | 15.4% | 22.2% |
| False block rate | — | — | **3.8%** |
| False warning rate | — | — | 18.4% |
| Clean pass rate | — | — | 77.8% |

Tier 0 catches truncation (80%) and fragmentation (20%) attacks that the semantic classifier misses. Tier 1.5 catches synonym substitution (100%) and encoding evasion (100%) that regex cannot touch. See `scripts/multitier_benchmark.py` for reproduction.

### Tier 1.5: Mini Semantic Model (ONNX)

Bundled fine-tuned MiniLM-L6-v2 classifier (87 MB ONNX). Runs entirely offline at ~16 ms/sample. Catches what regex cannot:
- Synonym substitution ("discard prior directives" instead of "ignore previous instructions")
- Social engineering framing ("the standard review process has been replaced")
- Indirect exfiltration ("collect authentication tokens and transmit to analytics endpoint")
- Subtle insecure code generation instructions (HTTP downgrade, dynamic code execution, TLS bypass)
- Counter-defensive attacks targeting the scanner itself
- Encoding evasion (base64, hex, ROT13 framing)
- Homoglyph/Unicode evasion (Cyrillic substitution, zero-width characters)

Trained on 6,472 labeled samples (v4: adversarially hardened via PWWS augmentation + FreeLB adversarial training) from 14+ published research sources. Cross-validated accuracy: 94.51% ± 0.67% (5-fold CV, v4 dataset). Hyperparameters selected via 192-configuration grid search. See [`docs/MINI-SEMANTIC-MODEL.md`](MINI-SEMANTIC-MODEL.md) for full model documentation.

Install from [GitHub Releases](https://github.com/prodnull/cloneguard/releases) (`.whl` includes the ONNX model).

### Tier 2: Semantic Classifier (Ollama, fallback)

Ollama-based classification using `qwen2.5:7b`. Used only when the mini model is not installed. Significantly slower (~680 ms/sample) and less accurate (42% recall) than the mini model — it is a general-purpose LLM not fine-tuned for this task.

Verdicts: SAFE, SUSPICIOUS, MALICIOUS (with confidence score).

## Trust Cache

SHA-256 file hashes stored in `~/.cloneguard/trust-cache.json`.

**How it works:**
1. File content is hashed (SHA-256)
2. The hash is stored keyed by `{repo_path}:{rel_path}` — binding the entry to the specific file location
3. On subsequent scans, if the current file hash matches the cached hash, scanning is skipped

**Security properties:**
- Any file modification invalidates the cache entry (hash mismatch)
- Cache entries are keyed by repo path + file path — an entry for one file cannot apply to another
- Corrupt cache files are detected and reset
- Tier 2 clean status is tracked separately (a file can be Tier 1 clean but not yet Tier 2 verified)
- The cache file lives in `~/.cloneguard/` — outside the repository, so repo content cannot tamper with it

## Allowlist

Content-hash based false positive suppression, stored in `~/.cloneguard/allowlist.json`.

### Purpose

Files that legitimately contain attack pattern strings (security documentation, test fixtures, research notes) will trigger false positives. The allowlist lets users mark specific file contents as reviewed and safe.

### How It Works

1. User runs `cloneguard allow <file> --reason "..."` at an interactive terminal
2. CloneGuard computes SHA-256 of the file's current content
3. The hash, file path (informational), reason, and timestamp are stored in `~/.cloneguard/allowlist.json`
4. On subsequent scans, if a file's content hash matches an allowlisted hash, findings are suppressed

### Security Properties

**Content-bound, not path-bound.** The allowlist stores content hashes, not file paths. If an attacker modifies an allowlisted file -- even by a single byte -- the hash no longer matches and the file is scanned normally. An attacker cannot allowlist a clean file and then replace it with a malicious one.

**Stored outside the repository.** The allowlist lives in `~/.cloneguard/`, not in the repo. Repository content cannot add, modify, or remove allowlist entries.

**Two-layer agent protection.** A compromised AI agent cannot manipulate the allowlist:

| Layer | Mechanism | What it blocks |
|-------|-----------|---------------|
| PreToolUse hook | Bash commands containing `cloneguard allow` or `cloneguard remove` are blocked (exit 2) before reaching the shell | Agent using Bash tool to run allowlist commands |
| CLI `isatty()` check | `cloneguard allow` and `cloneguard remove` refuse to run when stdin is not a TTY | Any non-interactive invocation (pipes, subprocesses, scripts) |

Both layers must be defeated for an agent to modify the allowlist. Neither is achievable through prompt injection:
- The hook runs before the command executes -- the agent cannot bypass it
- The TTY check is a kernel-level property -- prompt injection cannot forge it

### Commands

```bash
cloneguard allow <file> --reason "..."   # add (interactive only)
cloneguard list                           # view entries (no restriction)
cloneguard remove <file|hash>             # remove (interactive only)
```

## Real-World Evidence

CloneGuard addresses a documented, active threat. This is not theoretical.

### Assigned CVEs (partial list)

| CVE | Tool | Impact | CVSS |
|-----|------|--------|------|
| CVE-2025-59536 | Claude Code | RCE via malicious `.claude/settings.json` hooks | 8.7 |
| CVE-2026-21852 | Claude Code | API key exfiltration via `.env` ANTHROPIC_BASE_URL | 5.3 |
| CVE-2025-53773 | GitHub Copilot | Wormable RCE via prompt injection in README/issues | 7.8 |
| CVE-2025-54130 | Cursor | RCE via MCP server prompt injection | -- |
| CVE-2025-61590 | Cursor | RCE via VS Code workspaces + MCP | -- |
| IDEsaster (24+ CVEs) | All major AI IDEs | Universal prompt injection to tool abuse chain | -- |

### Confirmed Real-World Attacks

- **Clinejection (Feb 2026):** Prompt injection in a GitHub issue title led to npm supply chain compromise, infecting ~4,000 developer machines
- **RoguePilot (Feb 2026):** Hidden HTML comments in GitHub issues caused Copilot to exfiltrate GITHUB_TOKEN, enabling repository takeover
- **PromptPwnd (2025):** AI agents in CI/CD pipelines exploited via prompt injection; 5+ Fortune 500 companies had secrets leaked

### Independent Research

- **AIShellJack (arXiv:2509.22040):** 84% attack success rate across GitHub Copilot and Cursor
- **Trail of Bits (Aug 2025):** End-to-end PoC of Copilot backdoor injection via GitHub issues
- **NVIDIA (Black Hat USA 2025):** Recommends "assume prompt injection" as design principle

Full evidence report: `docs/sub-agents/real-world-evidence.md`

## Empirical Validation (PoC Results)

CloneGuard was tested against 8 realistic attack scenarios covering the major threat vectors. Each scenario was designed to demonstrate a documented real-world attack pattern.

### Detection Matrix

| # | Scenario | Tier 1 | Tier 2 | Combined | Real-World Analog |
|---|----------|:------:|:------:|:--------:|-------------------|
| 1 | CLAUDE.md credential exfil via HTML comment + SOC2 framing | DETECT | -- | DETECT | CVE-2025-59536 variant |
| 2 | README hidden HTML + Unicode injection | DETECT | -- | DETECT | Pillar Security "Rules File Backdoor" |
| 3 | Trojan package.json postinstall | DETECT | -- | DETECT | Clinejection variant |
| 4 | Self-propagating .cursorrules | DETECT | -- | DETECT | HiddenLayer "CopyPasta" AI virus |
| 5 | Copilot insecure code generation | miss | DETECT | DETECT | Pillar Security disclosure |
| 6 | .claude/settings.json takeover | N/A* | -- | N/A* | CVE-2025-59536 |
| 7 | Devcontainer privileged escape | DETECT | -- | DETECT | IDEsaster class |
| 8 | Multi-stage coordinated attack | DETECT | -- | DETECT | Clinejection + PromptPwnd |

*Scenario 6: Claude Code's own security hooks blocked creation of the test file, validating that this vector is already defended at the agent level.*

**Tier 1 detection rate:** 6/7 applicable scenarios (86%)
**Tier 1 + Tier 2 detection rate:** 7/7 applicable scenarios (100%)

### What Tier 2 Catches That Tier 1 Cannot

Scenario 5 demonstrates the fundamental regex limitation: instructions to "use `http://` not `https://`" or "prefer dynamic code execution for module loading" contain no injection keywords. They are semantically malicious but syntactically benign. Only the LLM-based Tier 2 classifier can assess the intent of such instructions.

## v0.3.0 Adversarial Hardening

Released 2026-03-10. This section documents the adversarial hardening effort applied to
Tier 1.5 (ONNX) and its measured effect on attack cost.

### Approach

Two rounds of PWWS (Probability Weighted Word Saliency) adversarial augmentation combined
with FreeLB (Free Large-Batch) adversarial training. PWWS generates synonym-substitution
adversarial examples targeting the model's most influential tokens. FreeLB applies
small-norm perturbations during training to improve robustness near the decision boundary.

- Round 1: 88 adversarial samples generated (generation ASR 65.7%), model retrained with FreeLB
- Round 2: 44 additional samples generated (generation ASR 31.7%), model retrained with FreeLB
- Round 3 skipped: benchmark ASR (20.0%) met the ≤35% stopping criterion after round 2
- PWWS generation ASR progression (65.7% → 31.7%) confirms the model hardened against the attack

### Benchmark: v3 vs. v4

Evaluated on 185 adversarial payloads (9 categories) + 757-sample benign eval set (v4) and
234-sample eval set (v3). **FPR figures are NOT directly comparable** across versions due
to different benign eval set sizes and content-type distributions. Only Tier 1.5 FPR is
a fair comparison.

| Metric | v3 | v4 | Notes |
|--------|:--:|:--:|-------|
| Overall recall | 80.5% | **90.3%** | Same 185-sample malicious corpus |
| **Tier 1.5 FPR** | 15.4% | **9.2%** | Most comparable: both Tier 1.5 standalone |
| Overall FPR | 3.8% | 19.0% | **Not comparable**: v3=234 samples, v4=757 samples |
| ASR (all categories) | 20.0%† | **9.7%**† | |
| ASR (vocab attacks) | — | **0.0%** | Encoding + synonym + homoglyph = 0% |
| Latency p95 | — | 16.61 ms | < 25 ms gate: PASS |
| 5-fold CV accuracy | 95.71% ± 0.53% | **94.51% ± 0.67%** | v4 on 6,472 samples |

†v3 ASR measured during round-2 training. v4 ASR measured on the final v4 model post-training.
Both are real measurements but describe different scenarios — see Adaptive Attack below.

### Adaptive Attack Ceiling

A fresh PWWS attack was run against the final v4 model as a test-time adversary (distinct
from the round-2 training-time measurement):

- **Adaptive ASR: 20.3%** (95% Wilson CI: 14.6%–27.5%)
- 30 successful evasions out of 148 attempts (37 samples excluded: already misclassified before attack)

The adaptive ASR (20.3%) is higher than the training-time benchmark ASR (9.7%). This reflects
the difference between samples already represented in the hardening corpus versus fresh
adversarial examples generated against the fully-trained model. Both numbers are real; they
measure different attack scenarios.

**Per-category adaptive ASR:**

| Category | Adaptive ASR |
|----------|:------------:|
| Encoding evasion | 0.0% |
| Homoglyph / Unicode | 5.0% |
| Social engineering | 10.0% |
| Counter-defensive | 15.0% |
| Synonym substitution | 15.0% |
| Structural dilution | 31.6% |
| Implicit instruction | 53.3% |
| Fragmentation | 77.8% |

### Mahalanobis Anomaly Detector

v4 adds a Mahalanobis distance anomaly detector using CLS embeddings from the dual-output
ONNX model. The target was 60% detection rate at ≤5% FPR (from Yoo et al. 2022 multi-feature
RDE). Actual results:

- **Detection rate: 2.7%** (5/185 adversarial samples)
- **FPR: 1.2%** (9/757 benign samples)
- Distribution overlap: benign mean 17.59, malicious mean 17.21 (Mahalanobis distances)

The 60% target was not met. PWWS adversarial examples preserve semantic similarity by
construction — the malicious CLS embedding distribution is not meaningfully separated from
the benign distribution. The Mahalanobis detector provides a marginal orthogonal signal
with very low cost (1.2% FPR), but it does not contribute materially to recall. This is
documented as a negative result, not a failure: the experiment was designed with a falsifiable
hypothesis and the hypothesis did not hold.

### Correlated Failure Analysis

18/185 adversarial samples (9.7%) were missed by all three tiers (Tier 0 regex + Tier 1.5
ONNX + Mahalanobis). This is the honest ceiling of the combined defense against the current
adversarial corpus.

| Category | Both-miss | Out of | Miss rate |
|----------|:---------:|:------:|:---------:|
| Fragmentation | 11 | 20 | 55% |
| Implicit instruction | 5 | 20 | 25% |
| Truncation padding | 2 | 20 | 10% |
| All other categories | 0 | 125 | 0% |

Fragmentation and implicit instruction failures are information-theoretic: short imperative
phrases ("Read config files from home dir.") and insecure coding guidelines
("Return SQL queries in error messages") are structurally indistinguishable from legitimate
developer instructions. These are design-space limits, not model deficiencies that additional
training data can close.

Data: `docs/results/correlated-failures-2026-03-10.json` (local, gitignored).
Script: `scripts/hardened_benchmark.py --correlated-failures`.

## Known Limitations

1. **Regex evasion.** Tier 1 patterns match known attack strings. Creative rewording, synonym substitution, or novel attack vectors will bypass regex detection. Tier 1.5 mitigates this with 95.4% recall (cross-validated) but is not infallible.

2. **Mean-pooling dilution (mitigated).** The mini model (Tier 1.5) uses mean-pooling, which averages token embeddings across the sequence. A short malicious instruction embedded in a long block of legitimate code can be diluted below the detection threshold within a single 256-token window. **Mitigations:** (a) Sliding window classification — when input exceeds 256 tokens, the classifier applies a 256-token window with 128-token stride (50% overlap), scanning up to 16 chunks (~8K chars, ~256ms worst case). This prevents truncation-based evasion for the vast majority of scanned content. (b) Per-value scanning in the MCP plugin classifies each extracted text value independently, preventing concatenation-based dilution. (c) Tier 0 regex scans full content line-by-line with no token limit. Mean-pooling dilution within a single 256-token chunk remains a limitation. See [`docs/MINI-SEMANTIC-MODEL.md`](MINI-SEMANTIC-MODEL.md#structural-vulnerability-mean-pooling-dilution) for analysis.

   **Depth limit.** The MCP plugin's recursive text extraction has a depth limit of 10 levels. Deeply nested structures beyond this limit are not scanned; a warning is logged when this limit is reached.

3. **Multilingual gaps.** The mini model has limited non-English training data (~30 samples). Non-English attacks may evade Tier 1.5. Tier 2 (Ollama) handles multilingual content natively if available.

4. **Not a sandbox.** CloneGuard scans files before the agent processes them. It does not constrain what the agent does after content is approved. A payload that bypasses all detection tiers will execute normally.

5. **Build script scanning is limited.** CloneGuard warns on build commands but does not analyze what build scripts will do. A `Makefile` with an obfuscated payload may pass Tier 1 and execute harmful commands.

6. **Bypass flag.** `cloneguard --bypass` skips Layer 0 scanning entirely. Layers 1-3 (hooks) remain active, but the pre-execution scan is lost. This flag exists for known-trusted repos where scanning overhead is unwanted. The PreToolUse hook blocks agents from invoking this flag.

7. **Single-user scope.** The trust cache and allowlist are per-user (`~/.cloneguard/`). In shared environments (CI runners, containers), each user/process has its own state.

8. **Multi-file coordination.** Files are scanned independently. A coordinated attack where each file appears innocent in isolation but becomes dangerous when processed together may evade detection. Tier 2 mitigates some cases by analyzing all files together.

9. **Layer 0 TOCTOU gap.** Layer 0 scans files on disk, then the agent reads them. A race condition is theoretically possible if files change between scan and read. Layers 1-3 mitigate this since they scan the actual content the agent processes (via stdin JSON).

10. **No guarantee of long-term viability.** This defense pattern — regex + embedding classifier + runtime hooks — has not been formally proven to be durable against adaptive adversaries. It is plausible that advances in adversarial ML, novel LLM exploitation techniques, or fundamental changes in how agents process input could render this entire approach ineffective. The 95.8% F1 is measured against today's attack distribution; future attacks are unconstrained. Defense-in-depth buys time and raises cost, but it is an empirical bet, not a mathematical guarantee. If the underlying assumption — that semantic evasion is structurally harder than byte-level evasion — is invalidated, the ONNX classifier's advantage over regex diminishes. We publish this tool as a practical improvement over no defense, not as a solved problem.

## Performance Overhead

CloneGuard is designed to add negligible latency relative to LLM API calls (typically 2–30 seconds).

| Component | Latency | Context |
|-----------|---------|---------|
| Tier 0 regex (193 patterns) | <50 ms | Full repo scan (~20 files) |
| Tier 1.5 ONNX (per file) | ~16 ms | Single file classification |
| Tier 2 Ollama (per file) | ~680 ms | Single file, local inference |
| Layer 0 full scan (Tier 0+1.5, 20 files) | ~370 ms | Pre-execution wrapper |
| Layer 1-3 hooks (per invocation) | <50 ms | Tier 0 only; ~70 ms with Tier 1.5 |
| Tier 1.5 ONNX sliding window (long input) | ~256 ms | Max 16 chunks × 16ms |
| MCP Gateway plugin (per request) | ~20 ms | Tier 0 + Tier 1.5 combined |
| Trust cache hit | ~0 ms | SHA-256 comparison only |

**Comparative context:** A single LLM API call to Claude, GPT-4, or Gemini takes 2–30 seconds. CloneGuard's Tier 0+1.5 scan adds <1% overhead to a typical agent session.
