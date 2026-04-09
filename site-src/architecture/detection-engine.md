# Detection Engine

CloneGuard uses three independent detection signals combined by a fusion layer.

## Signal 1: Pattern Matching

240 compiled regex rules across 34 categories. Each rule specifies:

- **ID** -- unique identifier (e.g., `IO-001`, `RH-003`, `BRW-005`)
- **Regex** -- compiled pattern
- **Severity** -- HIGH, MEDIUM, or LOW
- **Category** -- attack type classification
- **Scan mode restriction** -- some rules only fire in STRICT mode to avoid
  false positives on regular code

### Categories

Core categories cover instruction override, authority impersonation, behavioral
manipulation, privilege escalation, encoding obfuscation, unicode anomalies,
exfiltration, credential harvesting, environment variable hijacking, build
script attacks, CI/CD poisoning, config file injection, git hook exploitation,
MCP tool poisoning, reasoning hijack, markdown/SVG injection, terminal escape,
memory poisoning, viral propagation, and more.

Agent-type expansion packs add domain-specific patterns:

| Pack | Prefix | Patterns | Covers |
|------|--------|----------|--------|
| Browser agents | BRW | 8 | DOM injection, URL redirect, cookie theft, extension abuse |
| Autonomous agents | AUT | 12 | Goal hijacking, delegation abuse, sandbox escape, SSTI, deserialization |
| Financial agents | FIN | 8 | Transaction manipulation, approval bypass, ledger tampering |
| CI/CD agents | CIC | 8 | Workflow injection, release poisoning, secret exfiltration |

### Scan Modes

Rules behave differently depending on the file being scanned:

| Mode | Files | Behavior |
|------|-------|----------|
| STRICT | CLAUDE.md, .cursorrules, GEMINI.md, AGENTS.md | HIGH = block; all patterns active |
| STANDARD | README.md, package.json, Makefile | HIGH = warning; CI hygiene patterns suppressed |
| LENIENT | Test files, fixtures | Severity downgraded |

## Signal 2: Semantic Classifier

A fine-tuned MiniLM-L6-v2 model exported to ONNX format. Runs locally with no
external API calls.

| Metric | Value |
|--------|-------|
| F1 (5-fold CV) | 94.34% +/- 0.77% |
| Recall (5-fold CV) | 93.68% +/- 1.77% |
| Precision (5-fold CV) | 96.23% +/- 0.79% |
| Inference speed | ~16ms per sample |
| Model size | 87 MB (ONNX) |

The classifier catches attacks that regex cannot: synonym substitution, social
engineering rewording, encoding evasion, homoglyphs, and counter-defensive
framing.

Per-ScanMode detection thresholds:

| Mode | Suspicious | Malicious |
|------|:---:|:---:|
| STRICT | 0.50 | 0.80 |
| STANDARD | 0.65 | 0.88 |
| LENIENT | 0.75 | 0.92 |

Install with `pip install "cloneguard[mini]"`.

## Signal 3: Behavioral Sequences (CaMeL-lite)

Tracks tool-call patterns across the agent session. Detects multi-step attack
sequences where individual steps appear benign but the combination is malicious.

| Rule | Detects | Mode |
|------|---------|------|
| SEQ-001 | Sensitive file read followed by network exfiltration | **Enforce** |
| SEQ-002 | Sensitive file read followed by move/copy to accessible location | **Enforce** |
| SEQ-005 | Write to agent config files | **Enforce** |
| SEQ-003 | Chained tool calls exceeding depth threshold | Advisory |
| SEQ-004 | Rapid-fire tool invocations within time window | Advisory |
| SEQ-006 | MCP tool call following sensitive file read | Advisory |

SEQ-001/002/006 use session-wide typed markers -- padding with benign events
between the read and exfiltration steps does not evade detection.

## Fusion Layer

The three signals are combined into a single verdict with calibrated confidence.
Weight profiles are tunable per deployment:

- **Pattern signal** -- high precision, low recall on novel attacks
- **Semantic signal** -- strong on evasion, weaker on truncation/fragmentation
- **Behavioral signal** -- orthogonal to content-based signals, catches sequences

The fusion layer was calibrated against 208,127 real coding-agent sessions from
published SWE-bench datasets to validate false positive rates.
