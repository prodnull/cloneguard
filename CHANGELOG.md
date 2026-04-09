# Changelog

All notable changes to CloneGuard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-04-07

First PyPI release. Completes the v2 architecture milestone: detection engine
extraction, adaptive enforcement, enterprise governance, and agent-type
expansion.

### Added

**Detection**
- 240 detection rules across 34 categories (up from 204/25 in v0.5.0)
- Agent-type expansion packs: browser (BRW), autonomous (AUT), financial (FIN),
  CI/CD (CIC) -- 36 seed patterns across 4 domains
- PraisonAI CVE response patterns: Jinja2 SSTI (AUT-009), Python frame traversal
  sandbox escape (AUT-010), YAML tag deserialization (AUT-011), SSTI probes (AUT-012)
- PatternEngine subdirectory scanning for expansion pack pattern libraries

**Enforcement**
- Three-verdict model: SAFE / SUSPICIOUS / MALICIOUS with operator-configurable
  thresholds via YAML policy engine
- Sandbox adapters: Landlock (Linux), Seatbelt (macOS), Docker, gVisor,
  Firecracker, WASM -- all conforming to SandboxAdapter Protocol
- Sandbox snapshot/rollback for Landlock and Seatbelt
- Dry-run as default for all new installations
- Adapter registry with D-08 strength ordering and auto-selection

**Audit and Observability**
- NDJSON structured audit with session_id, verdict, confidence, signals,
  and enforcement_action fields

**Enterprise Governance**
- OPA/Rego policy backend via regopy
- Cedar policy backend via cedarpy
- SIEM connectors: Splunk HEC, Microsoft Sentinel DCR, Google Chronicle UDM
- SPIFFE identity module with agent_identity injection into audit events
- Ansible role for fleet deployment
- MDM profiles for Jamf and Intune (macOS)

**Packaging**
- Detection engine types extracted into `cloneguard.detection` package
- Hook config integrity self-check via SettingsScanner (CVE-2025-59536 class
  defense)
- Optional dependency extras: `mini`, `semantic`, `opa`, `cedar`, `spiffe`,
  `splunk`, `sentinel`, `chronicle`, `docker`, `wasm`, `governance`,
  `sandbox`, `all`

### Changed

- Minimum Python version remains 3.11
- Default enforcement mode is dry-run (detection-only, no blocking)

## [0.5.0] - 2026-03-21

### Added
- CaMeL-lite behavioral sequence monitoring (SEQ-001 through SEQ-005)
- Typed event markers with session-wide tracking
- 204 regex patterns across 25 categories
- MiniLM-L6-v2 ONNX classifier (94.3% F1, 5-fold cross-validated)
- Trust cache with SHA-256 content hashing
- Allowlist with two-layer self-protection (CLI guard + hook guard)
- Per-ScanMode detection thresholds for ONNX classifier
- YOLO mode escalation when `--dangerously-skip-permissions` detected

## [0.4.0] - 2026-03-10

### Added
- Adversarial hardening after automated red team evaluation
- Encoding obfuscation patterns (base64, hex, URL, unicode escapes)
- Unicode anomaly detection (zero-width, RTL override, tag characters)

## [0.3.0] - 2026-03-09

### Added
- Multi-agent hook compatibility survey (Claude Code, Gemini CLI, Cursor,
  Windsurf, VS Code Copilot)
- CI/CD poisoning patterns
- MCP tool poisoning patterns

## [0.2.0] - 2026-03-07

### Added
- Initial regex pattern engine
- Tier 2 Ollama LLM classification fallback
- Basic hook integration for Claude Code

## [0.1.0] - 2026-03-06

### Added
- Initial proof of concept
- File scanning with basic prompt injection detection
