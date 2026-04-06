---
phase: 04-detection-excellence
plan: 03
subsystem: detection-patterns
tags: [patterns, mcp, rade, memory-poisoning, dotfile-injection, workspace-config]
dependency_graph:
  requires: []
  provides: [cross-agent-patterns, mcp-registry, rade-detection]
  affects: [detection-engine, pattern-engine, scanner]
tech_stack:
  added: [mcp-registry-json]
  patterns: [recursive-yaml-loading, sha256-fingerprinting, graceful-degradation]
key_files:
  created:
    - src/cloneguard/detection/mcp_registry.py
    - src/cloneguard/detection/mcp_registry.json
    - src/cloneguard/rules/memory/agent_memory_poisoning.yaml
    - src/cloneguard/rules/memory/dotfile_injection.yaml
    - src/cloneguard/rules/memory/workspace_config_poisoning.yaml
    - src/cloneguard/rules/mcp/tool_description_fingerprinting.yaml
    - src/cloneguard/rules/mcp/mcp_rade_patterns.yaml
    - tests/test_mcp_registry.py
  modified:
    - src/cloneguard/detection/patterns.py
    - tests/test_patterns.py
    - tests/test_integration_all_patterns.py
  moved:
    - src/cloneguard/rules/*.yaml -> src/cloneguard/rules/coding/*.yaml (25 files)
decisions:
  - Renamed workspace config poisoning IDs from WC- to WCP- prefix to avoid collision with existing WC-001..WC-007 in workspace_config_exec.yaml
  - Fixed \b word boundary before dotfile names (DF-002, DF-004) since dot is not a word character
  - MCP registry uses placeholder hashes with length-range fallback for initial release
metrics:
  duration: 12m 23s
  completed: "2026-04-06T17:09:32Z"
  tasks_completed: 2
  tasks_total: 2
  tests_added: 34
  tests_total_passing: 531
  patterns_added: 18
  patterns_total: 222
  files_created: 8
  files_modified: 3
  files_moved: 25
---

# Phase 04 Plan 03: Cross-Agent Pattern Library and MCP Registry Summary

Reorganized pattern library into category subdirectories, added 12 memory/config poisoning and 6 MCP RADE detection patterns, implemented SHA-256-based MCP tool description fingerprinting registry with graceful degradation.

## What Changed

### Pattern Library Reorganization (D-15)

PatternEngine glob updated from `*.yaml` to `**/*.yaml` for recursive subdirectory loading. All 25 existing YAML rule files moved to `rules/coding/` via `git mv` preserving history. New `rules/memory/` and `rules/mcp/` subdirectories created. Backward compatible -- all existing tests pass without modification.

### Memory/Config Poisoning Patterns (D-16)

Three new YAML rule files with 12 patterns covering:

- **Agent memory poisoning** (MP-003 to MP-006): Detects instructions to modify MEMORY.md, SOUL.md, .claude/memory, .cursor/memory, conversation history injection, and direct memory injection commands.
- **Dotfile injection** (DF-001 to DF-004): Detects shell config injection (bashrc, zshrc), SSH/git config manipulation, and .env file creation via both command patterns and instruction patterns.
- **Workspace config poisoning** (WCP-001 to WCP-004): Detects IDE settings manipulation, devcontainer poisoning, VS Code tasks.json with suspicious commands, and agent rules file manipulation.

### MCP Registry and RADE Detection (D-17)

`MCPRegistry` class provides SHA-256 hash-based fingerprinting of MCP tool descriptions against a known-good registry. Ships as JSON package resource (`mcp_registry.json`). Three filesystem MCP server entries as placeholders with length-range fallback when hashes are empty.

Six new patterns in `rules/mcp/`:
- **MCPF-001/002/003**: Detect anomalous tool descriptions (excessive length, external URLs, behavioral directives).
- **RADE-001/002/003**: Detect Remote Agent Description Edit attacks (description change references, privilege escalation in tool lists, dangerous input schema defaults).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Renamed WCP- prefix for workspace config poisoning patterns**
- **Found during:** Task 1
- **Issue:** Plan specified WC-001..WC-004 IDs for workspace_config_poisoning.yaml, but existing workspace_config_exec.yaml already uses WC-001 through WC-007. Duplicate IDs would cause test confusion and incorrect pattern attribution.
- **Fix:** Renamed new patterns to WCP-001..WCP-004 (Workspace Config Poisoning prefix)
- **Files modified:** src/cloneguard/rules/memory/workspace_config_poisoning.yaml

**2. [Rule 1 - Bug] Fixed word boundary before dotfile names in DF-002 and DF-004 regexes**
- **Found during:** Task 1 test verification
- **Issue:** `\b` before `\.bashrc` / `\.env` never matches because `.` (dot) is not a word character, so `\b` at that position is never a boundary transition.
- **Fix:** Removed the erroneous `\b` before the dotfile group in both DF-002 and DF-004 patterns.
- **Files modified:** src/cloneguard/rules/memory/dotfile_injection.yaml

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | beff18c | Pattern library reorganization + memory/config poisoning patterns |
| 2 (RED) | f00f262 | Failing tests for MCP registry and RADE detection |
| 2 (GREEN) | 94a079f | MCPRegistry implementation + RADE patterns passing all tests |

## Verification Results

- `python -m pytest tests/test_patterns.py -x`: 144 passed
- `python -m pytest tests/test_integration_all_patterns.py -x`: 371 passed
- `python -m pytest tests/test_mcp_registry.py -x`: 16 passed
- `python -m ruff check src/cloneguard/detection/patterns.py`: all checks passed
- `python -m ruff check src/cloneguard/detection/mcp_registry.py`: all checks passed
- `python -m mypy src/cloneguard/detection/mcp_registry.py --strict`: no issues found
- PatternEngine loads 222 rules from 30 categories across 3 subdirectories

## Self-Check: PASSED

All 9 created files exist. All 3 commits verified in git log. Recursive glob, MCPRegistry class, and sha256 fingerprinting confirmed in source. 25 coding rule files in rules/coding/.
