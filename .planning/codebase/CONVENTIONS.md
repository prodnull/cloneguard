# Coding Conventions

**Analysis Date:** 2026-04-05

## Naming Patterns

**Files:**
- Lowercase snake_case for module files: `patterns.py`, `monitor.py`, `semantic.py`
- Underscore prefix for private modules: `_strict_basenames` (constants), internal helpers
- Test files follow `test_*.py` naming convention

**Functions:**
- snake_case for all function names (public and private)
- Prefix with `_` for private/internal functions: `_get_engine()`, `_detect_mode()`
- Descriptive names indicating purpose: `record_event()`, `check_enforcement()`, `classify()`

**Variables:**
- snake_case for all variables: `session_id`, `tool_input`, `malicious_threshold`
- ALL_CAPS for module-level constants: `_MAX_SESSION_EVENTS`, `_SAFE_HOSTS`, `_STRICT_BASENAMES`
- Type-annotated throughout: `session_id: str`, `events: list[dict]`

**Types:**
- PascalCase for class names: `PatternEngine`, `ToolCallMonitor`, `SemanticClassifier`
- PascalCase for Enum names: `Severity`, `Verdict`, `ScanMode`, `SemanticVerdict`
- Type hints use modern Python 3.11+ syntax: `dict[str, Any]`, `list[PatternMatch]`, `Path | None`

## Code Style

**Formatting:**
- Ruff with line-length 100 (configured in `pyproject.toml`)
- `from __future__ import annotations` at module top for forward-compatible type hints
- Docstrings: module-level at top in triple quotes, with description of purpose and design

**Linting:**
- Ruff rules: `["E", "F", "I", "N", "W", "UP"]` (style, undefined, imports, naming, whitespace, upgrades)
- mypy strict mode enforced: `python_version = "3.11"` + `strict = true`
- Import sort via Ruff: groups from `__future__`, stdlib, third-party, local

**Error Handling:**
- Try-except blocks surround external dependencies that may fail to import: `from cloneguard.mini_semantic import MiniSemanticClassifier`
- Pass silently on ImportError for optional dependencies; return `None` or `False`
- Broad `except Exception` only in subprocess/network contexts where failure must not propagate
- Never raise from `record_event()` functions (safety constraint: monitor failure blocks agents)

## Import Organization

**Order:**
1. `from __future__ import annotations` (always first)
2. Standard library imports (`os`, `re`, `json`, `sys`, `time`, `pathlib.Path`)
3. Third-party imports (`yaml`, `pytest`, `numpy`)
4. Relative local imports (`from cloneguard.patterns import PatternEngine`)

**Examples from codebase:**
```python
# hooks.py
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from cloneguard.monitor import get_monitor
from cloneguard.patterns import PatternEngine, PatternMatch, ScanMode, Severity, Verdict
```

**Path Aliases:**
- No aliases used; absolute imports from `cloneguard.*` package
- All relative paths via `pathlib.Path` (no string paths)

## Comments & Documentation

**Module Docstrings:**
- All modules begin with a docstring describing purpose, design, and key constraints
- Examples: `hooks.py` explains the three layer defense architecture and TOCTOU hardening
- `monitor.py` documents the "NEVER raises" and "never blocks" contract

**Function Docstrings:**
- Arguments documented with type hints in signature, not in docstring
- Complex functions include examples: `_detect_mode_for_tier15()` shows signal precedence
- Design rationale documented inline: "STRICT > STANDARD > LENIENT ordinal for max() comparison"

**Inline Comments:**
- Used for non-obvious algorithmic choices: "Signal precedence (highest wins; content markers can only upgrade, never downgrade)"
- NOT used for obvious code (e.g., no comment before `return result`)
- Locked/frozen behavior marked: `# LOCKED — see Phase 5 CONTEXT.md. Do not modify.`

**Docstring Style:**
- Triple-quoted strings for module docstrings
- Concise, one-sentence descriptions for function purpose
- Design constraints documented in docstring when relevant

## Function Design

**Size:**
- Most functions 20-50 lines; helpers can be 5-10 lines
- Complex orchestration (e.g., `RepoScanner.scan()`) reaches 100+ lines but stays focused on flow

**Parameters:**
- Type-hinted: `def scan(self, content: str, source_path: str) -> ScanResult:`
- Use dataclasses for complex parameter collections: `ScanResult`, `PatternMatch`, `ToolEvent`
- No positional-only or keyword-only markers (rely on clear naming)

**Return Values:**
- Dataclass returns for structured data: `ScanResult`, `SemanticFinding`, `EnforcementVerdict`
- Tuples for simple pairs: `tuple[int, str]` (exit code, output)
- Optional returns use `| None`: `def _get_mini_classifier() -> Any | None:`

## Module Design

**Exports:**
- No `__all__` list; all public names are those without leading underscore
- Module-level singletons loaded once per process: `_engine: PatternEngine | None = None`
- Lazy initialization via sentinel functions: `_get_engine()`, `_get_mini_classifier()`

**Dataclasses:**
- Frozen dataclasses for immutable rule definitions: `@dataclass(frozen=True) class _CompiledRule:`
- Standard dataclasses for mutable collections: `@dataclass class ScanResult:`
- Field defaults via `field(default_factory=...)` for mutable defaults: `matches: list[PatternMatch] = field(default_factory=list)`

## Error Handling

**Pattern:**
- Specific exceptions at API boundary, broad catches for internal robustness
- JSON decoding failures handled by returning empty collections: `except json.JSONDecodeError: return []`
- Missing optional imports return `None` or `False` rather than raising

**Logging:**
- Uses Python `logging` module: `logger = logging.getLogger(__name__)`
- INFO level for major events; DEBUG for noise; ERROR for recoverable failures
- Never logs secrets (content hashes are safe; file paths are safe)

**Exit Codes:**
- Hook handlers return `0` (pass), `1` (warning), `2` (block)
- CLI uses `2` for BLOCKED, `1` for WARNING, `0` for CLEAN

## Type Hints

**Coverage:**
- 100% type annotation: all function signatures, variable assignments, return types
- Modern syntax: `str | None` not `Optional[str]`; `list[X]` not `List[X]`
- Imports from `typing` only for `TYPE_CHECKING` and `Any`

**Examples:**
```python
# From patterns.py
def scan(self, content: str, source_path: str, mode: ScanMode | None = None) -> ScanResult:

# From monitor.py
def record_event(self, data: dict[str, Any]) -> None:

# From allowlist.py
def check(self, content: bytes) -> bool:
```

## Enums

**Pattern:**
- Inherit from `Enum` directly
- Use `.value` to get string representation: `severity.value == "critical"`
- String values for comparison: `CRITICAL = "critical"` not `CRITICAL = 1`

**Example from codebase:**
```python
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
```

---

*Convention analysis: 2026-04-05*
