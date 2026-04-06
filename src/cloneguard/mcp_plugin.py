# mypy: ignore-errors
"""Backward-compatible shim -- use cloneguard.adapters.mcp instead.

This module is DEPRECATED. It re-exports from cloneguard.adapters.mcp
for users who have mcp-gateway configurations referencing cloneguard.mcp_plugin.
Will be removed in a future major version.

T-03-10: This shim only re-imports from adapters.mcp. No new code execution path.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "cloneguard.mcp_plugin is deprecated. Use cloneguard.adapters.mcp instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export for backward compatibility
from cloneguard.adapters.mcp import CloneGuardMCPPlugin as CloneGuardPlugin  # noqa: E402, F401
from cloneguard.adapters.mcp import MCPAdapter  # noqa: E402, F401
